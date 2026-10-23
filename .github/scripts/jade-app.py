#!/usr/bin/env python3
"""Shared preparation for Jade application CI; never loads developer credentials."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tomllib


def read_manifest(root):
    return tomllib.loads((root / "jade.toml").read_text())


def metadata(root):
    manifest = read_manifest(root)
    package = manifest["package"]
    name, version, author = (package[k] for k in ("name", "version", "author"))
    if not re.fullmatch(r"[a-z][a-z0-9-]*", name):
        raise ValueError("invalid application name")
    if not re.fullmatch(r"[a-z0-9.-]+\.dhttp\.net", author):
        raise ValueError("CI requires the full package.author identity")
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?", version):
        raise ValueError("invalid release version")
    if os.environ.get("GITHUB_REF_TYPE") == "tag":
        tag = os.environ["GITHUB_REF_NAME"]
        if tag != f"v{version}":
            raise ValueError(f"release tag must be v{version}")
        subprocess.run(["git", "rev-parse", f"refs/tags/{tag}^{{tag}}"], cwd=root, check=True)
        target = subprocess.check_output(["git", "rev-parse", f"refs/tags/{tag}^{{commit}}"], cwd=root, text=True).strip()
        if target != subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip():
            raise ValueError("release tag must point to the checked-out commit")
    for kind in ("frontend", "backend"):
        if kind not in manifest:
            continue
        path = (root / manifest[kind]["path"]).resolve()
        if not path.is_relative_to(root.resolve()):
            raise ValueError("source path leaves application repository")
        version_file = path / ("package.json" if kind == "frontend" else "Cargo.toml")
        if version_file.exists():
            source = json.loads(version_file.read_text()) if kind == "frontend" else tomllib.loads(version_file.read_text())["package"]
            if source["version"] != version:
                raise ValueError(f"version mismatch: {version_file}")
    values = dict(name=name, version=version, author=author)
    for kind in ("frontend", "backend"):
        values[kind] = manifest.get(kind, {}).get("path", "")
    if os.environ.get("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a") as output:
            for key, value in values.items():
                if "\n" in value or "\r" in value:
                    raise ValueError("multiline workflow value")
                output.write(f"{key}={value}\n")
    print(json.dumps(values))


def credentials(root, home, fixture):
    author = read_manifest(root)["package"]["author"]
    if not re.fullmatch(r"[a-z0-9.-]+\.dhttp\.net", author):
        raise ValueError("invalid author")
    ssl = home / author.removesuffix(".dhttp.net") / "ssl"
    ssl.mkdir(parents=True, mode=0o700, exist_ok=False)
    if fixture:
        ski = ("1:0:" + "a" * 64).encode()
        der = bytes([4, len(ski)]) + ski
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
            "-nodes", "-days", "1", "-subj", f"/CN={author}",
            "-addext", f"subjectAltName=DNS:{author}",
            "-addext", "2.5.29.14=DER:" + ":".join(f"{b:02x}" for b in der),
            "-keyout", str(ssl / "privkey.pem"), "-out", str(ssl / "fullchain.crt"),
        ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    else:
        for env, file in [("DHTTP_AUTHOR_CERT", "fullchain.crt"), ("DHTTP_AUTHOR_KEY", "privkey.pem")]:
            value = os.environ.get(env)
            if not value:
                raise ValueError(f"missing release environment secret: {env}")
            (ssl / file).write_text(value)
        # Endpoint loading can refresh OCSP; a supplied response avoids needing it during startup.
        if value := os.environ.get("DHTTP_AUTHOR_OCSP"):
            (ssl / "ocsp.der").write_bytes(base64.b64decode(value, validate=True))
    (ssl / "privkey.pem").chmod(0o400)


def receipt(root):
    build = json.loads((root / ".jade/build.json").read_text())["result"]
    file = Path(build["file"])
    digest = hashlib.sha256(file.read_bytes()).hexdigest()
    if digest != build["package_sha256"]:
        raise ValueError("signed package changed after build")
    (root / ".jade/SHA256SUMS").write_text(f"{digest}  {file.name}\n")
    (root / ".jade/provenance.json").write_text(json.dumps({
        **build, "file": file.name,
        "commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip(),
        "jade_ref": os.environ.get("JADE_REF", "local"),
        "run_id": os.environ.get("GITHUB_RUN_ID"),
        "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
        "fixture_signature": os.environ.get("GITHUB_REF_TYPE") != "tag",
    }, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["metadata", "fixture", "credentials", "receipt"])
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--home", type=Path)
    args = parser.parse_args()
    if args.command in ("fixture", "credentials"):
        if args.home is None:
            parser.error("--home is required")
        credentials(args.root, args.home, args.command == "fixture")
    elif args.command == "metadata":
        metadata(args.root)
    else:
        receipt(args.root)


if __name__ == "__main__":
    main()
