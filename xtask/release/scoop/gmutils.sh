#!/usr/bin/env bash
set -euo pipefail

prepare_product_source() {
    local dest=$1
    rm -rf "$dest"
    mkdir -p "$dest"
    tar -C "${XTASK_RELEASE_REPO_ROOT:?}" \
        --exclude='./.git' \
        --exclude='./target' \
        --exclude='./xtask' \
        -cf - . | tar -C "$dest" -xf -
    python3 - "$dest/Cargo.toml" <<'PY'
from pathlib import Path
import sys
path = Path(sys.argv[1])
text = path.read_text()
text = text.replace('    "xtask",\n', '')
path.write_text(text)
PY
}

cd "${XTASK_RELEASE_REPO_ROOT:?}"
target=${XTASK_RELEASE_TARGET:?}
out=${XTASK_RELEASE_OUT_DIR:?}
version=${XTASK_RELEASE_SOURCE_VERSION:?}
rm -rf "$out/staging"
mkdir -p "$out/staging"
product_source="$out/product-source"
prepare_product_source "$product_source"
XWIN_ARCH=x86,x86_64 cargo-xwin build --release --manifest-path "$product_source/genmeta/Cargo.toml" --target "$target" --bin genmeta
cp "$product_source/target/$target/release/genmeta.exe" "$out/staging/genmeta.exe"
cp genmeta-ssh.bat "$out/staging/genmeta-ssh.bat"
python3 - "$out/staging" "$out/gmutils-$version-$target.zip" <<'PY'
from pathlib import Path
import sys, zipfile
staging = Path(sys.argv[1])
with zipfile.ZipFile(sys.argv[2], 'w', zipfile.ZIP_DEFLATED) as archive:
    for path in sorted(staging.iterdir()):
        if path.is_file():
            archive.write(path, path.name)
PY
rm -rf "$out/staging"
