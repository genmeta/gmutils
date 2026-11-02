# Jade

Jade creates projects, runs them in a local Pishoo development session, builds and
signs `.waz` releases, and publishes existing releases to the Pishoo store.
`run` needs an already running local Pishoo identity. `build` and `publish` do not
need a running host service. The gmutils packages include `genmeta` and `jade`.

```sh
jade create hello --template api
cd hello
# Select an installed Rust toolchain with wasm32-wasip2 when building Rust APIs.
# RUSTUP_TOOLCHAIN can select that toolchain without changing global defaults.
jade run --id test.sky.lee
```

Local run requires no developer subscription, certificate, or payment. To prepare
formal publication, activate the root name's fixed developer child:

```sh
jade publish --prepare --id sky.lee
# If needed, confirm the annual quote and finish checkout in the browser.
# The command waits for server-confirmed fulfillment and prepares dev.sky.lee.dhttp.net.
jade build --id dev.sky.lee
# Review build/hello-0.1.0.waz, then upload those exact bytes.
jade publish
```

Each root name binds one `dev.` developer name; certificate and sequence counts
are not limited. Devices and CI can hold independent keys under that same name
and annual subscription. Merely registering a normal `dev.` child does not grant
signing entitlement. Certificates have codeSigning, clientAuth, and serverAuth.
Ordinary TLS certificates cannot sign releases.

Jade uses `dhttp-home`, including `DHTTP_HOME` when set. Developer credentials are
kept privately in `<profile>/code-signing/<sequence>/credentials.json`; an installed
unified identity in `ssl/` may also be used. An ordinary TLS profile is preserved
when developer credentials are issued. Upload uses the selected developer key in
a temporary transport profile and keeps per-leaf OCSP caches under
`<profile>/code-signing/ocsp/`. It does not replace a normal host's TLS credentials.

Use `--signing-sequence N` with build or publish to select a specific local
credential. Otherwise Jade prefers the usable unified identity, then an available
sequence. The upload credential can differ from the package signing credential,
but the canonical author and owner_hash must match. Neither the old package's
private key nor a byte-identical certificate is required just to upload it.

Renew with `genmeta identity developer ROOT renew --sequence N`. Issuance and
renewal check entitlement; interactive preparation can confirm a quote and resume
checkout if needed. Noninteractive preparation never creates an order implicitly.
The pending CSR, private key and operation are preserved across failures. Initial
issuance replays the same CSR under the server ownership lock rather than creating
a second sequence after a lost response. A new independent CSR can create another
certificate; no additional annual subscription is needed.

## Run locally

```sh
jade run [PATH] [--id HOST] [--no-watch] [--fresh]
```

The first implementation uses authenticated Unix IPC on Linux and macOS. `--id`
selects the running host, not a signing author. Pishoo checks the operating-system
peer and identity owner, validates an unsigned immutable snapshot, and exposes its
API and frontend only to the authenticated host owner. Existing public ACLs do
not make development routes public. No checkout or developer-certificate request
is made by run.

By default Jade watches project inputs, rebuilds serially, and loads a new revision
only after validation succeeds. Failed builds keep the last revision running;
App and Lib switch together. Generated output and dependency caches are excluded
from watching; an explicitly discovered static `dist/` input is still watched.
`--no-watch` loads one revision and keeps serving until exit. `--fresh` selects a
new isolated data directory without deleting prior test data. Normal restarts
reuse data for the same host, canonical project path and package.

Pishoo rejects installed-name conflicts and simultaneous sessions for the same
host/package. Exact dependencies must already be installed in the test identity.
The command prints the actual API/App URLs, a GET example when available, and the
data directory. Ctrl+C exits successfully and disconnects the local session;
Pishoo removes development routes even if Jade exits unexpectedly. These temporary
snapshots are never registered as formal installed packages.

## Create a project

```sh
jade create hello                        # Vite frontend + Rust HTTP API (default)
jade create website --template static    # Static HTML
jade create frontend --template web      # Vite frontend
jade create service --template api       # Rust HTTP API
jade create application --template fullstack  # Vite frontend + Rust HTTP API
jade create "My Project" --name my-project
```

Creation writes `jade.toml`, source files, preparation instructions and
`.gitignore` into a new directory. The parent must exist. Creation does not load
credentials. The default template is `fullstack`, with both a Vite frontend and
a Rust API. Use `--template static`, `web` or `api` to generate only the files you need.

The `api` and `fullstack` starters include working GET `/hello`
handlers in `api/src/lib.rs`. The fullstack frontend calls `/<package-name>/hello`
and displays the returned message. Each generated README includes build, publish,
install and API request examples. Pishoo runs the backend; Vite's dev server alone
does not serve API requests.

## Configure a package

```toml
[package]
name = "hello"
version = "0.1.0"
description = "Hello application"
license = "Apache-2.0"

```

`name`, `version`, `description` and `license` are required. Optional package
fields are `author`, `title`, `release-notes` and `repository`. Title defaults to
the package name and release notes to `Release VERSION`.

Jade automatically finds a frontend build project from `package.json` with a
nonempty `scripts.build` at the project root, `web/` or `app/`. If none exists,
it looks for `index.html` in the root, `web/`, `app/` or `public/`, then falls back
to `dist/`, `web/dist/` or `app/dist/`. Multiple candidates at the same stage are
an error. Source takes precedence over existing build output. No `[frontend]`
or `[backend]` section is accepted.

Jade automatically finds a Rust backend through `Cargo.toml` at the project root,
`api/Cargo.toml` or `lib/Cargo.toml`. Multiple Rust projects are an error. When no
Rust source is present, Jade uses a prebuilt `lib.wasm` in the project root;
existing `lib.wasm` output is ignored when building source.

A frontend directory with a nonempty `package.json` build script first installs
dependencies (including development dependencies), then runs that script through
npm, pnpm or Bun. Every build synchronizes dependencies using
`npm install --include=dev`, `pnpm install --prod=false` or `bun install`.
`packageManager` takes precedence over lockfile detection; without either, npm is
used. Build scripts must write resources into `dist/` within the frontend directory.
Without a build script, the directory is collected as static resources and must
contain `index.html`.

Rust backends use the API template's `cdylib` and WASI HTTP bindings. Jade invokes
Cargo with `wasm32-wasip2` and reads its artifact report. Developers do not write a
build script or configure a build command. A prebuilt `lib.wasm` must contain its
own OpenAPI document.

Existing Rust APIs can keep `openapi.json` beside `Cargo.toml`; Jade embeds that
document after compilation. Declare either `jade:routes` metadata or this file, not both.
The document's version must match `package.version`. For C dependencies, install
WASI SDK and set `WASI_SDK_PATH`; project-specific flags belong in Cargo's
target-specific configuration.

Paths are relative to `jade.toml`. Runtime artifacts stay within the project;
source dependencies are managed by Cargo/npm. Optional runtime package
dependencies use exact author, name and version:

```toml
[[dependencies]]
author = "std.dhttp.net"
name = "message"
version = "1.2.3"
```

Backend discovery replaces the old `[backend]` and `[backend.host]` sections;
remove them from existing projects. Host capabilities need no purpose declarations.
Public API, store metadata and signed ZIP dependencies use `author`.

## Write a Rust API

```sh
jade create service --template api
cd service
rustup target add wasm32-wasip2
# Edit api/src/lib.rs
jade build --id alice.smith
jade publish build/service-0.1.0.waz
```

The generated `api/src/lib.rs` uses `wasip2` directly for the WASI HTTP entry
point and `serde_json` for JSON. It implements GET `/hello` without
a local SDK module or custom request/response wrappers.

When changing routes, update both the entry point's match arms and the `ROUTES`
metadata at the bottom of the file. Jade reads the `jade:routes` custom section
and generates route-level OpenAPI with the package's title and version, then
embeds it in the Component. Detailed request/response schema inference is not
included. Pishoo supplies the HTTP listener and mounts the ordinary package's
API under its package name.

After publication, install on your running Pishoo service and call the API
(replace the author and host identities with yours):

```sh
genmeta install alice.smith.dhttp.net/service --id alice.smith
genmeta curl --id alice.smith -f https://alice.smith.dhttp.net/service/hello
# {"message":"Hello from Rust"}
```

For web/fullstack templates, `jade build` prepares frontend dependencies automatically.
Install Node.js and the selected package manager (or Bun), and the Rust toolchain
and component target for API projects, before building.

## Build and publish

```sh
jade build [PATH] [--id AUTHOR] [-o FILE.waz] [--overwrite]
jade publish [PATH | FILE.waz] [--id ROOT] [--email EMAIL] [--signing-sequence N]
jade publish --prepare [PATH] [--id ROOT]
```

Build accepts a project directory or a Jade configuration file. Identity selection
uses explicit `--id`, then `package.author`, then the existing DHTTP default.
Explicit identity and configured author must agree. Otherwise a single available
identity is selected automatically; multiple candidates require a terminal
selection or `--id`. Selections are not saved in Jade-specific state.

Packages default to `build/NAME-VERSION.waz`; Cargo's intermediate artifacts go to
`build/target/`. Frontend outputs such as `web/dist/` or a root-level `dist/` stay
separate. `build/` is excluded from collected content, as is the legacy `.jade/`
directory. Existing projects should add `/build/` to `.gitignore`. Rebuilding
atomically updates a verified output belonging to the same package, version and owner;
failed builds preserve the previous package. Replacing an explicit `-o` file
requires `--overwrite`.

Build verifies component structure, the WASI HTTP entry point, supported imports,
OpenAPI, container contents and the digital signature. Publish repeats local
checks before preparing an authenticated endpoint and uploads one fixed snapshot.
It uses a selected developer credential for TLS and the public signing certificates
embedded in the existing WAZ. Both chains are independently validated and must bind the
same canonical domain and owner_hash; their DER bytes and keys may differ.
Publication preserves the exact WAZ bytes and never re-signs. Upload CI needs its
own developer transport key, but not the original package-signing private key. Publication admission verifies the signed certificate locally;
paid entitlement is enforced only at certificate issuance and renewal. Jade and
Registry never query CertServer during publication.
When PATH is omitted, publish uses the current project's exact
`build/NAME-VERSION.waz`. A directory or `jade.toml` selects that same convention;
custom output requires an explicit file. Name, version, and a configured author
must agree with the signed package. Missing output reports `E_BUILD_REQUIRED`;
a mismatch reports `E_PACKAGE_MISMATCH`. Publish never runs Cargo/npm, builds a
missing release, signs a package, or chooses another version automatically.

`--prepare` only prepares credentials and returns `credentials-ready`; then run
build explicitly. Interactive project publication can also prepare missing
credentials, but missing output still requires a separate build. Explicit file
publication cannot change its author with `--id` or start a preparation flow.

Before sending a package, it reads the store catalogue and rejects the legacy
`publisher`/`.pkg` protocol with no upload.
Local checks validate the codeSigning path against the compiled DHTTP Root,
strict certificate profile and package signature. TLS authentication validates
the upload identity. Optional issuer-signed DER CRLs can be imported independently
under `<author profile>/trust/code-signing/<issuer DER SHA256>.crl`. No list means
current revocation is unknown; a known revoked certificate is refused, and a stale
list requires an independently distributed replacement. Registry records the unreleased policy 1
and a portable signed publication receipt for historical installation.

Publication returns `published` or `already-published` for identical content.
Different content at the same version is a conflict. An uncertain upload performs
one read-only reconciliation; if unconfirmed it reports
`E_PUBLISH_OUTCOME_UNKNOWN`. Upload writes are not automatically repeated.

`.waz` is a standard ZIP with MIME `application/zip`. It contains `manifest.json`,
`signature.json`, optional `backend.wasm`, and frontend files under `public/`.
Root-level `README.md` and `CHANGELOG.md` are automatically included when present;
missing documents are skipped and need no declaration in `jade.toml`.
`payload_sha256` identifies the signed metadata, runtime files and documents;
`package_sha256` identifies the complete ZIP. See [the WAZ format](FORMAT.md).
Old WEBC release files are rejected and must be rebuilt from source. Deploy updated
store and host readers before publishing the new ZIP packages.

## Output and validation

Human summaries are the default. Use `--json` for one complete JSON document,
including errors, on stdout; progress and build logs go to stderr. JSON uses full
identities, while terminal summaries may display `alice.smith~`. `--verb` enables
debug logs. JSON and non-terminal runs never prompt.

Exit codes are 0 for success, 1 for runtime failure or unknown publication result,
2 for CLI usage errors, and 130 for cancellation.

```sh
cargo test -p jade --locked
cargo clippy -p jade --locked --all-targets -- -D warnings
# Requires Node.js, npm and registry access for the generated Vite frontend:
cargo test -p jade --locked --test pack_commands \
  web_template_builds_without_manual_dependency_installation -- --ignored --exact
# Also requires wasm32-wasip2 for the default fullstack template:
cargo test -p jade --locked --test pack_commands \
  default_fullstack_template_builds_without_manual_dependency_installation -- --ignored --exact
# Requires wasm32-wasip2 and the generated API's Cargo dependencies:
cargo test -p jade --locked --test pack_commands \
  rust_api_template_builds_without_developer_build_scripts -- --ignored --exact
# Requires OpenSSL 3 and local UDP sockets; uses a local store and test identities:
cargo test -p jade --locked \
  upload::tests::real_http3_publish_retry_dependencies_and_read_only_recovery \
  -- --ignored --exact
```

The implementation scope and acceptance criteria are in
[IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md). Install and manage published
packages through `genmeta install/update/uninstall`.

## Developer-signing tests

`jade/tests/scripts/code-signing.sh --offline` builds into a dedicated
`target/code-signing-tests` directory with the disposable test Root compiled in.
It runs package, build and launcher regression tests. This is a test artifact,
not a release binary. The locked dhttp 0.7.1 consumes `DHTTP_ROOT_CA_PEM` as PEM
text at compile time; a runtime variable or a `DHTTP_ROOT_CA` file path does not
change its trust anchor. Production builds must supply their approved PEM.
