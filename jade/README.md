# Jade

Jade creates projects, builds and signs `.waz` packages, and publishes them to the
Pishoo store. It is an independent executable in the gmutils workspace. Builds use
local tools and credentials; a running Pishoo service is not required.

```sh
cargo install --path jade --locked
jade create hello
cd hello
jade build --id alice.smith
jade publish .jade/hello-0.1.0.waz
```

Provision credentials through the DHTTP identity tools, for example
`genmeta identity apply`. Jade uses `dhttp-home`, including `DHTTP_HOME` when set.

## Create a project

```sh
jade create hello                         # Static HTML
jade create frontend --template web      # Vite frontend
jade create service --template api       # Rust HTTP API
jade create application --template fullstack
jade create "My Project" --name my-project
```

Creation writes `jade.toml`, source files, preparation instructions and
`.gitignore` into a new directory. The parent must exist. Creation does not load
credentials. Templates choose initial files; packages can contain a frontend,
a backend, or both.

## Configure a package

```toml
[package]
name = "hello"
version = "0.1.0"
description = "Hello application"
license = "Apache-2.0"

[frontend]
path = "public"
```

`name`, `version`, `description` and `license` are required. Optional package
fields are `author`, `title`, `release-notes` and `repository`. Title defaults to
the package name and release notes to `Release VERSION`.

To build frontend source and a Rust API, use these sections instead:

```toml
[frontend]
path = "web"

[backend]
path = "api"
```

A frontend directory with a nonempty `package.json` build script runs that script
through npm, pnpm or Bun. `packageManager` takes precedence over lockfile detection;
without either, npm is used. `frontend.output` defaults to `dist`, relative to the
frontend directory. Without a build script, the directory is collected as static
resources and must contain `index.html`.

Rust backends use the API template's `cdylib` and WASI HTTP bindings. Jade invokes
Cargo with `wasm32-wasip2` and reads its artifact report. Developers do not write a
build script or configure a build command. A backend path may also point directly
to a Component containing its own OpenAPI document.

Existing Rust APIs can keep `openapi.json` beside `Cargo.toml`; Jade embeds that
document after compilation. Declare either SDK routes or this file, not both.
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

Declare host capabilities when the backend imports them:

```toml
[backend.host]
private-storage = "Store application documents"
```

Supported capabilities are `private-storage`, `request-identity` and `signatures`.
The starter API needs none. Public API and store metadata use `author`; the signed
host manifest's dependency entries use `publisher` through an internal mapping.

## Write a Rust API

```sh
jade create service --template api
cd service
rustup target add wasm32-wasip2
# Edit api/src/api.rs
jade build --id alice.smith
```

The generated `api/src/sdk.rs` provides HTTP request/response handling, typed JSON
through Serde, and the `sdk::api!` declaration used by both dispatch and API
metadata. The starter declares GET `/hello` and POST `/echo`:

```rust
sdk::api! {
    get "/hello" => hello,
    post "/echo" => echo,
}
```

Jade generates route-level OpenAPI from those declarations and embeds it in the
Component, with the package's title and version. Detailed request/response schema
inference is not included. Pishoo supplies the HTTP listener and mounts the
ordinary package's API under its package name.

For web/fullstack templates, prepare frontend dependencies with
`npm --prefix web install`. Jade runs the existing build script; it does not
install frontend dependencies or the Rust toolchain.

## Build and publish

```sh
jade build [PATH] [--id AUTHOR] [-o FILE.waz] [--overwrite]
jade publish FILE.waz
```

Build accepts a project directory or a Jade configuration file. Identity selection
uses explicit `--id`, then `package.author`, then the existing DHTTP default.
Explicit identity and configured author must agree. Otherwise a single available
identity is selected automatically; multiple candidates require a terminal
selection or `--id`. Selections are not saved in Jade-specific state.

Packages default to `.jade/NAME-VERSION.waz`, separate from frontend outputs such
as `dist/`. `.jade/` is excluded from collected content. Rebuilding atomically
updates a verified output belonging to the same package, version and owner;
failed builds preserve the previous package. Replacing an explicit `-o` file
requires `--overwrite`.

Build verifies component structure, the WASI HTTP entry point, supported imports,
OpenAPI, container contents and the digital signature. Publish repeats local
checks before preparing an authenticated endpoint and uploads one fixed snapshot.
It uses the package's author credentials; certificate changes require rebuilding.
Before sending a package, it reads the store catalogue and rejects the legacy
`publisher`/`.pkg` protocol with no upload.
Local checks establish signature and identity binding; current network trust and
revocation checks belong to DHTTP authentication.

Publication returns `published` or `already-published` for identical content.
Different content at the same version is a conflict. An uncertain upload performs
one read-only reconciliation; if unconfirmed it reports
`E_PUBLISH_OUTCOME_UNKNOWN`. Upload writes are not automatically repeated.

`.waz` is WEBC v3 with MIME `application/webc`. `payload_sha256` identifies metadata
and runtime content; `package_sha256` identifies the complete signed file.

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
