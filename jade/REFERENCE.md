# Jade reference

See [README.md](README.md) for the short workflow and identity rules.
Examples use `alex.chen` (Alex Chen); replace it with your own name.

Each root name binds one `dev.` developer name; certificate and sequence counts
are not limited. Devices and CI can hold independent keys under that same name
and annual subscription. Merely registering a normal `dev.` child does not grant
signing entitlement. Certificates have codeSigning, clientAuth, and serverAuth.
Ordinary TLS certificates cannot sign releases.

Jade uses `dhttp-home`, including `DHTTP_HOME` when set. Developer credentials use
only the normal `<profile>/ssl/fullchain.crt` and `ssl/privkey.pem`, with OCSP in
`ssl/stapling.ocsp`. Developer issuance and renewal replace the certificate and
private key together through the normal identity transaction. Signing, upload and
hosting use that same installed identity selected by the author or default name.
Ordinary TLS certificates cannot sign packages; publish guides developer setup when the installed certificate lacks
`codeSigning`. Issued credentials are not stored or selected from
`code-signing/<sequence>/credentials.json`, and upload creates no temporary identity.
No independent `code-signing/` directory is created, including during setup.

`genmeta identity apply NAME` requests a new sequence using the target name's
current entitlement: a bound name with active developer entitlement receives
`codeSigning`, `clientAuth` and `serverAuth`; otherwise it receives ordinary TLS
credentials. `genmeta identity renew NAME` renews the installed sequence with its
existing purpose. Names and ownership are verified by the server; a `dev.` prefix
alone grants no signing rights.

`--signing-sequence N` with publish must match the sequence installed in `ssl/`.
Without it Jade uses that installed identity. An already signed package may have
been signed by another certificate, but its canonical author and owner_hash must
match the uploader. The old package's private key is not required for upload.

Renew with `genmeta identity renew DEV_NAME`. Issuance and
renewal check entitlement; interactive preparation can confirm a quote and resume
checkout if needed. Payment uses the same QR/link instructions and waiting
indicator as `genmeta identity apply`, bounded by the public link expiry,
invoice expiry and 15 minutes.
Only confirmed subscription fulfillment permits issuance; a paid invoice alone
does not. Cancellation or timeout preserves the operation for retry.
Noninteractive preparation never creates an order implicitly.

Developer checkout reads `payment_entry` from the authenticated
`GET /v2/invoice?no=...` response:

```json
{
  "url": "/v2/invoice?no=INV...",
  "payment_entry": {
    "url": "https://dhttp.net/checkout/ckt_dev_<32 hex characters>",
    "checkout_token": "ckt_dev_<32 hex characters>",
    "kind": "code_signing_purchase",
    "expires_at": 1793780000
  }
}
```

The nested URL must be an absolute HTTPS browser payment link. Jade encodes that
same link in its terminal QR code, using the compact layout shared with
`genmeta identity apply`. New developer tokens are opaque, fixed-length random
values; invoice/account data and signatures are kept out of the URL. The server
stores only their digests and enforces the invoice binding and expiry. The top-level
URL remains an API reference.
The server and website must support developer purchase and renewal through the
public checkout capability, including invoice queries, coupons, payment sessions
and result polling without another browser login. The capability must be scoped
to the invoice and expire without being extended by public reads. Jade reports a
missing payment entry and retains the pending operation rather than opening the
invoice API or constructing a billing URL. This client change requires the server
and website to implement that contract before the payment flow works end to end.

Developer certificates require account email verification for renewal and are
excluded from the automatic `genmeta identity renew --all` job. Renew them
explicitly before expiry; ordinary TLS identities continue to renew automatically.
Initial application keeps its private key and CSR only in memory, just like
ordinary identity apply. Exiting or failing discards them; a later application
generates a fresh request. It writes no pending application file or independent
credential directory. Renewal alone persists recovery material under the identity
root as `.identity-renew-SEQUENCE.pending.json`, with a shared
`.identity-operation.lock`; successful SSL installation removes the renewal state.
Historical credential/cache directories are not read or selected, and are not
automatically migrated or removed.


## Identity selection

Jade's `create`, `run`, `build` and `publish` commands have no `--id` option.
Creation writes no author and reads no credentials. Run and build both use the
exact `package.author` when configured. Otherwise they select the `dev` child of
the DHTTP default main name, retaining an existing development child. A default
of `dev.wang` selects `dev.dev.wang`; defaults `dev.dev.wang` and `dev.alex.chen`
stay unchanged. If neither author nor default is configured, they report
`E_IDENTITY_REQUIRED`; no identity is hardcoded and installed credentials are not
scanned to choose a name.

```toml
[package]
# Other required metadata omitted here.
author = "dev.alex.chen"
```

Short names and full `.dhttp.net` names are equivalent. Configured authors never
gain or lose `dev.`. Identity selection does not write back to `jade.toml` or save
Jade-specific preferences. With no author, keep the global default unchanged
between run and build to use the same identity. A later default change does not
change the author of an existing WAZ.

| Command | Identity source | Required credentials |
| --- | --- | --- |
| `create` | None | None |
| `run` | Configured author, otherwise default development identity | Ordinary hosting credentials |
| `build` | Same selection as run; recorded in WAZ | None |
| `publish` with a WAZ | Built author | Matching developer signing/upload credentials |
| Interactive publish without a build | Configured author, otherwise default development identity | Guides setup, then asks for build |

Project publication checks configured author/name/version against the built WAZ.
An explicit file is independent of the current project and default identity.
The visitor accessing a running application chooses a client identity independently
of the author and host.

## Run locally

```sh
jade run [PATH] [--fresh]
```

Run hosts the application on the configured author or default development identity.
Install ordinary credentials for this name first; local run requires no developer
certificate, subscription or payment. Jade enables the identity's normal listener
using `pishoo configure`, without changing the default identity or starting another
daemon. Run builds and watches a local snapshot; it does not create or modify the
release WAZ. Build explicitly after source changes to publish a new snapshot.
Changing `package.author` while run is watching requires restarting run to use
the new identity; previous local files stay in place until cleanup or replacement.

App URLs are `/app/<name>/`, standard APIs use `/std/<name>/...`, and ordinary
APIs use `/<name>/...`. There is no `/dev` URL prefix. Existing frontend and API
calls therefore use the same paths as an installed application.

```toml
[[dependencies]]
author = "dev.genmeta.tech.dhttp.net"
name = "profile"
version = "0.3.0"
path = "../profile"

[[dependencies]]
author = "dev.genmeta.tech.dhttp.net"
name = "message"
version = "0.2.1"
```

Dependencies with `path` are built and watched locally, recursively. Paths resolve
relative to their declaring `jade.toml`; local author/name/version must match.
Dependencies without `path` are installed from the store at the exact declared
version. Conflicting versions, dependency cycles and duplicate local names fail
explicitly. `path` is omitted from release metadata. Build and publish do not
recursively build dependencies. Local dependency source trees and nested Jade
projects are excluded when collecting static frontend resources.

Jade watches every local project and publishes each complete directory atomically
to `<dev-identity>/dev/<name>/`, containing `manifest.json`, optional `lib.wasm`,
and optional `app/`. Pishoo reads App files per request and compiles changed WASM
lazily. Build failures retain previous files. Local files require the real owner;
native services and installed dependencies keep normal routing and authorization.
Pishoo checks file existence, the real owner and file permissions; identity-name prefixes do not determine permission to execute these unsigned files.

Development data belongs to the dev identity, in `.volume/<name>` or
`.volume/std/<name>`, separate from the base identity. Ctrl+C/SIGTERM removes only
local code directories still owned by this watcher, preserving data and store
installations. `--fresh` archives previous local data explicitly. Later publishers'
replacements survive older watchers stopping. SIGKILL/power loss cannot clean up;
remove leftover `dev/<name>` directories manually. Old `dev-data` is left intact.

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
credentials or record an author. The default template is `fullstack`, with both a Vite frontend and
a Rust API. Use `--template static`, `web` or `api` to generate only the files you need.

The `api` and `fullstack` starters include GET `/whoami`
handlers in `api/src/lib.rs`. The default fullstack welcome page calls
`/<package-name>/whoami` and displays the verified visitor identity, or `anonymous`.
It defaults to English, remembers manual English/Chinese language choices, and
includes mobile layouts, loading and error states, and retry. Displayed identity
names omit the `.dhttp.net` suffix; the API returns the full verified name. The frontend-only `web` template uses the same design without
calling an API. Edit `web/index.html`, `web/src/main.js` and `web/src/style.css`.
The API uses a pinned Pishoo SDK to read the authenticated caller, never HTTP
identity headers; responses use `Cache-Control: no-store`. Each generated README includes build, publish,
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
fields are `author`, `title`, `release-notes` and `repository`. Author selects both
the local hosting identity and release author, and can omit `.dhttp.net`. Title defaults to
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

Runtime artifact paths stay within the project; Rust and frontend source
dependencies are managed by Cargo/npm. Runtime package dependencies use exact
author, name and version. For local development, an optional `path` resolves
relative to the declaring `jade.toml`, including nested dependencies:

```toml
[[dependencies]]
author = "dev.genmeta.tech.dhttp.net"
name = "message"
version = "1.2.3"
path = "../message"
```

`jade run` builds and watches dependencies with `path`; dependencies without it
are installed from the store at the declared version. Local package coordinates
must match. The path is omitted from release metadata; signed releases retain the
exact author, name and version dependency.

Backend discovery replaces the old `[backend]` and `[backend.host]` sections;
remove them from existing projects. Host capabilities need no purpose declarations.
Public API, store metadata and signed ZIP dependencies use `author`.

## Write a Rust API

```sh
jade create service --template api
cd service
rustup target add wasm32-wasip2
# Edit api/src/lib.rs; configure package.author or your DHTTP default identity.
jade build
jade publish build/service-0.1.0.waz
```

The generated `api/src/lib.rs` uses `wasip2` directly for the WASI HTTP entry
point, `serde_json` for JSON and a pinned Pishoo SDK for caller identity. It implements
GET `/whoami` without a local SDK module or custom request/response wrappers.

When changing routes, update both the entry point's match arms and the `ROUTES`
metadata at the bottom of the file. Jade reads the `jade:routes` custom section
and generates route-level OpenAPI with the package's title and version, then
embeds it in the Component. Detailed request/response schema inference is not
included. Pishoo supplies the HTTP listener and mounts the ordinary package's
API under its package name.

After publication, install on your running Pishoo service and call the API
(replace the author and host identities with yours):

```sh
genmeta install dev.alex.chen/service --id alex.chen
genmeta curl --id alex.chen -f https://alex.chen.dhttp.net/service/whoami
# {"name":"alex.chen.dhttp.net"}
```

For web/fullstack templates, `jade build` prepares frontend dependencies automatically.
Install Node.js and the selected package manager (or Bun), and the Rust toolchain
and component target for API projects, before building.

## Build and publish

```sh
jade build [PATH] [-o FILE.waz] [--overwrite]
jade publish [PATH | FILE.waz] [--email EMAIL] [--signing-sequence N]
```

Build accepts a project directory or a Jade configuration file. Its author comes
from the exact `package.author`, otherwise the default development identity as
described above. It resolves names without reading identity or signing credentials,
and records the author only in the generated WAZ. It does not add an author to
`jade.toml`.

Packages default to `build/NAME-VERSION.waz`; Cargo's intermediate artifacts go to
`build/target/`. Frontend outputs such as `web/dist/` or a root-level `dist/` stay
separate. `build/` is excluded from collected content, as is the legacy `.jade/`
directory. Existing projects should add `/build/` to `.gitignore`. Rebuilding
atomically updates a verified output belonging to the same package and version;
failed builds preserve the previous package. Replacing an explicit `-o` file
requires `--overwrite`.

Build verifies component structure, the WASI HTTP entry point, supported imports,
OpenAPI and container contents, then writes an unsigned WAZ. No developer
certificate, subscription or ordinary identity credentials are required.

Publish reads one fixed build snapshot. For an unsigned WAZ, it signs that
snapshot using the selected developer credential and verifies the resulting
signature before saving the signed WAZ and uploading. For an already signed
WAZ, it verifies and preserves the exact bytes, including the original signature;
a damaged signature is rejected rather than replaced. Upload CI can upload a
signed release with its own developer transport key when the canonical author
and owner_hash match, without the original signing key.

Publication verifies the signed certificate locally; paid entitlement is enforced
only at certificate issuance and renewal. Jade and Registry never query CertServer
during publication.
When PATH is omitted, publish uses the current project's exact
`build/NAME-VERSION.waz`. A directory or `jade.toml` selects that same convention;
custom output requires an explicit file. Name, version, and a configured author
must agree with the built package. Missing output reports `E_BUILD_REQUIRED`;
a mismatch reports `E_PACKAGE_MISMATCH`. Publish never runs Cargo/npm, builds a
missing release, or chooses another version automatically.

Interactive project publication guides missing developer credentials. With no
package, it selects the configured author or default development identity.
Without either, it reports `E_IDENTITY_REQUIRED`. It prepares matching credentials,
then reports `E_BUILD_REQUIRED` with instructions to build using that author.
With an existing package, it prepares matching signing/upload credentials and
continues publication. JSON and noninteractive runs only report the required next step.
For an explicit signed file, setup prepares credentials for its exact author
without changing any package bytes. Existing builds retain their recorded author
even if the global default has changed or is no longer configured.

Before sending a package, it reads the store catalogue and rejects the legacy
`publisher`/`.pkg` protocol with no upload.
Local checks validate the codeSigning path against the compiled DHTTP Root,
strict certificate profile and package signature. TLS authentication validates
the upload identity. Optional issuer-signed DER CRLs can be imported independently
under `<author profile>/trust/code-signing/<issuer DER SHA256>.crl`. No list means
current revocation is unknown; a known revoked certificate is refused, and a stale
list requires an independently distributed replacement. Registry records a portable signed publication receipt for historical installation.

Publication returns `published` or `already-published` for identical content.
Different content at the same version is a conflict. An uncertain upload performs
one read-only reconciliation; if unconfirmed it reports
`E_PUBLISH_OUTCOME_UNKNOWN`. Upload writes are not automatically repeated.

`.waz` is a standard ZIP with MIME `application/zip`. It contains `manifest.json`,
`signature.json` after publication signing, optional `backend.wasm`, and frontend files under `public/`.
Root-level `README.md` and `CHANGELOG.md` are automatically included when present;
missing documents are skipped and need no declaration in `jade.toml`.
`payload_sha256` identifies the metadata, runtime files and documents and stays
the same when signed; `package_sha256` identifies the complete ZIP and changes
when a signature is added. See [the WAZ format](FORMAT.md).
Old WEBC release files are rejected and must be rebuilt from source. Deploy updated
store and host readers before publishing the new ZIP packages.

## Output and validation

Human summaries are the default. Use `--json` for one complete JSON document,
including errors, on stdout; progress and build logs go to stderr. JSON uses full
identities, while terminal summaries may display `alex.chen~`. `--verb` enables
debug logs. JSON and non-terminal runs never prompt.

Exit codes are 0 for success, 1 for runtime failure or unknown publication result,
2 for CLI usage errors, and 130 for cancellation.

```sh
jade/tests/scripts/code-signing.sh
cargo clippy -p jade --locked --all-targets -- -D warnings
# Requires Node.js, npm and registry access for the generated Vite frontend:
jade/tests/scripts/code-signing.sh --test pack_commands \
  web_template_builds_without_manual_dependency_installation -- --ignored --exact
# Also requires wasm32-wasip2 for the default fullstack template:
jade/tests/scripts/code-signing.sh --test pack_commands \
  default_fullstack_template_builds_without_manual_dependency_installation -- --ignored --exact
# Requires wasm32-wasip2 and the generated API's Cargo dependencies:
jade/tests/scripts/code-signing.sh --test pack_commands \
  rust_api_template_builds_without_developer_build_scripts -- --ignored --exact
# Requires OpenSSL 3 and local UDP sockets; uses a local store and test identities:
jade/tests/scripts/code-signing.sh \
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
