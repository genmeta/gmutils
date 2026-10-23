<p align="center">
  <img src="https://media.dhttp.net/img/gmutils/gmutils.svg" width="900" alt="GMUTILS command-line tool family: identity, access, curl, nslookup, doctor, proxy, and discover">
</p>
<p align="center">
  <a href="https://github.com/genmeta/gmutils/releases"><img src="https://img.shields.io/badge/version-0.9.0--preview.4-1f6feb?style=flat-square" alt="Version 0.9.0-preview.4"></a>
  <a href="https://doc.rust-lang.org/edition-guide/rust-2024/"><img src="https://img.shields.io/badge/Rust-2024-dea584?style=flat-square&amp;logo=rust&amp;logoColor=black" alt="Rust 2024 edition"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-00a51a?style=flat-square&amp;logo=apache&amp;logoColor=white" alt="Apache-2.0 license"></a>
  <a href="#install"><img src="https://img.shields.io/badge/Cargo-supported-dea584?style=flat-square&amp;logo=rust&amp;logoColor=black" alt="Cargo package supported"></a>
  <a href="https://github.com/genmeta/homebrew-preview"><img src="https://img.shields.io/badge/Homebrew-supported-fbb040?style=flat-square&amp;logo=homebrew&amp;logoColor=black" alt="Homebrew package supported"></a>
  <a href="https://github.com/genmeta/gmutils/releases"><img src="https://img.shields.io/badge/DEB-supported-a81d33?style=flat-square&amp;logo=debian&amp;logoColor=white" alt="DEB package supported"></a>
  <a href="https://github.com/genmeta/gmutils/releases"><img src="https://img.shields.io/badge/RPM-supported-ee0000?style=flat-square&amp;logo=redhat&amp;logoColor=white" alt="RPM package supported"></a>
</p>


gmutils is the Genmeta command-line tool family for DHttp networking. It gives an endpoint the tools it needs to create and use a Unified Identity, publish or reach services, control access, diagnose connectivity, and manage DHttp-based remote sessions.

The `genmeta` launcher exposes the suite behind a consistent command surface: `genmeta <tool> [options]`. Most utilities are also published as individual crates for users who only need one command. [Jade](jade/README.md) is a separate project and executable for creating, building and publishing packages.

## Utils

Available commands:

| Command | Purpose |
| ------- | ------- |
| `genmeta identity` | Create, apply, inspect, and renew Unified Identities and certificates. |
| `genmeta access` | Manage DHttp API access-control rules. |
| `genmeta curl` | Send DHttp requests with a curl-like interface. |
| `genmeta listen` | Query or change internal/external/all listening; off stops an identity. |
| `genmeta mount` / `genmeta unmount` | List, configure or remove HTTP mounts on a running identity. |
| `genmeta proxy` | Run a local forward proxy that forwards HTTP requests to DHttp endpoints. |
| `genmeta nslookup` | Resolve DDns names and discover reachable DHttp addresses. |
| `genmeta discover` | Discover nearby DHttp endpoints over mDNS. |
| `genmeta doctor` | Diagnose NAT and network connectivity. |
| `jade create/build/publish` | Create projects, build and publish signed Pkg packages. |
| `genmeta install/update/uninstall` | Manage installed packages; query with `install --list` or `install --info`. |

See [Pishoo command validation](docs/pishoo-validation.md) for the running-host acceptance matrix and release follow-up checks.

See the [中文命令使用指南](docs/commands.zh-CN.md) for the current command reference, options, examples, and common workflows. The [DHttp utilities documentation](https://docs.dhttp.net/en/docs/core-components/utils) is also available online.

## Install

Use the official package repository for a system installation. Both methods install the `gmutils` package, which provides the `genmeta` command.

Installing or upgrading gmutils does not install Workspace. After a successful
interactive `genmeta identity apply` with the server enabled, you are asked whether
to install Workspace for that name; press Enter to accept or answer `n` to skip.
Installation uses the newly applied identity and requires its Pishoo service to be
reachable. Skipping
or an installation failure leaves the identity installed and prints the manual
command, `genmeta install workspace --id NAME`. Non-interactive applications skip
Workspace installation; there is no background retry.

### Linux (Debian/Ubuntu)

Use the following official DHttp APT repository setup:

```bash
# Add the package-signing key.
wget -qO- https://download.dhttp.net/ppa/key/public.key \
  | gpg --dearmor \
  | sudo tee /etc/apt/keyrings/genmeta.gpg > /dev/null

# Add the stable and preview package channels.
sudo tee /etc/apt/sources.list.d/genmeta.list > /dev/null <<'EOF'
deb [signed-by=/etc/apt/keyrings/genmeta.gpg] https://download.dhttp.net/ppa/genmeta stable main
deb [signed-by=/etc/apt/keyrings/genmeta.gpg] https://download.dhttp.net/ppa/genmeta preview main
EOF

sudo apt update
sudo apt install gmutils
```

Install `pishoo` as well when this machine will expose local services through DHttp: `sudo apt install pishoo gmutils`. Refer to the [Linux guide](https://docs.dhttp.net/en/docs/getting-started/linux) for group, service, and gateway configuration.

### macOS

```bash
brew tap genmeta/preview https://github.com/genmeta/homebrew-preview
brew trust genmeta/preview
brew update
brew install gmutils
```

For a DHttp gateway, install `pishoo` alongside gmutils: `brew install pishoo gmutils`. The [macOS guide](https://docs.dhttp.net/en/docs/getting-started/macos) covers service management and configuration locations.

### Build from source

With a current Rust toolchain, build and install the launcher from this checkout:

```bash
cargo install --path genmeta --locked
```

Source installations use the same Workspace prompt during `genmeta identity apply`.
For an existing identity, start Pishoo and run `genmeta install workspace --id NAME`.

## Quick start

Create or apply an identity through the interactive flow, then inspect the available commands:

```bash
genmeta identity apply
genmeta --help
```

Identities are stored under the current user's `~/.dhttp` directory by default. Most client commands use the default identity automatically; pass `--id` to select another identity when a command supports it.

For `nslookup`, only an explicit trailing `~` expands to `.dhttp.net`:

```bash
genmeta nslookup 'alice.smith~' h3
genmeta nslookup example.com system
```

Ordinary query names retain their namespace. Names are normalized through `dhttp-home`.

### Install a published package

```bash
genmeta install workspace
genmeta install dev.dhttp.net/workspace --version 0.2.0 --id alice.smith
genmeta install std.dhttp.net/message
```

Installation defaults to the latest published package version and the configured
default identity. Bare installation names select the standard publisher: `workspace`
means `std.dhttp.net/workspace`. Author names may omit `.dhttp.net`, so
`alice/message` means `alice.dhttp.net/message`. Update, uninstall and info resolve
bare names against the installed catalog and preserve the registered publisher.
The selected identity's Pishoo service must already be running and enabled.
Local credentials use the current account’s identity home. Installation accepts only published store releases; local package files, URLs and anonymous installation are not supported.

The CLI authenticates `store.dhttp.net`, pins an exact version, and sends one
authenticated `POST /std/sys/pkg/install` request with JSON `{author, name, version}`
to Pishoo. Pishoo verifies and installs the package and its exact package dependencies.
Successful output is JSON on stdout; progress and diagnostics go to stderr.
Package output abbreviates identities as `alice.smith~` and package IDs as
`alice.smith~/workspace`; the standard publisher appears as `std/workspace`.
Packages containing static pages include `entry_url` in the result, mounted at
`https://IDENTITY/app/NAME/`.
Resolution has a 120-second deadline; installation waits up to 15 minutes.
An interruption or timeout reports an unknown outcome and never retries the
write automatically. Dependencies installed before a parent failure remain.
Installation does not grant access permissions.

The store must support the current WEBC manifest metadata protocol. Older App
responses containing OpenAPI are rejected with a compatibility diagnostic.

## CLI help and identity listening

Use `genmeta --help`, `genmeta identity --help`, and `genmeta doctor --help`
for command groups. `--version` and `-V` are available for the launcher and
these groups; the `version` subcommand is also supported.

`genmeta listen --id NAME [internal|external|all|off]` queries or changes local listening. Omitting the mode reads existing configuration; explicit modes create missing configuration. `listen off` deletes the listen KV and leaves the identity stopped across restarts, preserving mounts. Stopping requires y/n confirmation; scripts use `--yes`. `genmeta mount [--id NAME] [PATH URL]` lists mounts or adds/updates one mount through `GET/PATCH /std/sys/mount`. `genmeta unmount [--id NAME] PATH URL [--yes]` uses `DELETE /std/sys/mount?location=PATH&proxy_pass=URL`, checking both values before deletion.

A running Pishoo process automatically discovers and applies saved changes.
Interactive identity application creates missing listening configuration only
when the user accepts server activation. Declining, or noninteractive application,
creates no server configuration. Existing configuration is preserved. The current
configuration path is `.volume/sys/setting/database`; credentials alone do not
enable hosting. Install an App or mount a local service to serve content.
See [Identity to Workspace and contacts](docs/identity-workspace-contacts.md)
for the complete command sequence, readiness checks, and contact approval flow.

Commands suppress runtime logs by default, including background NAT messages.
Pass `--verb` to enable debug logs, for example `genmeta --verb nslookup alice.smith~`.
The flag also works on standalone tools. `RUST_LOG` alone does not enable logs.
Command results, progress and errors remain visible; curl's `--verbose`
request/response output is independent of debug logging.

## Build and sign a package

`jade build PATH` reads `jade.toml`, runs native frontend or Rust API builds when
needed, and signs the resulting package locally. Static resources and prebuilt
Components use the same command. A running Pishoo service is not required.
The default output is `.jade/NAME-VERSION.waz`; `--id` selects the signing identity.
See [Jade](jade/README.md) for configuration, templates and JSON output.

## Access policies

`genmeta access` calls the selected identity's authenticated DHTTP management
API. `--id` selects both the local client credentials and the identity hosting
the API; otherwise the default identity is used. `--global` selects the home
scope for loading credentials. Pishoo must be running for that identity.

```bash
genmeta access --id alice.pilot /api allow '*?' --method GET
genmeta access /api review '**' --method POST
genmeta access /api deny '?'
genmeta access /api list
genmeta access list --wide
genmeta access /api remove '*?' --method GET
genmeta access /api remove --all --method GET
genmeta access remove /api
```

Rules are listed through `GET /std/acl/access`, written through
`POST /std/acl/access?api=PATH`, and deleted through
`DELETE /std/acl/allow?name=GRANTEE` with the API and method in the JSON body.
Path-specific reads use `GET /std/acl/access?api=PATH`; query values are URL encoded.
For App visibility, set GET on `/app/NAME` for `*?`; the host applies that root
policy to App GET/HEAD resources and deep links.
The CLI never opens or migrates the access database. Pishoo/daccess owns
persistence, authorization and the live policy cache. HTTP errors and pending
approval responses are reported without treating the operation as completed.

Paths are literal API prefixes. Each `(API, method, grantee)` has one policy;
setting it again updates the effect. Writes and explicit grantee removal
default to method `*`; lists, `clear`, `remove --all` and global path removal
include all methods unless `--method` is supplied. Grantees are registered
contact names, `group@issuer`, `**` (named), `?` (anonymous), or `*?` (all).
Only a trailing `~` expands contact/issuer names to `.dhttp.net`; ordinary names
keep their namespace. A named contact must already exist in daccess, except
for the profile owner. API prefixes must begin with `/` and contain no query,
wildcard or fragment.
Removal uses grantees rather than database row IDs. Bulk removal lists current
rules and deletes them individually through the API; it is not an atomic batch.
Successful writes print a confirmation after the server responds. `list --wide`
and path-specific `list` print tab-separated `PATH`, `METHOD`, `EFFECT`, and
`GRANTEE` columns with a header; `list` prints just the API prefixes.

Access management uses only mDNS resolution and direct local network endpoints.
DHTTP owns interface watching and exposes active IPv4 and IPv6 bindings.
The CLI selects and registers resolver sources through DHTTP's `qresolve`
interface, and passes binding snapshots to dyns to synchronize mDNS instances.
Connection candidates are handled by the current DHTTP/QUIC runtime.
It can operate without Internet access while the service remains locally
reachable and its certificates and cached OCSP staples are valid. The DHTTP
runtime starts background STUN probes, but initialization does not
wait for them. Missing or stale client OCSP staples require an online refresh;
unrestricted offline operation is therefore not guaranteed. Each management
request has a 30-second timeout, configurable with `--timeout`.

## Release dependencies and development builds

The 0.9.0-preview.2 release uses compatible crates.io versions for DHTTP, DNS, QUIC and
daccess. The published TLS backend is `qrustls` 0.23.45. `Cargo.lock` records the
resolved dependency versions. Publication order and lockfile preparation are
listed in [RELEASING.md](RELEASING.md). Run Cargo outside directories containing
ancestor path patches when preparing the release lockfile.

CLI settings, identity profiles and recoverable certificate installation are
maintained by dhttp-home. Online OCSP preparation is enabled explicitly when
loading an endpoint; ordinary DHTTP identity loading remains local-only.
Each CLI uses DHTTP endpoints directly and selects its dyns resolver sources.

The process-wide runtime manages all network interfaces. Curl, proxy and
nslookup accept the default `--interface '*'`; other outbound interface
patterns are rejected until the runtime exposes interface selection. NAT and
mDNS discovery accept interface names or local IPs as report/discovery filters.
Missing or stale local OCSP staples are fetched, validated and cached when an
identity is used.

## Package management

Project creation, builds and publication use the independent [Jade project](jade/README.md)
and its `jade` executable. Install it separately with `cargo install --path jade --locked`
from this checkout. Installation, updates, queries and removal use `genmeta`.

The development workflow uses `jade.toml` and existing native build tools.

```sh
# Static starter; no identity is needed until build.
jade create ./hello
jade build ./hello --id alice.smith
jade publish ./hello/.jade/hello-0.1.0.waz

# Rust API starter; Jade invokes Cargo, with no developer-written build script.
jade create ./service --template api
rustup target add wasm32-wasip2
jade build ./service --id alice.smith
jade publish ./service/.jade/service-0.1.0.waz
genmeta install std.dhttp.net/workspace --id alice.smith
genmeta update workspace --id alice.smith
genmeta install --list --id alice.smith
genmeta install --info message --id alice.smith
genmeta uninstall alice.smith.dhttp.net/message --id alice.smith
```

Package identity is `author/name`; all management operations act on the entire package. A `.waz` currently uses a WEBC v3 container and may contain a backend, static pages, or both, with one version and signature. `install --list`, `install --info` and `uninstall` query the selected identity's Pishoo service. Full package IDs must match the installed publisher; removal retains business data and dependencies.

`install` leaves an identical installed version unchanged and directs version
changes to `update`. `update` requires an installed package, stays with its current
publisher, and selects the latest published version unless `--version` is given.
The CLI checks these conditions before using the existing store installation API;
the preflight is not an atomic compare-and-swap with concurrent administrators.
Exact dependency/publisher checks and per-package transactions remain on the host.

`jade create PATH` generates a new project. `--template` selects static, web, api
or fullstack source files, and `--name` separates the package name from its folder.

`jade build [PATH]` accepts a directory or Jade configuration file. Frontend build
scripts run through npm/pnpm; Rust APIs compile through Cargo to WASI Components.
Existing static directories and Components are collected directly. Build checks
content and signatures, then atomically writes the package. `-o FILE --overwrite`
replaces an explicit output. Results are human-readable by default; `--json`
provides canonical IDs and stable diagnostic codes for scripts.

`jade publish FILE` reads the author from the signed package, checks matching
credentials and uploads the fixed snapshot. It does not rebuild the package.

The new removal command requires the Pishoo detail API's `Package-Id` response
header and sends `Expected-Package-Id` to prevent deleting a replacement publisher
under the same short name. Update Pishoo first if this capability is missing.

## Pishoo management

Pishoo provides the host APIs and `pishoo reload`; management lives in gmutils:

```sh
genmeta listen --id alice.smith all
genmeta listen --id alice.smith off --yes
genmeta listen --id alice.smith internal
pishoo reload
genmeta mount --id alice.smith /api 127.0.0.1:8080
genmeta unmount --id alice.smith /api 127.0.0.1:8080 --yes
genmeta install alice.smith/example --version 1.0.0 --id alice.smith
genmeta install --list --id alice.smith
```

Listening configuration is edited locally, including when listening is off.
Proxy changes and package operations call the running host and retain its authorization,
validation, dependency and atomic-install rules. Installation and updates select published store releases and resolve exact dependencies through the host. Local artifacts are used only for build and publish.
`jade build` builds or collects declared artifacts and signs directly. Local
signature and component checks run during build/publish; the host additionally
checks runtime compatibility during install/update. No Pishoo CLI or pishoo-pack
executable is needed. Service start/stop/restart/status belong
to systemctl or brew services; gmutils does not wrap them.

Store metadata uses `author`, `author_owner_hash` and `dependencies[].author`; catalog filters and update requests also use `author`. Signed manifest dependency keys remain `publisher`.
