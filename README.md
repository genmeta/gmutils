<p align="center">
  <img src="https://media.dhttp.net/img/gmutils/gmutils.svg" width="900" alt="GMUTILS command-line tool family: identity, access, curl, nslookup, doctor, proxy, and discover">
</p>
<p align="center">
  <a href="https://github.com/genmeta/gmutils/releases"><img src="https://img.shields.io/badge/version-0.9.0-1f6feb?style=flat-square" alt="Version 0.9.0"></a>
  <a href="https://doc.rust-lang.org/edition-guide/rust-2024/"><img src="https://img.shields.io/badge/Rust-2024-dea584?style=flat-square&amp;logo=rust&amp;logoColor=black" alt="Rust 2024 edition"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-00a51a?style=flat-square&amp;logo=apache&amp;logoColor=white" alt="Apache-2.0 license"></a>
  <a href="#install"><img src="https://img.shields.io/badge/Cargo-supported-dea584?style=flat-square&amp;logo=rust&amp;logoColor=black" alt="Cargo package supported"></a>
  <a href="https://github.com/genmeta/homebrew-preview"><img src="https://img.shields.io/badge/Homebrew-supported-fbb040?style=flat-square&amp;logo=homebrew&amp;logoColor=black" alt="Homebrew package supported"></a>
  <a href="https://github.com/genmeta/gmutils/releases"><img src="https://img.shields.io/badge/DEB-supported-a81d33?style=flat-square&amp;logo=debian&amp;logoColor=white" alt="DEB package supported"></a>
  <a href="https://github.com/genmeta/gmutils/releases"><img src="https://img.shields.io/badge/RPM-supported-ee0000?style=flat-square&amp;logo=redhat&amp;logoColor=white" alt="RPM package supported"></a>
</p>


gmutils is the Genmeta command-line tool family for DHttp networking. It gives an endpoint the tools it needs to create and use a Unified Identity, publish or reach services, control access, diagnose connectivity, and manage DHttp-based remote sessions.

The `genmeta` launcher exposes the suite behind a consistent command surface: `genmeta <tool> [options]`. Most utilities are also published as individual crates for users who only need one command.

## Utils

Available commands:

| Command | Purpose |
| ------- | ------- |
| `genmeta identity` | Create, apply, inspect, and renew Unified Identities and certificates. |
| `genmeta access` | Manage DHttp API access-control rules. |
| `genmeta curl` | Send DHttp requests with a curl-like interface. |
| `genmeta proxy` | Run a local forward proxy that forwards HTTP requests to DHttp endpoints. |
| `genmeta nslookup` | Resolve DDns names and discover reachable DHttp addresses. |
| `genmeta discover` | Discover nearby DHttp endpoints over mDNS. |
| `genmeta doctor` | Diagnose NAT and network connectivity. |

See the [DHttp utilities documentation](https://docs.dhttp.net/en/docs/core-components/utils) for detailed usage and examples.

## Install

Use the official package repository for a system installation. Both methods install the `gmutils` package, which provides the `genmeta` command.

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

## CLI help and identity listening

Use `genmeta --help`, `genmeta identity --help`, and `genmeta doctor --help`
for command groups. `--version` and `-V` are available for the launcher and
these groups; the `version` subcommand is also supported.

`genmeta identity ensite --id NAME` and `dissite --id NAME` update Pishoo's
`db/config.db` for the selected user or global home. `ensite` changes disabled
listening to `both` (3) and preserves an already enabled scope; `dissite` sets
it to `off` (0). Proxy rules are preserved. Restart the Pishoo process serving
that home after saving; an installed service supports `pishoo restart`.
New identity onboarding creates a configuration with listening disabled and
`file/welcome/index.html`, served at `/std/file/welcome/index.html` once enabled.

Access and curl log warnings and errors by default, suppressing background
NAT warnings. Set `RUST_LOG=debug` or
`RUST_LOG=trace` to inspect transport diagnostics. Curl progress and `--verbose`
request/response output are independent of this log filter.

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
`POST /std/acl/access/{api}`, and deleted through
`DELETE /std/acl/allow/{grantee}` with the API and method in the JSON body.
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
The shared mDNS resolver tracks active IPv4 and IPv6 sockets as interfaces
change. Connection candidates are handled by the current DHTTP/QUIC runtime.
It can operate without Internet access while the service remains locally
reachable and its certificates and cached OCSP staples are valid. The DHTTP
runtime starts background STUN probes, but initialization does not
wait for them. Missing or stale client OCSP staples require an online refresh;
unrestricted offline operation is therefore not guaranteed. Each management
request has a 30-second timeout, configurable with `--timeout`.

## Release dependencies and development builds

The 0.9.0 release uses compatible crates.io versions for DHTTP, DNS, QUIC and
daccess. The published TLS backend is `qrustls` 0.23.45. `Cargo.lock` records the
resolved dependency versions. Publication order and lockfile preparation are
listed in [RELEASING.md](RELEASING.md). Run Cargo outside directories containing
ancestor path patches when preparing the release lockfile.

CLI settings and atomic certificate installation are maintained inside
`genmeta-network`.

The process-wide runtime manages all network interfaces. Curl, proxy and
nslookup accept the default `--interface '*'`; other outbound interface
patterns are rejected until the runtime exposes interface selection. NAT and
mDNS discovery accept interface names or local IPs as report/discovery filters.
Missing or stale local OCSP staples are fetched, validated and cached when an
identity is used.
