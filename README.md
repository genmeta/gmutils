<p align="center">
  <img src="https://media.dhttp.net/img/gmutils/gmutils.svg" width="900" alt="GMUTILS command-line tool family: identity, access, curl, nslookup, ssh, doctor, proxy, and discover">
</p>
<p align="center">
  <a href="https://github.com/genmeta/gmutils/releases"><img src="https://img.shields.io/badge/version-0.8.2--beta.2-1f6feb?style=flat-square" alt="Version 0.8.2-beta.2"></a>
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
| `genmeta ssh` | Administer remote endpoints over DHttp with SSH-compatible syntax. |
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
cargo install --path genmeta
```

## Quick start

Create or apply an identity through the interactive flow, then inspect the available commands:

```bash
genmeta identity apply
genmeta --help
```

Identities are stored under the current user's `~/.dhttp` directory by default. Most client commands use the default identity automatically; pass `--id` to select another identity when a command supports it.
