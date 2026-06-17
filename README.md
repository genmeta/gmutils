# gmutils

gmutils is the Genmeta command-line tool family for DHTTP/3 networking,
identity management, discovery, diagnostics, access-control management, proxying,
and DShell sessions.

The workspace publishes the following crates:

| Crate | Purpose |
| ----- | ------- |
| `genmeta` | Unified launcher for the Genmeta CLI family. |
| `genmeta-access` | Access-control rule management. |
| `genmeta-curl` | Curl-like DHTTP/3 client. |
| `genmeta-discover` | LAN service discovery. |
| `genmeta-doctor` | Environment and network diagnostics. |
| `genmeta-identity` | DHTTP identity and certificate-chain management. |
| `genmeta-nat` | NAT and STUN diagnostics. |
| `genmeta-nslookup` | DNS and DHTTP resolver lookup tool. |
| `genmeta-proxy` | Forward proxy for DHTTP requests. |
| `genmeta-ssh` | DShell client compatibility command. |

## Install

After the initial public release is available on crates.io, install the launcher
with Cargo:

```bash
cargo install genmeta
```

Individual tool crates can also be installed directly, for example:

```bash
cargo install genmeta-ssh
cargo install genmeta-nat
```

## License

gmutils is licensed under the Apache License, Version 2.0.
