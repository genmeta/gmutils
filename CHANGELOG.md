# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.8.2] - 2026-08-31

### Added

- Add aggregate automatic certificate renewal with `identity renew --all`.
- Add local `ensite` and `dissite` server configuration management.

### Changed

- Promote `genmeta`, `genmeta-access`, `genmeta-discover`, and
  `genmeta-identity` to stable releases.
- Request certificates for both client and server use during apply, and create
  server configurations disabled by default.
- Let `genmeta ssh` use the ordinary DDNS default when no certificate sequence
  is supplied, derive the authority from the connected peer certificate, and
  use `/shell/<username>` as its default path.
- Keep `genmeta ssh` connections alive for two minutes after effective traffic,
  using 20-second heartbeat PINGs and a 60-second QUIC idle timeout.

### Fixed

- Migrate existing access-rule stores while preserving rule priority.

### Dependencies

- Require stable `dhttp` v0.6.2, `dshell` v0.6.2, and `h3x` v0.6.2.

### Components

- `genmeta` v0.8.2
- `genmeta-access` v0.4.2
- `genmeta-curl` v0.7.1
- `genmeta-discover` v0.4.2
- `genmeta-doctor` v0.4.1
- `genmeta-identity` v0.4.2
- `genmeta-nat` v0.5.1
- `genmeta-nslookup` v0.5.1
- `genmeta-proxy` v0.4.1
- `genmeta-ssh` v0.7.2

## [0.8.2-beta.2] - 2026-08-24

### Changed

- Let `genmeta ssh` use the ordinary DDNS default when no certificate sequence
  is supplied, matching `genmeta nslookup` behavior.
- Derive the conversation authority from the connected peer certificate after
  the QUIC handshake while preserving an explicitly supplied sequence.
- Use `/shell/<username>` as the default SSH path and remove the previous
  certserver candidate-ranking flow.
- Keep `genmeta ssh` connections alive for two minutes after effective traffic,
  using 20-second heartbeat PINGs and a 60-second QUIC idle timeout.

### Dependencies

- Require stable `dhttp` v0.6.2, `dshell` v0.6.2, and `h3x` v0.6.2.

### Components

- `genmeta` v0.8.2-beta.2
- `genmeta-ssh` v0.7.2
- All other gmutils workspace member versions are unchanged from v0.8.2-beta.1.

## [0.8.2-beta.1] - 2026-08-19

### Added

- Add aggregate automatic certificate renewal with `identity renew --all`.
- Add local `ensite` and `dissite` server configuration management.

### Changed

- Request certificates for both client and server use during apply, and create
  server configurations disabled by default.
- Migrate existing access-rule stores while preserving rule priority.

### Dependencies

- Restore crates.io dependencies on `dhttp` v0.6.2 and `dshell` v0.6.2.

### Components

- `genmeta` v0.8.2-beta.1
- `genmeta-access` v0.4.2-beta.1
- `genmeta-discover` v0.4.2-beta.1
- `genmeta-identity` v0.4.2-beta.1
- `genmeta-ssh` v0.7.2-beta.1
- All other gmutils workspace member versions are unchanged from v0.8.1.

## [0.8.1-beta.4] - 2026-08-11

### Fixed

- Adapt `genmeta nslookup` to the latest `qresolve` contract without changing
  its CLI: use the default QUIC/DHTTP service and request all address families.
- Update local resolver implementations to the latest `qresolve` contract.

### Dependencies

- Release manifests and the binary lockfile target `dhttp` v0.6.1, `h3x`
  v0.6.1, `dquic` v0.7.1, and `qresolve` v0.8.0.

### Components

- `genmeta` v0.8.1-beta.4
- `genmeta-nslookup` v0.5.1-beta.2
- All other gmutils workspace member versions are unchanged from v0.8.1-beta.3.

## [0.8.1-beta.3] - 2026-08-10

### Fixed

- Preserve `.dhttp.net` logical names and numeric certificate sequence
  selectors when opening DHTTP/3 connections.
- Apply HTTP and HTTPS default ports to conventional DNS targets before they
  reach the system resolver.

### Dependencies

- Release manifests target `dhttp` v0.6.1-beta.3 and `h3x` v0.6.1-beta.2.

### Components

- `genmeta` v0.8.1-beta.3
- `genmeta-curl` v0.7.1-beta.2
- `genmeta-proxy` v0.4.1-beta.2
- `genmeta-ssh` v0.7.1-beta.3
- All other gmutils workspace member versions are unchanged from v0.8.1-beta.2.

## [0.8.1-beta.2] - 2026-08-07

### Added

- Persist certificate-renewal operations and schedule automatic renewal for
  user and global identity scopes.

### Changed

- Identity apply and renew flows retain renewal state and preserve the active
  certificate-server ports while renewal work is in progress.
- DHTTP service names and default endpoints now use the current deployment
  variables.

### Fixed

- Renewal edge cases are handled without leaving stale renewal records or
  legacy service-port routing behind.

### Dependencies

- Release manifests target `dhttp` v0.6.1-beta.2 and `h3x` v0.6.1-beta.1.

### Components

- `genmeta` v0.8.1-beta.2
- `genmeta-identity` v0.4.1-beta.2
- All other gmutils workspace member versions are unchanged from v0.8.1-beta.1.

## [0.8.1-beta.1] - 2026-08-05

### Fixed

- Split ordinary HTTPS and H3 certificate-server endpoints so configured H3
  ports are retained while ordinary HTTPS uses the default port.
- Access rule additions are idempotent, and access listings use `~` shorthand
  for canonical `.dhttp.net` client names.

### Dependencies

- Release manifests target `dhttp` v0.6.1-beta.1.

### Components

- `genmeta` v0.8.1-beta.1
- `genmeta-access` v0.4.1-beta.1
- `genmeta-curl` v0.7.1-beta.1
- `genmeta-discover` v0.4.1-beta.1
- `genmeta-doctor` v0.4.1-beta.1
- `genmeta-identity` v0.4.1-beta.1
- `genmeta-nat` v0.5.1-beta.1
- `genmeta-nslookup` v0.5.1-beta.1
- `genmeta-proxy` v0.4.1-beta.1
- `genmeta-ssh` v0.7.1-beta.1

## [0.8.0] - 2026-08-04

### Changed

- Promote genmeta and all gmutils workspace components to stable releases.
- Align runtime dependencies with dhttp 0.6.0, h3x 0.6.0, dshell 0.6.0,
  and rankey 0.2.2.
- Adapt NAT diagnostics to one STUN client per interface.

### Components

- `genmeta` v0.8.0
- `genmeta-access` v0.4.0
- `genmeta-curl` v0.7.0
- `genmeta-discover` v0.4.0
- `genmeta-doctor` v0.4.0
- `genmeta-identity` v0.4.0
- `genmeta-nat` v0.5.0
- `genmeta-nslookup` v0.5.0
- `genmeta-proxy` v0.4.0
- `genmeta-ssh` v0.7.0

## [0.8.0-beta.8] - 2026-07-26

### Added

- `genmeta access` accepts `--id` as a visible alias for `--identity`.

### Changed

- Identity renewal is skipped when the current certificate is still valid for
  15 days or more; the command reports the remaining validity instead, and
  `--force` still renews immediately.

### Fixed

- Access commands explicitly close the SQLite connection pool before the
  runtime shuts down, so WAL `-shm`/`-wal` files are no longer left behind.
- Welcome guidance on macOS prints the correct
  `sudo brew services reload pishoo` command.

### Dependencies

- Release manifests now target `dhttp` v0.6.0-beta.5.

### Components

- `genmeta` v0.8.0-beta.8
- `genmeta-access` v0.4.0-beta.4
- `genmeta-identity` v0.4.0-beta.8
- All other gmutils workspace member versions are unchanged from v0.8.0-beta.7.

## [0.8.0-beta.7] - 2026-07-22

### Fixed

- Retained successful local key-generation and certificate-request milestones
  in the identity transcript so later terminal redraws cannot erase them.
- Removed blank QR-code quiet-zone rows above identity payment instructions.
- Welcome-service guidance now tells users to add themselves to the required
  local service group before reloading pishoo: `dhttp` on Linux and `_www` on
  macOS.
- Scoped Linux-only device-name parsing to Linux builds, avoiding unused-code
  warnings on other platforms.

### Components

- `genmeta` v0.8.0-beta.7
- `genmeta-identity` v0.4.0-beta.7
- All other gmutils workspace member versions are unchanged from v0.8.0-beta.6.

## [0.8.0-beta.6] - 2026-07-17

### Changed

- Paid identity checkout guidance puts the payment deadline and action before
  the indented QR code and leaves the copyable payment link last.
- Identity apply and renew retain checkmarked local key generation, CSR request,
  and committed installation or renewal milestones. Non-interactive execution
  emits the same successful milestones without progress animation.
- New welcome services are mounted at `/welcome`. Immediately after default
  identity selection, onboarding prints a compact, consistently indented block
  with the platform-specific pishoo reload command and the copyable `genmeta
  curl` command for the new identity.

### Components

- `genmeta` v0.8.0-beta.6
- `genmeta-identity` v0.4.0-beta.6
- All other gmutils workspace member versions are unchanged from v0.8.0-beta.5.

## [0.8.0-beta.5] - 2026-07-17

### Changed

- Identity progress clears transient name, email, payment, renewal, and default
  operations. Interactive terminals retain only local key generation and
  locally generated CSR completion; non-interactive execution emits no progress
  copy.
- Scoop package metadata derives its `checkver` URL from the selected stable or
  preview channel and uses the canonical version-matching expression.

### Fixed

- Identity email validation rejects malformed local and domain boundaries before
  contacting certserver and uses the same validation for prompted and explicit
  email input.
- Certserver errors accept current numeric codes and legacy symbolic codes,
  preserve the server-provided message, display the original wire error code,
  and use the same normalized recovery decisions for both representations.
- Identity progress operations no longer inherit the display-only progress span,
  ensuring completion is finalized before subsequent output and prompts.

### Dependencies

- Release packaging uses `genmeta-xtask-release` v0.2.0-beta.9 for
  channel-aware Scoop metadata.

### Components

- `genmeta` v0.8.0-beta.5
- `genmeta-identity` v0.4.0-beta.5
- All other gmutils workspace member versions are unchanged from v0.8.0-beta.4.

## [0.8.0-beta.4] - 2026-07-16

### Added

- `genmeta id` is a visible alias for `genmeta identity`.
- `genmeta identity default -v` shows the default identity's full details.
- Successful identity apply, replacement, and renewal append a post-commit
  certificate audit record to the selected profile's `cert.log`; audit-write
  failures do not roll back installed identity material.

### Changed

- `genmeta ssh` now discovers all online primary sequences, preserves server ranking, and connects through the first online sequence unless an explicit selector is supplied.
- `genmeta identity apply [name]` is now the single create-or-update flow;
  the former `identity create` command has been removed.
- Existing identities, new root identities, and new direct sub-identities now
  share the same `identity apply` lifecycle. Names entered by an interactive
  prompt receive an early local and certserver availability check.
- Bare `genmeta identity renew` targets the configured default identity, and
  renew no longer accepts `--default`.
- Identity authentication selects the first usable proof from the target,
  direct parent, and email sequence. It skips expired, incomplete, and invalid
  local certificates with an actionable warning, while transport and server
  failures remain terminal instead of changing proof.
- Verification-code recovery keeps attempt limits at the code prompt without
  resending automatically, and treats blocked accounts as terminal.
- `apply`, `renew`, and `default` now give `--force` command-specific meanings:
  local replacement approval, recoverable renewal preflight, and non-ready
  default selection respectively. Force never bypasses authentication,
  certificate validation, payment confirmation, or a missing local target.
- Removed legacy public identity flow switches, including `--auth`,
  `--register-if-missing`, `--replace-local`, `--send-code`, and
  `--allow-nonready`.
- Compact identity output uses `(default)` and retains abnormal states. The
  shared detail renderer reports usage, sequence, profile directory, validity,
  reason, and warning fields; `default -v`, `info`, and `list -v` use the same
  format.
- Renewal preserves the original certificate-chain kind and sequence, performs
  strict local preflight, installs validated material transactionally, and
  prints a visible success result.

### Fixed

- Identity authentication now degrades only after unusable local material or
  explicit authorization rejection; transport, parsing, quota, and unknown
  failures remain terminal.
- Generated private keys stay in memory until a validated certificate can be
  installed, and local certificate/key replacement rolls back on commit
  failure without deleting service files.

### Fixed

- Identity fallback errors compile cleanly with the release workflow nightly toolchain.

### Dependencies

- Release manifests now target `dhttp` v0.6.0-beta.4, including
  `dhttp-access` v0.4.0-beta.2, `dhttp-home` v0.5.0-beta.1, and
  `dhttp-log` v0.1.0-beta.1 through the facade; discovery and transport
  dependencies target `dyns` v0.7.0-beta.2, `h3x` v0.6.0-beta.4,
  `dquic` v0.7.0-beta.4, and `dshell` v0.6.0-beta.3.

### Components

- `genmeta` v0.8.0-beta.4
- `genmeta-curl` v0.7.0-beta.4
- `genmeta-ssh` v0.7.0-beta.4
- `genmeta-access` v0.4.0-beta.3
- `genmeta-identity` v0.4.0-beta.4
- `genmeta-proxy` v0.4.0-beta.3
- `genmeta-discover` v0.4.0-beta.3
- `genmeta-doctor` v0.4.0-beta.3
- `genmeta-nat` v0.5.0-beta.3
- `genmeta-nslookup` v0.5.0-beta.3

## [0.8.0-beta.3] - 2026-07-09

### Added

- `genmeta access` supports explicit DHTTP identity shorthand in access-rule
  patterns through the `dhttp` access facade.

### Changed

- Access-control integration now consumes access APIs and access feature
  activation through the `dhttp` facade instead of a direct `dhttp-access`
  dependency.
- CLI progress integration remains opt-in so ordinary non-progress output is
  stable.

### Fixed

- Release workflows upload package assets from publish reports instead of broad
  local artifact globs.

### Dependencies

- Release manifests now target `dhttp` v0.5.0-beta.3, `dhttp-access`
  v0.4.0-beta.1 through the `dhttp` facade, `dhttp-home`
  v0.4.0-beta.1, `dhttp-identity` v0.3.0-beta.1, `dyns`
  v0.6.0-beta.3, `h3x` v0.6.0-beta.3, `dquic`
  v0.7.0-beta.2, `dshell` v0.6.0-beta.2, and `rankey` v0.2.1.

### Components

- `genmeta` v0.8.0-beta.3
- `genmeta-curl` v0.7.0-beta.3
- `genmeta-ssh` v0.7.0-beta.3
- `genmeta-access` v0.4.0-beta.2
- `genmeta-identity` v0.4.0-beta.3
- `genmeta-proxy` v0.4.0-beta.2
- `genmeta-discover` v0.4.0-beta.2
- `genmeta-doctor` v0.4.0-beta.2
- `genmeta-nat` v0.5.0-beta.2
- `genmeta-nslookup` v0.5.0-beta.2

## [0.8.0-beta.2] - 2026-07-06

### Added

- `genmeta curl` now reports HTTP/3 verbose metadata, redirect/upload verbose output, progress coordination, streamed response handling, and `--fail` flag clusters.
- `genmeta identity` now shows QR checkout codes and enriches generated device names.
- `genmeta ssh` now selects the SSH primary sequence before connecting.

### Fixed

- `genmeta curl` now rejects unsupported redirect schemes and invalid redirect locations, preserves verbose markers while decoding, and sends headers before upload bodies.

### Dependencies

- Release manifests now target `h3x` v0.6.0-beta.2, `dhttp`
  v0.5.0-beta.2, `dhttp-access` v0.3.0, `dshell` v0.6.0-beta.2,
  `dyns` v0.6.0-beta.2, and `rankey` v0.2.1.

### Components

- `genmeta` v0.8.0-beta.2
- `genmeta-curl` v0.7.0-beta.2
- `genmeta-ssh` v0.7.0-beta.2
- `genmeta-access` v0.4.0-beta.1
- `genmeta-identity` v0.4.0-beta.2
- `genmeta-proxy` v0.4.0-beta.1
- `genmeta-discover` v0.4.0-beta.1
- `genmeta-doctor` v0.4.0-beta.1
- `genmeta-nat` v0.5.0-beta.1
- `genmeta-nslookup` v0.5.0-beta.1

## [0.8.0-beta.1] - 2026-07-02

### Changed

- Prepared the CLI workspace for the DHTTP beta dependency line.
- Release packaging now resolves package destinations by stable/preview
  channel and pins the shared `genmeta-xtask-release` tooling to the
  reproducible `v0.1.0` git tag.

### Fixed

- Identity apply/create flows recover from owner-email mismatches and missing
  target identities during apply, then create the welcome service files for
  newly saved local identities.
- Certificate server quota/error parsing accepts the current V2 response
  shapes used by sub-identity registration.

### Dependencies

- Release manifests now target `h3x` v0.6.0-beta.1, `dhttp`
  v0.5.0-beta.1, `dhttp-access` v0.3.0, `dshell` v0.6.0-beta.1,
  `dyns` v0.6.0-beta.1, and `rankey` v0.2.1.
- Release tooling uses `genmeta-xtask-release` v0.1.0 from the public
  `v0.1.0` git tag.

### Components

- `genmeta` v0.8.0-beta.1
- `genmeta-curl` v0.7.0-beta.1
- `genmeta-ssh` v0.7.0-beta.1
- `genmeta-access` v0.4.0-beta.1
- `genmeta-identity` v0.4.0-beta.1
- `genmeta-proxy` v0.4.0-beta.1
- `genmeta-discover` v0.4.0-beta.1
- `genmeta-doctor` v0.4.0-beta.1
- `genmeta-nat` v0.5.0-beta.1
- `genmeta-nslookup` v0.5.0-beta.1

## [0.7.0] - 2026-06-26

### Added

- CLI tools now support scoped dhttp home selection across identity, access,
  curl, nslookup, NAT, proxy, and SSH flows.
- Release packaging now reads its build and destination contract from
  `xtask/release.toml`, including per-target build environment bindings.

### Changed

- Identity flows use explicit apply targets, replacement-aware default prompts,
  and selected-home local-state behavior for missing identity homes.
- Homebrew and S3/R2 package generation use the normalized manifest-first
  packaging contract.

### Fixed

- Identity `default` and `renew` commands now report missing selected-home state
  through user-facing business errors instead of raw filesystem/profile errors.
- CLI and package integration are aligned with the scoped dhttp home rollout.

### Dependencies

- Release manifests now target `h3x` v0.5.0, `dhttp` v0.4.0,
  `dhttp-access` v0.3.0, `dshell` v0.5.0, `dyns` v0.5.0, and `rankey` v0.2.1.

### Components

- `genmeta` v0.7.0
- `genmeta-curl` v0.6.0
- `genmeta-ssh` v0.6.1
- `genmeta-access` v0.3.0
- `genmeta-identity` v0.3.0
- `genmeta-proxy` v0.3.0
- `genmeta-discover` v0.3.1
- `genmeta-doctor` v0.3.1
- `genmeta-nat` v0.4.0
- `genmeta-nslookup` v0.4.0

## [0.6.0] - 2026-06-15

This release brings the command-line tool family onto the public DHTTP
endpoint stack. The launcher, client tools, identity flows, access
management, DShell integration, diagnostics, and packaging pipeline now line
up around the same DHTTP identity, trust, discovery, and transport crates
that are published for the broader ecosystem.

### Added

- `genmeta-identity` now speaks the certificate server V2 API for identity
  creation, application, renewal, approval selection, and checkout polling.
  It supports identity-based and email-based approval paths, staged email
  verification, local replacement confirmation, and server-assigned chain
  sequencing.
- Identity commands render transcript-style progress, chain summaries, and
  network wait feedback through `indicatif`, including spinners for long
  certificate and checkout operations.
- The release `xtask` now stages and verifies manifest-based packages for
  DEB, RPM, Scoop, and Homebrew outputs, then plans and publishes the
  corresponding S3/R2 metadata.
- CI now runs release dry-runs for the product package surfaces and has a
  separate crates.io publish workflow that skips package versions already
  present in the registry.

### Changed

- `genmeta`, `genmeta-curl`, `genmeta-discover`, `genmeta-doctor`,
  `genmeta-identity`, `genmeta-nat`, `genmeta-nslookup`, `genmeta-proxy`,
  and `genmeta-ssh` now build against the DHTTP endpoint facade and its
  published transport/discovery stack.
- `genmeta-ssh` now uses the `dshell` crate and WebTransport conversation
  API directly, keeping the compatibility CLI while moving protocol handling
  into the DShell crate.
- `genmeta-identity` now uses DHTTP identity metadata under `dhttp.net`,
  consumes `dhttp::trust::DHTTP_ROOT_CA`, and embeds the certificate server
  base URL from the build-time `DHTTP_CERT_SERVER_URL` environment variable.
  Runtime `CERT_SERVER_URL` overrides are no longer used.
- Identity CLI policy now requires explicit approval-path choices when
  non-interactive input would otherwise be ambiguous. `--auth identity` and
  `--auth email` remain; automatic guessing is removed from the user-facing
  flow.
- `genmeta-curl` normalizes bare DHTTP authorities before request
  construction, so inputs such as an identity authority resolve to an HTTPS
  root request.
- NAT diagnostics use deterministic bootstrap STUN selection, typed failure
  classification, streamed interface reports, and clearer bullet summaries.
- Access-control commands use the DHTTP access facade and a simplified path
  command shape.

### Removed

- The deprecated `genmeta-common` crate has been removed. Tool-specific
  crates now consume DHTTP endpoint types and helpers directly from the
  facade.
- Legacy root-CA bootstrap wiring and old Homebrew content snippets were
  removed in favor of the current DHTTP trust and package-manifest flows.

### Fixed

- Release packaging now forwards DHTTP bootstrap environment variables into
  package builds and passes the embedded root CA into DEB builds.
- Containerized package builds patch sibling dependencies correctly during
  local integrated runs while official release CI remains standalone.
- Windows MSVC packaging builds are supported, Scoop cross-builds are
  serialized where needed, and the S3 client avoids the aws-lc backend that
  fails on the i686 Windows toolchain.
- Linux packaging handles current target constraints: unsupported armv7 RPM
  output is skipped, and the temporary aarch64 Zig linker workaround filters
  the unsupported Cortex-A53 linker flag.
- The launcher installs the Rustls crypto provider before initializing tool
  subcommands.
- DHTTP client paths wait for WebTransport peer settings before using the
  connection, and the default connect-timeout path is bounded.
- `genmeta-nat` observes STUN clients from the active network state before
  classifying connectivity results.

### Dependencies

- Release manifests now target upstream crates from this release wave: `h3x`
  v0.4.0, `dhttp` v0.2.0, `dhttp-access` v0.2.0, `dshell` v0.4.0,
  `dyns` v0.4.0, and `rankey` v0.2.1.

### Components

- `genmeta` v0.6.0
- `genmeta-curl` v0.5.0
- `genmeta-ssh` v0.6.0
- `genmeta-access` v0.2.0
- `genmeta-identity` v0.2.0
- `genmeta-proxy` v0.2.0
- `genmeta-discover` v0.3.0
- `genmeta-doctor` v0.3.0
- `genmeta-nat` v0.3.0
- `genmeta-nslookup` v0.3.0

## [0.5.0] - 2026-04-20

Major release following the workspace-wide migration to the `h3x`
ecosystem and the introduction of the `dhttp-home` identity model.
Compared to v0.4.2, identity management, the DNS stack, several CLI
shapes, and the crate layout have all changed.

### Added

- **`genmeta-identity` crate** — the sole entry point for managing
  identities (`genmeta identity create | apply | renew | list | info |
  default`). Talks to the certificate server over DHTTP/3 with TLS
  certificate pinning. Supports `--captcha` and the `CERT_SERVER_URL`
  environment variable for non-interactive enrollment and renewal.
  Displays key usage and extended key usage, and manages the default
  identity explicitly.
- **`dhttp-home` as a first-class dependency** — a DHTTP home holds
  many identity homes. `genmeta identity` is the only writer; every
  other tool discovers identities from the same home.
- **Unified identity-lookup convention across every tool** —
  `-i/--id <name>` accepts either a partial or fully qualified name
  (expanded via `Name::try_expand_from`), otherwise the default
  identity is used. `--anonymous` skips identity loading entirely.
  The `GENMETA_HOME` environment variable selects an alternate home.
- **`genmeta-proxy` crate** — a new HTTP/1.1 forward proxy. Routes
  `.genmeta.net` hosts over DHTTP/3, tunnels `CONNECT` over TCP,
  supports `--daemon`/`--log`, TCP keepalive, a connection cap, and a
  header read timeout. Defaults to dual-stack `[::]:16080`.
- **`genmeta-access` crate** — identity-scoped access rules persisted
  in SQLite (replaces the former standalone `firewall-bin` CLI).
- **`xtask` crate** — packaging pipeline using
  `dpkg-buildpackage` + `debhelper`, cross-compiling to multiple
  targets in parallel with mounted cargo caches. `--sibling`
  bind-mounts sibling workspaces for integrated builds.
- **Dynamic interface rebinding** in `curl`, `ssh`, `nslookup`,
  `proxy`, and `discover` via `watch_bind_interfaces`, stabilised by
  `identity_key` so stable endpoints survive interface churn.
- **Minor CLI features** — `curl -4/-6` address-family selection;
  `ssh` native raw mode with SIGWINCH resize forwarding; `genmeta
  nat` resolves its STUN server via gmdns instead of a hard-coded
  address.

### Changed

- Workspace-wide migration to the **`h3x` ecosystem** (Network +
  QuicEndpoint API), replacing the previous `h3` / `gm-quic` stack.
  `dquic` is re-exported through `h3x::dquic`.
- Default DNS resolver: **`http` → `h3`**, with a system-resolver
  fallback.
- SSH URI scheme: **`ssh3://` → `https://`**.
- Terminology sweep: **`HTTP/3` → `DHTTP/3`** across the codebase.
- Identity CLI flags: `--domain`/`--domains` **→ `--suffix`/`--identities`**;
  the `.genmeta.net` suffix is hidden in display output.
- `genmeta-common` reorganised into `bind` / `dns` / `id` /
  `h3-client` features, with `bon`-based builder APIs for h3 client
  setup.
- A custom root CA (project `root.crt`) is **merged with** the system
  trust store instead of replacing it.
- Structured error types across `curl`, `ssh`, `nslookup`, `nat`,
  `discover`, and `identity`: `Whatever` replaced by named `Error`
  enums, with `snafu::Report` for consistent error rendering.

### Removed

- `genmeta-profile` crate — identity modelling has moved into
  `dhttp-home` plus `genmeta-identity`.
- `genmeta-ssh3` crate — renamed to **`genmeta-ssh`** alongside the
  URI-scheme change.
- The system DNS resolver helper in `genmeta-common`.
- The `STUN_SERVER` environment variable.
- The legacy buildx / Makefile packaging — superseded by `xtask`.

### Fixed

- Certificate-server client now enforces TLS certificate pinning.
- Proxy: rewrites upstream HTTP/3 responses to HTTP/1.1 before
  forwarding; uses the low-level `h3` API for correct stream
  lifecycle management.
- SSH: defers `connection.close()` while forwarding tasks are still
  active; moved stdin reads to a dedicated thread; PTY/flush fixes
  via updated `genmeta-ssh-core`.
- Removed panic risks from `unwrap`/`expect` on dynamic data paths.
- TTY detection gates ANSI colouring in `tracing` output so logs stay
  clean when redirected.

### Dependencies

- All git dependencies are pinned to specific revisions: `gmdns`,
  `rankey`, `firewall-base`/`-db`/`-migration`, and `genmeta-ssh-core`.
- `dhttp-home` tracks `branch = "main"` to stay unified with the
  transitive usage from `firewall-db`; `Cargo.lock` still locks it
  to a specific commit.
- `h3x` is pulled once: the direct dependency tracks `main` over
  `https://`, with a `[patch."https://github.com/genmeta/h3x.git"]`
  redirect to `ssh://` at a fixed revision. This unifies the direct
  dependency with transitive `h3x` uses from `gmdns` and
  `genmeta-ssh-core`, so exactly one copy is compiled.
- `h3x` is the only git dependency over `https://`; everything else
  uses `ssh://`.

### Components

- `genmeta` v0.5.0
- `genmeta-common` v0.2.0
- `genmeta-curl` v0.4.0
- `genmeta-discover` v0.2.0
- `genmeta-doctor` v0.2.0
- `genmeta-nat` v0.2.0
- `genmeta-nslookup` v0.2.0
- `genmeta-ssh` v0.5.0 (formerly `genmeta-ssh3`)
- `genmeta-identity` v0.1.0 (new)
- `genmeta-access` v0.1.0 (new)
- `genmeta-proxy` v0.1.0 (new)

### Policy

- Starting with v0.5.0, this CHANGELOG is written in English and
  follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).


## [0.4.2] - 2025-11-3

### Changed
- 更新traversal依赖

## [0.4.1] - 2025-9-30

### Changed
- 使用genmeta-buildx构建系统自动打包
- genmeta-ssh3和genmeta-curl支持connect timeout参数
- genmeta-ssh3解析命令行-o选项，优先级高于配置文件
- genmeta-ssh3协议更新（客户端传递环境变量，重命名）
- ssh3相关代码移动到单独仓库
- 其他诸多琐碎问题...

### Components
- genmeta v0.4.1
- genmeta-ssh3 v0.4.1
- genmeta-curl v0.3.1

## [0.4.0] - 2025-9-23

### Changed
- 新增genmeta-doctor，genmeta-nat 移入其中作为net子命令
- 新增ssh-config crate用于处理openssh和genmeta配置文件（ssh config语法）
- genmeta-ssh3h和curl支持--id参数携带身份，解析profile身份配置文件，发起带有client name参数和tls证书的quic连接
- 重构了错误处理，使用snafu::report宏自动打印错误栈
- 修复tracing初始化方式和默认日志级别

### Components
- genmeta v0.4.0 ?
- genmeta-ssh3 v0.4.0 ?
- genmeta-curl v0.2.0 ?
- genmeta-doctor v0.1.0
- ssh-config v0.1.0

## [0.3.2] - 2025-7-30

### Changed
- ssh3支持了windows平台

### Components
- genmeta v0.3.2
- genmeta-ssh3 v0.3.1

## [0.3.1] - 2025-7-30

### Changed
- 依赖：更新gm-quic-traversal，适配windows

### Components
- genmeta v0.3.1

## [0.3.0] - 2025-07-29

### Changed
- 依赖：适配gm-quic-traversal v0.3
- 新增：nat探测工具
- 重构：将tracing_subscriber初始化交给子模块
- 重构：结构化ssh3和ssh3-proto的错误
- 重构：优化ssh3的命令行参数解析
- 重构：修复ssh3-proto的一些typo

### Components
- genmeta v0.3.0
- genmeta-ssh3 v0.3.0
- genmeta-curl v0.1.6
- genmeta-nslookup v0.1.3
- genmeta-discover v0.1.2
- genmeta-nat v0.1.0
- ssh3-proto v0.2.0

## [0.2.8] - 2025-06-26

### Changed
- 重构：将 genmeta-request 重命名为 genmeta-curl，更好地反映工具的用途
- genmeta-nslookup: 优化输出格式，提升可读性
- genmeta-discover: 优化输出格式，提升可读性

### Fixed
- genmeta-nslookup: DNS 结果去重，避免重复显示
- genmeta-discover: DNS 结果去重，避免重复显示

### Components
- genmeta v0.2.8
- genmeta-ssh3 v0.2.7
- genmeta-curl v0.1.4 (formerly genmeta-request)
- genmeta-nslookup v0.1.2
- genmeta-discover v0.1.1

## [0.2.7] - 2025-06-11

### Added
- ssh3, request, nslookup 支持使用~省略.genmeta.net

### Changed
- 更新依赖，提升打洞能力

### Components
- genmeta v0.2.7
- genmeta-ssh3 v0.2.7  
- genmeta-request v0.1.4
- genmeta-nslookup v0.1.1

## [0.2.6] - 2025-06-04

### Added
- 新工具：genmeta-nslookup，支持DNS查询
- 新工具：genmeta-discover，支持发现局域网中的设备（mdns）
- genmeta-ssh3 和 genmeta-request 支持 http dns 和 mdns 解析

### Components
- genmeta v0.2.6
- genmeta-ssh3 v0.2.6
- genmeta-request v0.1.3
- genmeta-nslookup v0.1.0
- genmeta-discover v0.1.0

## [0.2.5] - 2025-05-30

### Added
- request 发送请求时设置 http 版本为 h3
- request 发送请求时设置 Host, User-Agent, Accept 头
- ssh 支持 -l（登录用户名）选项，更好支持 rsync

### Fixed
- ssh 修复进程退出时没有恢复终端

### Components
- genmeta v0.2.5
- genmeta-ssh3 v0.2.5
- genmeta-request v0.1.2

## [0.2.4] - 2025-05-26

### Added
- 提取 gateway 和 gmutils 关于 ssh 协议的共通代码
- 支持本地转发和远程转发，整理动态转发
- 发送心跳保活包保持连接活跃
- session 结束时结束程序
- server 返回进程退出的状态码

### Components
- genmeta v0.2.4
- genmeta-ssh3 v0.2.4
- ssh3-proto v0.1.0

## [0.2.3] - 2025-05-21

### Changed
- 自己实现配置解析而不是使用 ssh_config（修复了难以交叉编译的问题）
- 跟进 gm-quic-traversal 更新

### Components
- genmeta v0.2.3
- genmeta-ssh3 v0.2.3

## [0.2.2] - 2025-05-19

### Added
- 支持加载系统 ssh 配置文件
- 将 fake-ssh.sh（genmeta-ssh3.sh）打包进 deb

### Fixed
- 修复 mux 不正确退出，收包完全惰性的问题

### Components
- genmeta v0.2.2
- genmeta-ssh3 v0.2.2

## [0.2.1] - 2025-05-19

### Added
- 加上了这个 changelog

### Changed
- 优化 mux 的行为，更贴近标准的 ssh，只有多路复用的所有Channel结束ssh才结束
- 优化了日志打印
- 让 ssh 不处理 heredoc

### Components
- genmeta v0.2.1
- genmeta-ssh3 v0.2.1

## [0.2.0] - 2025-05-17

### Changed
- 完全重写 ssh

### Components
- genmeta v0.2
