# Release preparation for v0.9.0-preview.5

| Package | Published version | Prepared version |
| --- | --- | --- |
| genmeta | 0.9.0-preview.4 | 0.9.0-preview.5 |
| genmeta-access | 0.5.0-preview.3 | 0.5.0-preview.4 |
| genmeta-curl | 0.8.0-preview.3 | 0.8.0-preview.4 |
| genmeta-discover | 0.5.0-preview.2 | 0.5.0-preview.3 |
| genmeta-doctor | 0.5.0-preview.2 | 0.5.0-preview.3 |
| genmeta-identity | 0.5.0-preview.4 | 0.5.0-preview.5 |
| genmeta-nat | 0.6.0-preview.2 | 0.6.0-preview.3 |
| genmeta-nslookup | 0.6.0-preview.2 | 0.6.0-preview.3 |
| genmeta-proxy | 0.5.0-preview.2 | 0.5.0-preview.3 |
| jade | not published by this workflow | 0.1.0 (bundled executable) |

The published versions above were checked against crates.io on 2026-10-23.
Every Genmeta crate changed after v0.9.0-preview.4, so each receives a new preview
version and workspace dependencies select those new versions. The publication
order already places dependencies before dependents. Jade ships in the gmutils
Debian and Homebrew packages and remains outside the crates.io publication list.
The `feat/waz-release-20261023` PR branch prepares these changes;
no tag is created or pushed by this preparation.

## Scope and compatibility

This release targets the current Pishoo unified Pkg, listen/mount and query-based
ACL APIs. Package creation, build and publication use the separate Jade executable
(`jade create/build/publish`); frontend and backend source locations are discovered
automatically without configuration sections. `genmeta` provides install/update/uninstall and
installed queries via install --list/--info. Signed source files use .waz. No
legacy App/Lib package flags, package/server grouping, forward or unlisten aliases
are restored. App entry URLs use /app/NAME/.

Listen edits .volume/sys/setting/database locally, including when the identity is
off. It accepts internal/external/all/off, and off retains mounts. Mount/unmount
use the authenticated running Pishoo /std/sys/mount API. Unmount matches both
location and proxy_pass; off and unmount require confirmation or --yes.

Package installation and upgrades do not install Workspace. After interactive
identity application with the server enabled, the CLI asks whether to install
Workspace, defaulting to yes on Enter. Confirmation precedes a read-only readiness
check and `genmeta install workspace --id NAME`. Running Pishoo automatically
discovers enabled identities; this flow does not call `pishoo reload` or require
a system-managed service. The readiness check waits for up to 30 seconds.
Installation uses the
same identity home, including global applications. Disabled servers,
non-interactive runs and declined or cancelled prompts skip readiness checks and
installation. Skips and failures print the manual install command; failures retain
the applied identity. Only the read-only readiness check is retried; installation
is submitted once. This replaces the package-manager Workspace install hooks.

Package output abbreviates identities and URL hosts with `~`, and displays the
standard publisher as `std`, including in JSON results. Protocol requests retain
canonical identities.

Identity activation creates only explicit listening configuration. It no longer
creates a default welcome site. Certificate logging preserves history when moving
an existing real logs directory into log. Curl header write-out tokens consume
both closing braces, including Pishoo-Viewer-Name on App HEAD responses.

Runtime dependencies use published registry releases without sibling Cargo
patches. The access CLI's test-only daccess dependency uses the same published
crates.io version 0.2.0 as Pishoo, so its contract tests exercise the current HTTP
routes. There is no Git source override for this dependency.

## Jade project

Jade lives in `jade/` with its own manifest, executable, README, fixtures and tests.
Build and test it with `cargo build -p jade --locked` and
`cargo test -p jade --locked`. Install from this checkout with
`cargo install --path jade --locked`. Workspace CI includes Jade. The gmutils
Debian and Homebrew packages install both the `genmeta` and `jade` commands;
their version continues to follow `genmeta/Cargo.toml`. The existing release
workflow builds both executables and checks the archive contents before
publication. Homebrew supports Apple Silicon and Intel Macs and tests both
installed commands. RPM/Scoop recipes and the crates.io publication list are unchanged.

Jade implements the `create/build/publish` workflow described in the
[implementation plan](jade/IMPLEMENTATION_PLAN.md): `jade.toml`, native frontend
builds, Rust HTTP API templates with built-in Cargo invocation, local content and
signature checks, and human/JSON result reporting. Publish uses the signed
package's author; package output defaults to `build/`. New `.waz` releases are standard ZIP files; update the store and host readers before publication. Old WEBC releases must be rebuilt. Runtime templates and local
HTTP/3 publication have dedicated acceptance checks; platform CI remains a release
gate.

### Local application release

Applications use local `jade build` and `jade publish`; there are no application
release workflows. The six independent repositories are Workspace, Introduction,
Profile, Message, Calendar and Journal under `pishoo-projects`. Their
`RELEASING.md` files record exact versions, dependencies and commands.

Install gmutils through Debian or Homebrew, or build this checkout. Prepare Bun 1.4.2+
and Node for source frontends; install the `wasm32-wasip2` Rust target and set
`WASI_SDK_PATH` for SQLite backends. In each repository, run the existing tests,
then `jade build`. Review `build/NAME-VERSION.waz` before running
`jade publish build/NAME-VERSION.waz`. Jade reads the manifest's author and uses
the matching local DHTTP credentials. Standard applications use `std.dhttp.net`;
Journal uses `alice.smith.dhttp.net`. Local validation used isolated test signing
identities; those test packages were saved outside the application repositories.
Build locally with the real author identity before publishing.

Release order: deploy the registry's existing `author`/`.waz` implementation first;
then Profile 0.3.0 and Message 0.2.1; then Introduction 0.1.0; then Workspace 0.3.2.
Calendar 0.1.2 and Journal 0.1.2 can follow independently. The 2026-10-23 read-only
production probe still returned `publisher` and `.pkg`; Jade rejects that catalogue
before sending any upload. No registry deployment or data migration is part of
these application changes. On `E_PUBLISH_OUTCOME_UNKNOWN`, keep and retry the same
signed file after checking the reported state; do not rebuild or automatically
repeat an upload. Do not reuse a version for changed runtime content.

## Preview.5 release checks

- `cargo test --workspace --locked --all-features --all-targets -- --test-threads=1`:
  passes, with environment-specific acceptance tests run separately. Real Rust
  API, web/fullstack template and local HTTP/3 publication checks also pass.
- Workspace formatting, strict all-target/all-feature Clippy and `git diff --check`
  pass. The built launcher reports `genmeta 0.9.0-preview.5`.
- All nine changed Genmeta crates pass `cargo publish --dry-run --locked --allow-dirty`
  together, including compilation of packaged sources and temporary-registry
  resolution of their new dependency versions. Each upload is explicitly skipped
  by Cargo's dry-run mode.
- The lockfile records the new workspace versions, ZIP dependencies and the
  crates.io daccess 0.2.0 release. Platform packaging and remote CI remain pre-tag gates.

## Validation on 2026-10-23

- Jade regular tests, strict Clippy, formatting, stable Rust check and the local
  HTTP/3 publication contract pass. The earlier Rust API/host acceptance remains
  recorded in `jade/IMPLEMENTATION_PLAN.md`.
- All six applications build and sign through Jade with isolated test identities.
  Existing Workspace, Introduction, Profile, Message and Calendar tests pass;
  Journal has no unit tests and was verified by its actual Jade build.
- Before the preview.5 version bump, a real amd64 Debian package was built with the release recipe and installed in
  a disposable Debian container. Both commands run; the installed Jade creates
  and signs a static project successfully.
- Before the preview.5 version bump, the native Apple Silicon Homebrew archive was built with the release recipe.
  Both Mach-O commands run after extraction, and Jade creates and signs a static
  project. The formula installs and tests both commands. The release workflow
  also packages Intel Macs; this local smoke test covers Apple Silicon.
- PR branches are pushed for review. No application pipelines, store uploads or
  registry deployments are run by this preparation. Production returned the old
  catalogue protocol in the most recent read-only check.

## Validation on 2026-10-21

- Locked, all-feature workspace tests pass. Both normally ignored HTTP/3 host and
  publication contract tests were run separately with OpenSSL 3 and local UDP.
- Strict all-target/all-feature Clippy and nightly formatting pass.
- Warning-denied workspace documentation builds.
- All four changed crates pass the multi-package cargo publish --dry-run --locked
  verification using a temporary registry; no crate was uploaded.
- Real running-Pishoo acceptance covers installed queries, dependency/author
  removal protection, mount/unmount and HTTP forwarding, ACL operations, all four
  listening modes and restoration, curl, proxy, nslookup and discover. See
  [Pishoo command validation](docs/pishoo-validation.md).
- Existing package catalogs, ACL rules, mounts and listening settings were restored.
  SSL and App/Lib files were hash-checked unchanged. Existing background contact
  retry timestamps/counters continued advancing; no contact/message test data
  was created or restored over that background activity.

The online store was still serving the legacy App/Lib protocol during validation.
Its new /store/v1/packages routes returned 403. Store-backed install/update success
and a new-package live uninstall cycle await that rollout; per the user's decision
these are external follow-up checks, not blockers for this CLI commit. The local
HTTP/3 fixture verifies install, unchanged-version handling, identity-conditional
uninstall, post-delete absence and host errors without publishing a real package.

## Before tagging

Run the repository CI on Linux, macOS and Windows, including the 1.94.0 MSRV job
and DEB/RPM/Homebrew artifact checks. Those platform jobs were not replaced by a
local macOS test. Check the new store protocol once its rollout completes.

After CI and review/merge, create annotated tag v0.9.0-preview.5 at the checked
commit. Existing workflows publish crates, Linux DEB/RPM and macOS Homebrew preview
artifacts. The publish workflow orders all changed utility crates before the
launcher and NAT before Doctor. Trusted Publishing remains required for existing crates; first-publication tokens
remain limited to new crates. Public APT verification stays enabled.

This preparation does not push a tag, publish artifacts, deploy the store, replace
the Homebrew-installed CLI, or restart production services for a new host build.
