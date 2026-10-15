# Release preparation for v0.9.0-preview.3

| Package | Published version | Prepared version |
| --- | --- | --- |
| genmeta | 0.9.0-preview.2 | 0.9.0-preview.3 |
| genmeta-identity | 0.5.0-preview.2 | 0.5.0-preview.3 |
| Other workspace command crates | current preview.2 versions | unchanged |

## Scope and compatibility

Require explicit server activation during identity apply, preserve enabled/listen
semantics, and provide the management/package commands removed from Pishoo.
Identity activation and listening edit the local config.db so disabled services
can be restored. Proxy and package operations use authenticated host APIs.

Use Pishoo v0.9.0-preview.3 for the complete opt-in lifecycle and mDNS cleanup.
System service start/stop/restart/status remain systemctl/Homebrew operations.
Package builds and publication validate through the publisher identity's running
Pishoo API; genmeta no longer launches pishoo-pack or pishoo app/lib check.

## Validation

Run nightly formatting, commitlint, strict Clippy, locked workspace tests,
documentation, MSRV and crate/DEB/RPM/Homebrew dry runs before tagging. The registry
lockfile uses published dependencies without sibling Cargo patches. Run Cargo
with --manifest-path from outside ancestor local overrides while keeping sources
in the current checkout.

Regressions cover browser-only application, enabled/listen compatibility, literal
build arguments, input-file protection, authenticated HTTP/3 upload and host errors.
Publish genmeta-identity 0.5.0-preview.3 before genmeta 0.9.0-preview.3. The existing
workflow skips unchanged crate versions already present on crates.io.

## Publication

After successful CI and rebase merge, create annotated tag v0.9.0-preview.3 at the
checked commit. Existing workflows publish crates, Linux DEB/RPM and macOS Homebrew
preview artifacts. Trusted Publishing remains required for existing crates; API
tokens remain limited to first publication. Public APT verification remains enabled.

Windows/Scoop release artifacts remain deferred. This preparation does not create
a tag, publish artifacts or deploy/restart production services.

## Preparation results (2026-10-15)

- Locked workspace tests and nightly formatting passed.
- Strict nightly Clippy passed for all targets/features with warnings denied.
- genmeta-identity and genmeta passed cargo publish --dry-run --locked, including
  package verification against the temporary registry. No crates were uploaded.
- Conventional Commits checks passed locally; platform/artifact checks remain CI gates.
