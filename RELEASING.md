# Release preparation for v0.9.0-preview.4

| Package | Published version | Prepared version |
| --- | --- | --- |
| genmeta | 0.9.0-preview.3 | 0.9.0-preview.4 |
| genmeta-access | 0.5.0-preview.2 | 0.5.0-preview.3 |
| genmeta-curl | 0.8.0-preview.2 | 0.8.0-preview.3 |
| genmeta-identity | 0.5.0-preview.3 | 0.5.0-preview.4 |
| Other workspace command crates | current versions | unchanged |

The previous launcher, access and identity versions are already published. Keep
these new versions and workspace dependency requirements together; the publish
workflow deliberately skips versions already on crates.io.

## Scope and compatibility

This release targets the current Pishoo unified Pkg, listen/mount and query-based
ACL APIs. Package commands are top-level build/publish/install/update/uninstall;
installed queries use install --list/--info. Signed source files use .pkg. No
legacy App/Lib package flags, package/server grouping, forward or unlisten aliases
are restored. App entry URLs use /app/NAME/.

Listen edits .volume/sys/setting/database locally, including when the identity is
off. It accepts internal/external/all/off, and off retains mounts. Mount/unmount
use the authenticated running Pishoo /std/sys/mount API. Unmount matches both
location and proxy_pass; off and unmount require confirmation or --yes.

Homebrew post_install, DEB configure and RPM posttrans attempt
`genmeta install workspace` once using the installation user's default identity.
The shared hook runs as the invoking user for sudo installs and otherwise uses
the current account. Missing default identity, an unreachable host or a failed
request prints the manual command and does not fail gmutils installation.
There is no background retry or pending-install state. Cargo has no install hook.
This supersedes the previous manual-only default Workspace installation policy.

Identity activation creates only explicit listening configuration. It no longer
creates a default welcome site. Certificate logging preserves history when moving
an existing real logs directory into log. Curl header write-out tokens consume
both closing braces, including Pishoo-Viewer-Name on App HEAD responses.

Runtime dependencies use published registry releases without sibling Cargo
patches. The access CLI's test-only daccess dependency is pinned to the same
revision as Pishoo so its contract tests exercise the current HTTP routes.

## Validation on 2026-10-21

- Locked, all-feature workspace tests pass. Both normally ignored HTTP/3 host and
  publication contract tests were run separately with OpenSSL 3 and local UDP.
- Installer-hook tests cover direct users, sudo delegation, missing prerequisites,
  command failures and nonfatal completion without retries.
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

After CI and review/merge, create annotated tag v0.9.0-preview.4 at the checked
commit. Existing workflows publish crates, Linux DEB/RPM and macOS Homebrew preview
artifacts. The publish workflow orders access/curl/identity before the launcher.
Trusted Publishing remains required for existing crates; first-publication tokens
remain limited to new crates. Public APT verification stays enabled.

This preparation does not push a tag, publish artifacts, deploy the store, replace
the Homebrew-installed CLI, or restart production services for a new host build.
