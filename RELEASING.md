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
ACL APIs. Package creation, build and publication use the separate Jade executable
(`jade create/build/publish`); `genmeta` provides install/update/uninstall and
installed queries via install --list/--info. Signed source files use .waz. No
legacy App/Lib package flags, package/server grouping, forward or unlisten aliases
are restored. App entry URLs use /app/NAME/.

Listen edits .volume/sys/setting/database locally, including when the identity is
off. It accepts internal/external/all/off, and off retains mounts. Mount/unmount
use the authenticated running Pishoo /std/sys/mount API. Unmount matches both
location and proxy_pass; off and unmount require confirmation or --yes.

Package installation and upgrades do not install Workspace. After interactive
identity application with the server enabled, the CLI asks whether to install
Workspace, defaulting to yes on Enter. Confirmation precedes Pishoo reload, the
readiness check and `genmeta install workspace --id NAME`. Installation uses the
same identity home, including global applications. Disabled servers,
non-interactive runs and declined or cancelled prompts skip reload and
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
patches. The access CLI's test-only daccess dependency is pinned to the same
revision as Pishoo so its contract tests exercise the current HTTP routes.

## Jade project

Jade lives in `jade/` with its own manifest, executable, README, fixtures and tests.
Build and test it with `cargo build -p jade --locked` and
`cargo test -p jade --locked`. Install from this checkout with
`cargo install --path jade --locked`. Workspace CI includes Jade; the existing
gmutils distribution recipes and explicit crates.io publication list continue
to release the Genmeta utilities. Jade can be built and installed independently.

Jade implements the `create/build/publish` workflow described in the
[implementation plan](jade/IMPLEMENTATION_PLAN.md): `jade.toml`, native frontend
builds, Rust HTTP API templates with built-in Cargo invocation, local content and
signature checks, and human/JSON result reporting. Publish uses the signed
package's author; package output defaults to `.jade/`. Runtime templates and local
HTTP/3 publication have dedicated acceptance checks; platform CI remains a release
gate.

### Application pipelines

The six independent repositories in `pishoo-projects` use
[jade-app.yml](.github/workflows/jade-app.yml). Their callers pin both the reusable
workflow and `jade-ref` to the same full gmutils commit. Push that commit before
pushing the application callers. The workflow builds Jade from that revision,
uses Rust 1.97.1, Bun 1.4.3, Node 24 and the checksum-verified WASI SDK 33, runs the
application's existing tests, then executes `jade build`. Branches, pull requests
and manual branch runs use an isolated self-signed test identity and cannot
publish. A `vVERSION` annotated tag must match `jade.toml` and native manifests.

Before pushing release tags, create a `release` GitHub environment in each
application repository, restrict it to approved version tags and require a
reviewer. Store `DHTTP_AUTHOR_CERT` (PEM certificate chain) and `DHTTP_AUTHOR_KEY`
(PEM private key) as environment secrets for the manifest's exact author.
`DHTTP_AUTHOR_OCSP` is optional base64 DER; DHTTP refreshes missing or expired
responses. The standard applications use `std.dhttp.net`; Journal uses
`alice.smith.dhttp.net`. The workflow never reads a developer's identity directory.
Public network configuration can be supplied as repository variables
`DHTTP_ROOT_CA_PEM`, `DHTTP_BOOTSTRAP_URL`, `DHTTP_NAME_SERVICE`,
`DHTTP_MDNS_SERVICE_DOMAIN` and `DHTTP_CA_SERVICE`; unset values use the DHTTP
dependency's defaults. The test `ci` environment must contain no signing secrets.

The signed `.waz`, build result, SHA256SUMS and provenance are uploaded as workflow
artifacts before publication. Jade sends those exact bytes once and verifies the
saved version. `publish.json` is retained even on failure. On
`E_PUBLISH_OUTCOME_UNKNOWN`, recover that artifact and retry the same package after
checking the receipt; do not automatically rebuild or retry an upload.

Release order: deploy the registry's existing `author`/`.waz` implementation first;
then Profile 0.3.0 and Message 0.2.1; then Introduction 0.1.0; then Workspace 0.3.2.
Calendar 0.1.2 and Journal 0.1.2 can follow independently. The 2026-10-23 read-only
production probe still returned `publisher` and `.pkg`; Jade now rejects that
catalogue before sending any upload. No registry deployment or data migration is
part of these application changes. Each application's `RELEASING.md` records its
tag and exact dependencies.

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

After CI and review/merge, create annotated tag v0.9.0-preview.4 at the checked
commit. Existing workflows publish crates, Linux DEB/RPM and macOS Homebrew preview
artifacts. The publish workflow orders access/curl/identity before the launcher.
Trusted Publishing remains required for existing crates; first-publication tokens
remain limited to new crates. Public APT verification stays enabled.

This preparation does not push a tag, publish artifacts, deploy the store, replace
the Homebrew-installed CLI, or restart production services for a new host build.
