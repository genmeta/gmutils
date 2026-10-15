# Release preparation for v0.9.0-preview.2

| Package | Previous published version | Prepared version |
| --- | --- | --- |
| `genmeta` | 0.9.0-preview.1 | 0.9.0-preview.2 |
| `genmeta-access` | 0.5.0-preview.1 | 0.5.0-preview.2 |
| `genmeta-curl` | 0.8.0-preview.1 | 0.8.0-preview.2 |
| `genmeta-discover` | 0.5.0-preview.1 | 0.5.0-preview.2 |
| `genmeta-doctor` | 0.5.0-preview.1 | 0.5.0-preview.2 |
| `genmeta-identity` | 0.5.0-preview.1 | 0.5.0-preview.2 |
| `genmeta-nat` | 0.6.0-preview.1 | 0.6.0-preview.2 |
| `genmeta-nslookup` | 0.6.0-preview.1 | 0.6.0-preview.2 |
| `genmeta-proxy` | 0.5.0-preview.1 | 0.5.0-preview.2 |

## Dependency order

Release prerequisites are [dhttp PR #34](https://github.com/genmeta/dhttp/pull/34)
(dhttp-home 0.6.1, then dhttp 0.7.1) and
[daccess PR #3](https://github.com/genmeta/daccess/pull/3) (daccess 0.1.1).
Both releases must be available on crates.io before final registry checks.
The manifests require these versions with Cargo's compatible-version requirements.
Existing dyns 0.8.0, h3x 0.7.0 and QUIC versions remain in their current series;
the TLS backend remains qrustls 0.23.45. No sibling path or Git patches are shipped.

## Validation and lockfiles

The required dhttp 0.7.1, dhttp-home 0.6.1 and daccess 0.1.1 releases are
available on crates.io. The committed Cargo.lock now resolves those registry
versions with checksums and no local overrides. Registry checks run from a
checkout outside ancestor Cargo path patches.

Run locked Rust CI, documentation, MSRV and crate/DEB/RPM/Homebrew dry runs
before tagging. Merge using rebase and tag only the checked commit.
Local integration lockfiles must never replace the registry release lockfile.

## Publication

Planned tag: `v0.9.0-preview.2`. Release through the repository's GitHub Actions workflow.
Use an annotated tag with the changelog entry as its release notes. Actual
publication and production deployment remain separate from this preparation PR.

Publish dhttp-home 0.6.1, dhttp 0.7.1 and daccess 0.1.1 first, then the updated
command crates, and genmeta last. dyns 0.8.0 is already published. Command crates depend directly on these upstream libraries.
Refresh the registry lockfile after upstream publication before running
release checks; local integration overrides are not a release lockfile.

## Tag-triggered artifacts

Pushing `v0.9.0-preview.2` to this repository triggers release.yml for DEB, RPM and Homebrew.
The tag must match the main package version. Packaging creates a draft GitHub
Release, uploads artifacts, and publishes that Release after all package jobs
succeed. Release builds keep `--locked`; refresh the registry lockfile after
upstream publication before tagging. The existing S3, signing and tap/bucket
credentials must be configured in repository Actions settings.

Windows/Scoop publication is deferred for this release. The existing Scoop
script, template and destinations are retained for a later release, but no
Windows job runs when the v0.9.0-preview.2 tag is pushed.

All workspace command crates use `-preview.2` prereleases. DEB/RPM and Homebrew
publication selects the preview channel from the main package version.

## History and validation

The original development commits are retained as individual commits. The release
commit updates versions and dependencies; temporary task plans and implementation
reports are excluded from the release tree. Required registry checks and
publication ordering above still apply.

## Preparation checks (2026-10-15)

- Workspace tests: 285 passed; the opt-in local HTTP/3 publish test also passed.
- Strict all-target/all-feature Clippy and nightly formatting passed.
- Actual package/remove help exposes the unified commands and --type option.

The preparation checks above used fixed upstream PR sources. Final checks use
published crates through the refreshed registry lockfile. Their CI results must
pass before merging and tagging.

Publication uses the repository CARGO_REGISTRY_TOKEN when configured. Without
that secret, existing crates use Trusted Publishing; first publication requires
an API token.
