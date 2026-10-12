# Release preparation for v0.9.0-preview.1

| Package | Previous published version | Prepared version |
| --- | --- | --- |
| `genmeta` | 0.8.2 | 0.9.0-preview.1 |
| `genmeta-access` | 0.4.2 | 0.5.0-preview.1 |
| `genmeta-curl` | 0.7.1 | 0.8.0-preview.1 |
| `genmeta-discover` | 0.4.2 | 0.5.0-preview.1 |
| `genmeta-doctor` | 0.4.1 | 0.5.0-preview.1 |
| `genmeta-identity` | 0.4.2 | 0.5.0-preview.1 |
| `genmeta-nat` | 0.5.1 | 0.6.0-preview.1 |
| `genmeta-nslookup` | 0.5.1 | 0.6.0-preview.1 |
| `genmeta-proxy` | 0.4.1 | 0.5.0-preview.1 |

## Dependency order

dquic → h3x → dhttp → ddns → daccess

Manifest versions use Cargo's compatible-version requirements, without `=`.
They allow patch updates within the selected 0.x series. External Genmeta
dependencies come from crates.io; no sibling checkout or Git patch is required.
The dquic TLS backend is the published qrustls 0.23.45 package, used as `rustls`
where the application exchanges TLS types with qtls.

## Validation and lockfiles

This PR is release preparation. Unpublished upstream versions can make CI fail;
such failures do not confirm compilation, tests or package verification.
For tracked lockfiles, run `cargo generate-lockfile` after upstream publication,
review and commit the resulting registry lockfile before tagging.
Run Cargo from a checkout outside directories containing ancestor path patches.
Never commit a lockfile generated with local transport path overrides as the
registry release lockfile. Re-run the normal CI checks and publish dry run after
upstream publication and lockfile refresh; merge and tag only that checked commit.

## Publication

Planned tag: `v0.9.0-preview.1`. Release through the repository's GitHub Actions workflow.
Use an annotated tag with the changelog entry as its release notes. Actual
publication and production deployment remain separate from this preparation PR.

Publish the updated dhttp-home, DHTTP and dyns APIs first, then command crates,
and genmeta last. Command crates depend directly on these upstream libraries.
Refresh the registry lockfile after upstream publication before running
release checks; local integration overrides are not a release lockfile.

## Tag-triggered artifacts

Pushing `v0.9.0-preview.1` to this repository triggers release.yml for DEB, RPM and Homebrew.
The tag must match the main package version. Packaging creates a draft GitHub
Release, uploads artifacts, and publishes that Release after all package jobs
succeed. Release builds keep `--locked`; refresh the registry lockfile after
upstream publication before tagging. The existing S3, signing and tap/bucket
credentials must be configured in repository Actions settings.

Windows/Scoop publication is deferred for this release. The existing Scoop
script, template and destinations are retained for a later release, but no
Windows job runs when the v0.9.0-preview.1 tag is pushed.

All workspace command crates use `-preview.1` prereleases. DEB/RPM and Homebrew
publication selects the preview channel from the main package version.
