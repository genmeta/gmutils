# Release preparation for v0.9.0

| Package | Previous version | Prepared version |
| --- | --- | --- |
| genmeta | 0.9.0-preview.5 | 0.9.0 |
| genmeta-identity | 0.5.0-preview.5 | 0.5.0 |
| jade | 0.1.0 | 0.1.0, bundled executable |

Other utility crates keep their published versions. The existing publish workflow
publishes genmeta-identity before genmeta and skips versions already on crates.io.
Jade stays outside that workflow's crate list and ships in the gmutils bundles.

## Scope

The release/0.9.0 branch includes the configuration fixes through f8a9c515.
Listen and identity activation delegate settings to matching Pishoo 0.9.0.
Valid settings are preserved; legacy settings are handled by the host. A service
configuration failure leaves the identity installed and prints recovery guidance.

Developer certificate management and the new package signing policy remain on
feat/developer-certificates. Jade keeps the existing TLS identity signing flow;
standard authors remain std.dhttp.net and Journal remains alice.smith.dhttp.net.
No registry migration or application author migration is needed for this release.

## Validation before tagging

Run from this checkout with the locked dependencies:

```sh
cargo +nightly fmt --all -- --check
cargo test --workspace --locked --all-features --all-targets -- --test-threads=1
cargo +nightly clippy --workspace --locked --all-targets --all-features -- -D warnings
cargo publish --dry-run --locked -p genmeta-identity -p genmeta
```

Run the ignored configuration tests with PISHOO_BIN set to the matching candidate
host. Coverage CI builds a fixed Pishoo release commit and includes these tests.
CI also covers platform builds and Jade acceptance. Verify DEB/RPM/Homebrew
artifacts and the formal release configuration before tagging; a local macOS run
does not replace those checks.

After review, CI and packaging checks, create the annotated v0.9.0 tag at the
verified commit. The existing workflows publish the changed crates and stable
channel packages. Preparing this branch does not create a tag or publish artifacts.

## Application packages

Use the Jade executable built from this release branch. Existing Profile 0.3.0,
Message 0.2.1, Introduction 0.1.1, Calendar 0.1.2, Journal 0.1.2 and Medical 0.1.0
remain published independently. Workspace 0.3.5 retains Introduction 0.1.1,
Profile 0.3.0 and Message 0.2.1 as exact dependencies.

Build new application versions locally with jade build, then review the author,
version, dependencies and complete WAZ digest before publishing. Preserve the
same signed file when recovering an uncertain upload; never overwrite an existing
version with different bytes.
