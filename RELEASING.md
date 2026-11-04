# Release preparation for v0.9.1-preview.1

The release label is **0.9.1.Preview.1**; Cargo versions and the annotated Git tag
use the repository's existing SemVer spelling, **0.9.1-preview.1** and
**v0.9.1-preview.1**. The change baseline is the published `v0.9.0` tag, rather
than the stale preview.5 heading previously in this document. See
[CHANGELOG.md](CHANGELOG.md#091-preview1---2026-11-04) for release notes.

## Versions and publication order

| Package | Previous published version | Prepared version |
| --- | --- | --- |
| genmeta-access | 0.5.0-preview.4 | 0.5.0-preview.5 |
| genmeta-curl | 0.8.0-preview.4 | 0.8.0-preview.5 |
| genmeta-discover | 0.5.0-preview.3 | 0.5.0-preview.4 |
| genmeta-identity | 0.5.0 | 0.5.1-preview.1 |
| genmeta-nat | 0.6.0-preview.3 | 0.6.0-preview.4 |
| genmeta-doctor | 0.5.0-preview.3 | 0.5.0-preview.4 |
| genmeta-nslookup | 0.6.0-preview.3 | 0.6.0-preview.4 |
| genmeta-proxy | 0.5.0-preview.3 | 0.5.0-preview.4 |
| genmeta | 0.9.0 | 0.9.1-preview.1 |
| jade | bundled; outside crates.io workflow | 0.1.0 (unchanged) |

Previous versions were checked against the crates.io API on 2026-11-04. The
identity crate's version advances beyond the published stable 0.5.0; it must not
return to the 0.5.0 preview series. Other utility crates advance their independent
preview series because their packaged sources/tests or workspace dependencies
changed. Workspace version requirements and `Cargo.lock` must agree. The existing
publish workflow already orders dependencies before dependents, including NAT
before Doctor and all utilities before the launcher.

Jade retains its independent crate/executable. DEB and Homebrew bundle `genmeta`
and `jade`, with the distribution version taken from `genmeta/Cargo.toml`.
RPM/Scoop recipes and the crates.io package list retain their existing scope.

## Behavior and compatibility

- `jade create/run/build/publish` separates local development, unsigned builds
  and signing/upload. Build requires no credentials; local run uses ordinary
  credentials; publish prepares developer credentials interactively and signs
  only the reviewed existing build. Already signed packages must verify and are
  uploaded unchanged. Publish never rebuilds sources or changes the local WAZ.
- Explicit `--id dev.alex.chen` selects that actual development child for every
  Jade command. A main name `dev.wang` uses child `dev.dev.wang`. No prefix is
  automatically added to explicit input. Configured/package authors stay exact.
- Both ordinary and developer credentials use the identity's normal `ssl/`
  certificate, key and OCSP staple. Apply requests a new sequence and lets the
  server choose certificate usage from current binding/entitlement. Renew retains
  sequence and usage. Legacy signing files are neither selected nor migrated or
  deleted. Developer renewal is explicit, outside `renew --all`.
- Local dependencies with `path` are built/watched recursively; other dependencies
  install exact versions from the store. App/API routes and `.volume` data use
  normal identity paths. Ctrl+C/SIGTERM removes only code still owned by this run;
  `--fresh` archives data. Unclean termination may leave code to remove manually.
- New official packages use author `dev.genmeta.tech.dhttp.net`; bare installs
  select this author. Explicit legacy `std.dhttp.net` packages remain supported.
  Updates retain their installed author; changing publishers is a separate action.
- The matching Pishoo must support developer package validation, local file
  hosting, `pishoo configure`, unified package APIs and conditional removal.
  Names alone do not grant signing or local execution rights.
- Developer checkout requires the server's authenticated invoice API to return
  an HTTPS public `payment_entry` and to confirm subscription fulfillment.
  Noninteractive/JSON commands do not start setup or purchases. Local tests do
  not establish production checkout/store deployment readiness.

The published DHTTP/DNS/QUIC dependencies remain pinned by `Cargo.lock`. Keep
`DHTTP_ROOT_CA_PEM` as approved PEM **content** at compile time for dhttp 0.7.1;
never substitute a filename or runtime trust setting. Production build outputs
must be separate from the disposable test Root build.

## Local release checks

Run from this repository without sibling Cargo patches. Use the source checkout
for fixture-based tests; the identity crate archive excludes disposable test
private keys, and packaged sources are verified through the publish dry run.

```sh
cargo fmt --all -- --check
cargo test --workspace --all-targets --locked -- --list
cargo test --workspace --exclude jade --locked --all-features --all-targets -- --test-threads=1
jade/tests/scripts/code-signing.sh --all-features --all-targets -- --test-threads=1
cargo clippy --workspace --locked --all-targets --all-features -- -D warnings
cargo fmt --manifest-path xtask/Cargo.toml -- --check
cargo test --manifest-path xtask/Cargo.toml --locked
cargo clippy --manifest-path xtask/Cargo.toml --locked --all-targets -- -D warnings
```

The Jade script compiles its test trust anchor only into
`target/code-signing-tests`. Do not distribute those executables or fixture keys.
CI uses the same isolation for Jade integration tests; ordinary release build
and crate verification keep the production trust configuration.

Run the opt-in Rust API/frontend and local HTTP/3 acceptance checks in
[Jade's reference](jade/REFERENCE.md#output-and-validation). Cross-repository
Pishoo acceptance needs a matching built host; see
[host validation](docs/pishoo-validation.md) for the earlier baseline, not evidence
of this version's production acceptance.

Verify all nine crates together so Cargo can resolve their prepared versions in
its temporary registry, without uploading anything:

```sh
cargo publish --dry-run --locked --allow-dirty \
  -p genmeta-access -p genmeta-curl -p genmeta-discover \
  -p genmeta-identity -p genmeta-nat -p genmeta-doctor \
  -p genmeta-nslookup -p genmeta-proxy -p genmeta
```

## Validation on 2026-11-04

- Workspace and xtask formatting pass. Strict workspace all-target/all-feature
  Clippy and strict xtask Clippy pass; xtask's own locked test command passes.
- The ordinary workspace checks pass 333 tests with 11 opt-in cases skipped;
  isolated Jade checks pass 75 tests with 5 opt-in cases skipped.
- Four Jade opt-in acceptance tests pass separately: local HTTP/3 publication,
  Rust API generation/rebuild, and real web/fullstack template builds. Together
  with ordinary checks, 412 of the 424 inventoried tests were executed and pass;
  the other 12 environment/host-specific cases remain opt-in.
- All nine crates pass the combined locked publish dry run, including compilation
  of packaged sources and resolution of new versions through Cargo's temporary
  registry. Cargo explicitly skips every upload in dry-run mode.
- The before/after workspace inventories contain the same 424 test names. No
  test was renamed, added or removed by this release preparation.
- All nine generated `.crate` archives were inspected and contain no private
  signing-key PEM files. The identity manifest explicitly excludes fixture keys.
- The launcher reports `genmeta 0.9.1-preview.1`; bundled Jade reports `jade 0.1.0`.
  Changed workflow YAML parses successfully, and `git diff --check` passes.

Linux/macOS/Windows CI, MSRV 1.94.0 and DEB/RPM/Homebrew artifact checks remain
required before tagging; local macOS verification does not replace those jobs.

## Release handoff

1. Review the version/notes diff and pass the local checks above.
2. Push the reviewed branch through repository CI and verify the matching Pishoo,
   store and developer checkout contracts. Check both executables in DEB/Homebrew.
3. After review/merge and passing CI, create an annotated `v0.9.1-preview.1` tag at
   the checked commit, using this changelog entry as its annotation, then push it
   when publication is authorized.
4. Tag-triggered workflows publish crates in the order above and preview
   distribution artifacts. Existing crates use Trusted Publishing; first-release
   tokens remain restricted to new crates. Keep public APT verification enabled.

This document records preparation. Creating/pushing the release tag and uploading
or publishing artifacts are separate release actions.
