# Pishoo command validation

Validated on macOS, 2026-10-21, for genmeta 0.9.0-preview.4 against the running
current Pishoo host. The previous Homebrew CLI is a separate executable; acceptance
used the newly built binary.

| Command family | Running-host acceptance |
| --- | --- |
| install --list / --info | Installed array, short/full package identities, all installed package details, missing details and author mismatch |
| install / update | Invalid local/URL/version input and missing-update rejection; exact installed-version requests reach the trusted store and report its 403 |
| uninstall | Missing package, mismatched author and dependency-protected removal fail without changing the installed catalog |
| mount | Query, add, update, real loopback HTTP forwarding, explicit upstream path, exact location, reserved path and nonlocal-upstream rejection |
| unmount | Both match values encoded, upstream-changed rejection, noninteractive confirmation, exact removal and idempotent removal |
| access | List/wide/method filter/root read, allow/deny/review, group grantee, exact grantee removal, clear/method filtering, --all and multiple-path removal |
| listen | Query and internal/external/all/off, confirmation refusal, local recovery from off, preserved mounts and unaffected peer identity |
| curl | Authenticated/anonymous calls, App GET/HEAD, verified visitor/no-store headers, redirects and output files |
| proxy | Temporary HTTP proxy forwards a real App request over DHTTP/3 |
| nslookup / discover | Resolve and discover the real identity's mDNS advertisement |
| Removed syntax | server, forward, unlisten and listen auto/loopback/list are rejected |

The opt-in runner is [genmeta/tests/pishoo_live.py](../genmeta/tests/pishoo_live.py).
It uses a unique mount/ACL prefix and a temporary loopback upstream. Its finally
block restores listening first, removes its own rules and mounts, and checks the
original package catalog, ACL rules, mounts and listen mode. Readiness probes may
fail transiently while the host applies a listen change; they are not successful
checks. The completed run recorded 92 passed checks and restored all temporary
resources. No existing package was removed and no business messages or contacts
were created.

```sh
cargo build --locked -p genmeta
GENMETA_TEST_BINARY="$PWD/target/debug/genmeta" python3 genmeta/tests/pishoo_live.py \
  --id YOUR_TEST_ID --peer ANOTHER_TEST_ID --output /tmp/pishoo-live.json
```

Use dedicated test identities with a running reachable Pishoo. The runner cycles
one identity's listening modes briefly; the peer remains enabled. When the store
is being rolled out separately, --allow-store-pending records failed exact-version
store resolution as an external pending check. It never relabels an unsuccessful
install as a pass. The current live check cannot demonstrate installing a new
package or restoring one after a successful uninstall until the unified store
protocol is available.

Local tests additionally cover exact store release resolution, CLI syntax, signing
and packaging, authenticated HTTP/3 installation and errors, unchanged-version
checks, full-ID conditional uninstall and post-delete absence, plus publication
retry/recovery through a loopback fixture. They do not publish packages to the
online store. The real HTTP/3 tests own global trust roots and run separately:

```sh
cargo test --locked --workspace --all-features --all-targets -- --test-threads=1
cargo test --locked -p genmeta install::tests::host_api_commands_authenticate_and_preserve_methods_bodies_and_errors -- --ignored --exact
cargo test --locked -p genmeta upload::tests::real_http3_publish_retry_dependencies_and_read_only_recovery -- --ignored --exact
```

The two explicit HTTP/3 tests require OpenSSL 3 on PATH and permission to bind
local UDP sockets. Release validation also includes formatting, strict Clippy,
warning-denied documentation and a four-crate publish dry run. Platform/MSRV and
Linux/Homebrew artifact validation remain CI gates before tagging.
