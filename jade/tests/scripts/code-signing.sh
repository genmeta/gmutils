#!/bin/sh
set -eu
repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
cd "$repo_root"
CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$repo_root/target/code-signing-tests}"
export CARGO_TARGET_DIR
# Compile the executable under the isolated test trust anchor. Never use this
# build for a production release; no runtime trust bypass is available.
DHTTP_ROOT_CA_PEM="$(cat "$repo_root/genmeta-identity/tests/fixtures/code-signing/root.cert.pem")" cargo test --locked -p jade "$@"
