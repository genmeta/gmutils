#!/usr/bin/env bash
# Run Cargo without inheriting patches from the parent development workspace.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
toolchain=""
if [[ "${1:-}" == +* ]]; then
    toolchain="$1"
    shift
fi
if [[ $# -eq 0 ]]; then
    echo "Usage: $0 [+toolchain] <cargo-command> [arguments...]" >&2
    exit 2
fi
command_name="$1"
shift

build_cwd="$(mktemp -d "${TMPDIR:-/tmp}/gmutils-cargo.XXXXXX")"
trap 'rm -d "$build_cwd"' EXIT
cd "$build_cwd"
cargo_args=("$command_name" --manifest-path "$repo_root/Cargo.toml" \
    --config "$repo_root/.cargo/config.toml" "$@")
if [[ -n "$toolchain" ]]; then
    cargo "$toolchain" "${cargo_args[@]}"
else
    cargo "${cargo_args[@]}"
fi
