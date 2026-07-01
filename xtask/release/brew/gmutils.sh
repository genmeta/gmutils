#!/usr/bin/env bash
set -euo pipefail

prepare_product_source() {
    local dest=$1
    rm -rf "$dest"
    mkdir -p "$dest"
    tar -C "${XTASK_RELEASE_REPO_ROOT:?}" \
        --exclude='./.git' \
        --exclude='./target' \
        --exclude='./xtask' \
        -cf - . | tar -C "$dest" -xf -
    python3 - "$dest/Cargo.toml" <<'PY'
from pathlib import Path
import sys
path = Path(sys.argv[1])
text = path.read_text()
text = text.replace('    "xtask",\n', '')
path.write_text(text)
PY
}

cd "${XTASK_RELEASE_REPO_ROOT:?}"
target=${XTASK_RELEASE_TARGET:?}
out=${XTASK_RELEASE_OUT_DIR:?}
version=${XTASK_RELEASE_SOURCE_VERSION:?}
rm -rf "$out/staging"
mkdir -p "$out/staging"
product_source="$out/product-source"
prepare_product_source "$product_source"
cargo build --release --manifest-path "$product_source/genmeta/Cargo.toml" --target "$target" --bin genmeta
cp "$product_source/target/$target/release/genmeta" "$out/staging/genmeta"
cp genmeta-ssh.sh "$out/staging/genmeta-ssh.sh"
tar -C "$out/staging" -czf "$out/gmutils-$version-$target.tar.gz" .
rm -rf "$out/staging"
