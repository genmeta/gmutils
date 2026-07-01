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

if [ "${XTASK_RELEASE_PACKAGE_ID:?}" != "gmutils" ]; then
    echo "gmutils deb script received unexpected package ${XTASK_RELEASE_PACKAGE_ID}" >&2
    exit 1
fi

case "${XTASK_RELEASE_TARGET:?}" in
    x86_64-unknown-linux-gnu) deb=amd64; gnu=x86_64-linux-gnu ;;
    aarch64-unknown-linux-gnu) deb=arm64; gnu=aarch64-linux-gnu ;;
    armv7-unknown-linux-gnueabihf) deb=armhf; gnu=arm-linux-gnueabihf ;;
    i686-unknown-linux-gnu) deb=i386; gnu=i386-linux-gnu ;;
    *) echo "unsupported deb target ${XTASK_RELEASE_TARGET}" >&2; exit 1 ;;
esac

cd "${XTASK_RELEASE_REPO_ROOT:?}"
profile=${XTASK_RELEASE_PROFILE:?}
profile_args=
if [ "$profile" = "release" ]; then
    profile_args=--release
fi

src="${XTASK_RELEASE_OUT_DIR:?}/src"
rm -rf "$src"
mkdir -p "$src/debian"
cp -r xtask/deb/. "$src/debian/"
printf 'gmutils (%s) unstable; urgency=low\n\n  * release %s\n\n -- Genmeta Tech Limited <developer@genmeta.net>  %s\n' \
    "${XTASK_RELEASE_PACKAGE_VERSION:?}" "${XTASK_RELEASE_SOURCE_VERSION:?}" "$(date -R)" > "$src/debian/changelog"
product_source="$src/product-source"
prepare_product_source "$product_source"

export HOME=/tmp
export RUSTUP_HOME=/opt/rustup
export CARGO_HOME=/opt/cargo
export PATH=/opt/cargo/bin:/usr/local/zig:$PATH
export TRIPLE=${XTASK_RELEASE_TARGET}
export ZIG_TARGET=${XTASK_RELEASE_TARGET}.2.28
export BUILD_PROFILE=$profile
export CARGO_PROFILE_ARGS=$profile_args
export DEB_HOST_MULTIARCH=$gnu
export SOURCE_ROOT=$product_source

cd "$src"
dpkg-buildpackage -B -uc -us -d -a"$deb"
