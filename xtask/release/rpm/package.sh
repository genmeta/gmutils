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

rpm_arch() {
    case "$1" in
        x86_64-unknown-linux-gnu) echo x86_64 ;;
        aarch64-unknown-linux-gnu) echo aarch64 ;;
        armv7-unknown-linux-gnueabihf) echo armv7hl ;;
        i686-unknown-linux-gnu) echo i686 ;;
        *) echo "unsupported rpm target $1" >&2; exit 1 ;;
    esac
}

write_aarch64_zig_workaround() {
    if [ "${XTASK_RELEASE_TARGET:?}" != "aarch64-unknown-linux-gnu" ]; then
        return
    fi
    cat > /tmp/gmutils-aarch64-zig <<'SH'
#!/usr/bin/env bash
set -euo pipefail
if [ "${1:-}" = "cc" ] || [ "${1:-}" = "c++" ]; then
    zig_subcommand="$1"
    shift
    filtered_args=()
    for arg in "$@"; do
        case "$arg" in
            -Wl,--fix-cortex-a53-843419|--fix-cortex-a53-843419) continue ;;
        esac
        filtered_args+=("$arg")
    done
    exec /usr/local/zig/zig "$zig_subcommand" "${filtered_args[@]}"
fi
exec /usr/local/zig/zig "$@"
SH
    chmod +x /tmp/gmutils-aarch64-zig
    export CARGO_ZIGBUILD_ZIG_PATH=/tmp/gmutils-aarch64-zig
    export RUSTFLAGS="${RUSTFLAGS:-} -Z unstable-options -Clinker-flavor=gnu-lld-cc"
}

split_package_version() {
    local package_version=${XTASK_RELEASE_PACKAGE_VERSION:?}
    if [ "$package_version" = "${package_version%-*}" ]; then
        echo "rpm package version must include release suffix: $package_version" >&2
        exit 1
    fi
    RPM_VERSION=${package_version%-*}
    RPM_RELEASE=${package_version##*-}
}

write_spec() {
    cat > "$1" <<EOF_SPEC
Name:           gmutils
Version:        ${RPM_VERSION}
Release:        ${RPM_RELEASE}
Summary:        Genmeta binary utilities
License:        Apache-2.0
URL:            https://www.dhttp.net
Vendor:         Genmeta Tech Limited
Source0:        genmeta
Source1:        genmeta-ssh.sh
AutoReqProv:    no
Requires:       glibc

%description
Genmeta command-line tools for DHTTP/3, DShell, DNS, and identity management.

%prep
# nothing to do: binary already built by cargo-zigbuild

%build
# nothing to do: binary already built by cargo-zigbuild

%install
rm -rf %{buildroot}
install -D -m 0755 %{SOURCE0} %{buildroot}/usr/bin/genmeta
install -D -m 0755 %{SOURCE1} %{buildroot}/usr/bin/genmeta-ssh.sh

%files
/usr/bin/genmeta
/usr/bin/genmeta-ssh.sh

%changelog
* %(date '+%a %b %d %Y') Genmeta Tech Limited <developer@genmeta.net> - ${RPM_VERSION}-${RPM_RELEASE}
- release ${XTASK_RELEASE_SOURCE_VERSION:?}
EOF_SPEC
}

if [ "${XTASK_RELEASE_PACKAGE_ID:?}" != "gmutils" ]; then
    echo "gmutils rpm script received unexpected package ${XTASK_RELEASE_PACKAGE_ID}" >&2
    exit 1
fi

cd "${XTASK_RELEASE_REPO_ROOT:?}"
target=${XTASK_RELEASE_TARGET:?}
arch=$(rpm_arch "$target")
profile=${XTASK_RELEASE_PROFILE:?}
profile_args=
if [ "$profile" = "release" ]; then
    profile_args=--release
fi
split_package_version

src="${XTASK_RELEASE_OUT_DIR:?}/src"
product_source="$src/product-source"
prepare_product_source "$product_source"

export HOME=/tmp
export RUSTUP_HOME=/opt/rustup
export CARGO_HOME=/opt/cargo
export PATH=/opt/cargo/bin:/usr/local/zig:$PATH
export RUSTFLAGS="${RUSTFLAGS:-}"
write_aarch64_zig_workaround

cd "$product_source"
cargo zigbuild $profile_args --manifest-path genmeta/Cargo.toml --target "$target.2.28" --bin genmeta

release_dir="$product_source/target/$target/$profile"
topdir="${XTASK_RELEASE_OUT_DIR:?}/rpmbuild"
rm -rf "$topdir"/{SPECS,BUILD,BUILDROOT,SOURCES,SRPMS,RPMS}
mkdir -p "$topdir"/{SPECS,BUILD,BUILDROOT,SOURCES,SRPMS,RPMS}

spec="$topdir/SPECS/gmutils.spec"
write_spec "$spec"
cp "$release_dir/genmeta" "$topdir/SOURCES/genmeta"
cp "$product_source/genmeta-ssh.sh" "$topdir/SOURCES/genmeta-ssh.sh"

rpmbuild -bb \
    --target="$arch" \
    --define "_topdir $topdir" \
    --define "_binary_payload w19.xzdio" \
    "$spec"

find "$topdir/RPMS" -name '*.rpm' -exec mv {} "${XTASK_RELEASE_OUT_DIR:?}/" \;
