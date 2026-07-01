FROM fedora:40

ARG XTASK_RELEASE_TARGET
ENV CARGO_HOME=/opt/cargo \
    RUSTUP_HOME=/opt/rustup \
    PATH=/opt/cargo/bin:/usr/local/zig:$PATH

RUN set -eux; \
    dnf install -y --setopt=install_weak_deps=False \
        rpm-build rpmdevtools systemd-rpm-macros \
        gcc make pkgconf-pkg-config \
        ca-certificates curl wget tar xz which util-linux \
        clang; \
    dnf clean all

RUN set -eux; \
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
        sh -s -- --default-toolchain nightly --profile minimal -y; \
    rustup target add "$XTASK_RELEASE_TARGET"; \
    wget -q https://ziglang.org/download/0.14.0/zig-linux-x86_64-0.14.0.tar.xz; \
    tar -xf zig-linux-x86_64-0.14.0.tar.xz; \
    mv zig-linux-x86_64-0.14.0 /usr/local/zig; \
    ln -s /usr/local/zig/zig /usr/local/bin/zig; \
    rm zig-linux-x86_64-0.14.0.tar.xz; \
    cargo install cargo-zigbuild; \
    chmod -R a+rX /opt/cargo /opt/rustup

COPY xtask/release/rpm/package.sh /opt/genmeta-release/package
RUN chmod +x /opt/genmeta-release/package
