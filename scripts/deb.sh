#!/usr/bin/env bash

# 定义目标架构数组
TARGETS=(
    "x86_64-unknown-linux-gnu"
    "i686-unknown-linux-musl"
    "aarch64-unknown-linux-musl"
    "armv7-unknown-linux-musleabihf"
)

# 遍历每个目标架构并执行构建和打包
for TARGET in "${TARGETS[@]}"; do
    cargo zigbuild --target "$TARGET" --release --bin genmeta
    cargo deb --target "$TARGET" --no-build
done

echo "All builds completed successfully!"