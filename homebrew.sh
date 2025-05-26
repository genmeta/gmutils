#!/usr/bin/env bash

# 检查必需参数
if [ $# -lt 1 ]; then
    echo "用法: $0 <版本号> [cargo附加参数...]"
    echo "例如: $0 0.2.3"
    exit 1
fi

BINNAME=genmeta
FORMULA=gmutils
VERSION=$1
# 移除版本号，剩余的传给cargo
shift 1
CARGO_ARGS="$@"

ARM_TARGET=aarch64-apple-darwin
ARM_WORKDIR=/tmp/gmutils_${VERSION}_arm64
ARM_ARCHIVE=gmutils_${VERSION}_arm64.tar.gz
ARM_ARCHIVE_PATH=$ARM_WORKDIR/$ARM_ARCHIVE
ARM_ARCHIVES_DIR=$ARM_WORKDIR/archives

echo "正在构建 ARM64 (Apple Silicon) 版本..."
cargo build --release --bin $BINNAME --target $ARM_TARGET $CARGO_ARGS
echo "构建完成，正在打包... 缓存路径: $ARM_WORKDIR"
mkdir -p $ARM_ARCHIVES_DIR
cp target/$ARM_TARGET/release/$BINNAME $ARM_ARCHIVES_DIR
cp genmeta-ssh3.sh                     $ARM_ARCHIVES_DIR 
tar -czvf $ARM_ARCHIVE_PATH -C $ARM_ARCHIVES_DIR .
ARM_ARCHIVE_SHA256=$(shasum -a 256 $ARM_ARCHIVE_PATH | cut -d ' ' -f 1)
echo "ARM64 构建完成，SHA256: $ARM_ARCHIVE_SHA256 $ARM_ARCHIVE_PATH"

AMD_TARGET=x86_64-apple-darwin
AMD_WORKDIR=/tmp/gmutils_${VERSION}_amd64
AMD_ARCHIVE=gmutils_${VERSION}_amd64.tar.gz
AMD_ARCHIVE_PATH=$AMD_WORKDIR/$AMD_ARCHIVE
AMD_ARCHIVES_DIR=$AMD_WORKDIR/archives

echo "正在构建 AMD64 (Intel) 版本..."
cargo build --release --bin $BINNAME --target $AMD_TARGET $CARGO_ARGS
echo "构建完成，正在打包... 缓存路径: $AMD_WORKDIR"
mkdir -p $AMD_ARCHIVES_DIR
cp target/$AMD_TARGET/release/$BINNAME $AMD_ARCHIVES_DIR
cp genmeta-ssh3.sh                     $AMD_ARCHIVES_DIR 
tar -czvf $AMD_ARCHIVE_PATH -C $AMD_ARCHIVES_DIR .
AMD_ARCHIVE_SHA256=$(shasum -a 256 $AMD_ARCHIVE_PATH | cut -d ' ' -f 1)
echo "AMD64 构建完成，SHA256: $AMD_ARCHIVE_SHA256 $AMD_ARCHIVE_PATH"

echo "构建归档位于:"
echo "ARM64: $ARM_ARCHIVE_PATH"
echo "AMD64: $AMD_ARCHIVE_PATH"

echo "上传归档到服务器:"
rsync --rsync-path="sudo rsync" $ARM_ARCHIVE_PATH $AMD_ARCHIVE_PATH ubuntu@download.genmeta.net:/data/wwwroot/homebrew/

# 确保homebrew-genmeta目录存在
if [ ! -d "../homebrew-genmeta" ]; then
    echo "错误: ../homebrew-genmeta 目录不存在"
    echo "请先 git clone git@github.com:genmeta/homebrew-genmeta.git"
    exit 1
fi

echo "生成 Homebrew formula..."
cat>../homebrew-genmeta/gmutils.rb<<EOF
class Gmutils < Formula
  desc "Genmeta Binary Utilities"
  version "${VERSION}"

  on_arm do
    url "https://download.genmeta.net/homebrew/$ARM_ARCHIVE"
    sha256 "$ARM_ARCHIVE_SHA256"
  end
  
  on_intel do
    url "https://download.genmeta.net/homebrew/$AMD_ARCHIVE"
    sha256 "$AMD_ARCHIVE_SHA256"
  end

  def install
    bin.install "genmeta"
    bin.install "genmeta-ssh3.sh"
  end

  test do
    system "#{bin}/genmeta", "--version"
  end
end
EOF

echo "提交变更到 homebrew-genmeta 仓库..."
cd ../homebrew-genmeta/
git add gmutils.rb
git commit -S -m "feat: release gmutils v${VERSION}"
echo "打包完成！请检查并推送仓库更改。"

echo "清理临时文件..."
rm -r $ARM_WORKDIR $AMD_WORKDIR
