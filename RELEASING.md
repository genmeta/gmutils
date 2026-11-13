# gmutils 0.9.1 发布准备

正式标签为 v0.9.1，分发包版本来自 genmeta/Cargo.toml。Jade 独立版本为 0.1.1，继续随 DEB/Homebrew 分发；不新增 Jade 的 crates.io 发布任务。变更说明见 CHANGELOG.md；历史 preview.1 已发布。

## 组件与发布顺序

各工具保留独立版本：genmeta-access 0.5.0、genmeta-curl 0.8.0、genmeta-discover 0.5.0、genmeta-identity 0.5.1、genmeta-nat 0.6.0、genmeta-doctor 0.5.0、genmeta-nslookup 0.6.0、genmeta-proxy 0.5.0、genmeta 0.9.1。workspace dependencies 与 Cargo.lock 一起同步，依赖先于使用方发布。2026-11-06 查询时这些正式版本尚未占用，实际上传前仍须复核。

新建 API/fullstack 项目的 Rust 源码目录为 `wasm/`；继续识别已有 `api/`、`lib/` 工程，前端 api 模块不变。

## 当前契约

Jade create 默认不写作者；build/run 使用 package.author，缺省时取已配置默认身份的开发子名字，未配置则报错。所有 Jade 命令均无 --id。build 只生成未签名快照，无需凭据；run 使用普通身份凭据运行本地代码；publish 按已有 WAZ 作者选择统一 ssl 凭据，签名并持久保存后上传，不重建源码。

包自身 author 保留，新 dependencies 仅有 name、精确 version 和可选本地 path，path 不写入 WAZ。历史签名包中的作者继续精确核对。包名由首个成功作者占用；同版本任何重传均返回冲突。发生结果不确定的上传只核对精确原包，不换字节重签同版本。

官方作者精确为 dev.genmeta.tech.dhttp.net。genmeta install NAME 沿用已安装作者；首次安装按精确包名寻找唯一作者，歧义时要求显式 AUTHOR/NAME，不固定补官方作者。安装要求 Pishoo 0.9.1，签名、回执和完整性由宿主独立验证。

普通与开发者凭据均使用身份目录 ssl/fullchain.crt、ssl/privkey.pem、ssl/stapling.ocsp。首次申请不持久保存 pending 私钥，续签沿原序列，开发者续签显式执行。生产信任根与测试根分别编译，不分发测试根二进制。

## 检查

```sh
cargo fmt --all -- --check
cargo test --workspace --exclude jade --locked --all-features --all-targets -- --test-threads=1
jade/tests/scripts/code-signing.sh --all-features --all-targets -- --test-threads=1
cargo clippy --workspace --locked --all-targets --all-features -- -D warnings
cargo fmt --manifest-path xtask/Cargo.toml -- --check
cargo test --manifest-path xtask/Cargo.toml --locked
cargo clippy --manifest-path xtask/Cargo.toml --locked --all-targets -- -D warnings
cargo publish --dry-run --locked --allow-dirty \
  -p genmeta-access -p genmeta-curl -p genmeta-discover -p genmeta-identity \
  -p genmeta-nat -p genmeta-doctor -p genmeta-nslookup -p genmeta-proxy -p genmeta
```

检查须使用独立仓库和原锁文件，不更新邻近依赖。不带发布凭据的 dry-run 不上传。Jade 脚本将测试根限定在 target/code-signing-tests。

完成候选检查与源码审阅后再合并、建立不可变 annotated v0.9.1 标签，并核对 Linux/macOS/Windows CI、MSRV 与 DEB/RPM/Homebrew/Scoop 的既有分发范围。上传 crate 和推送发行标签是实际发布步骤，本地检查不代表这些步骤已完成。
