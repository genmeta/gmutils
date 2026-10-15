# genmeta package publish：实现与商店兼容差异

核验日期：2026-10-14。设计来源：`pishoo/pishoo/docs/genmeta-upload-design.md`。

## 客户端

```sh
genmeta package publish FILE.webc [-i PUBLISHER | --id PUBLISHER]
```

必须安装支持当前包规范的 `pishoo app check` / `pishoo lib check`。优先查找
与 genmeta 同目录的 pishoo，再使用 PATH。只处理本地普通文件，完整包最多
64 MiB。`--id` 是签名发布者核对项；省略时按 manifest publisher 在用户
`DHTTP_HOME`（默认 `~/.dhttp`）选取真实凭据，不使用默认或匿名身份。

单次读取的字节快照写入私有临时文件供宿主整包校验，子进程 JSON 被捕获，
上传仍使用该快照。模块只解析 manifest、签名信封和现有 payload 摘要，
没有另建包验签器。签名证书链须逐字节等于实际出站 LocalAuthority。

唯一目标为 `store.dhttp.net`，固定 owner_hash 为
`ffc3e50e1dfb7baca1cc07a7cbfcf8cb34a9bf5a9c25024fcf9a9786bb230746`。
PUT、核实 GET 和下载 GET 都在打开请求流之前核对该锚，响应再核对
RemoteAuthority 名称与 owner_hash。没有重定向跟随、可配置商店、自动重签、
自动发布依赖或 202/status 轮询。

首次 201 要求保存的完整包大小/摘要与快照相同；200 同内容重签通过固定
下载路径下载原保存包、宿主校验并比较 payload_sha256。结果不明时仅执行
一次精确版本 GET，必要时下载核实，不重复 PUT。不能证明已发布时非零退出，
stderr 说明发布结果未知并保留失败原因。下架版本不能作为成功。

成功 stdout 是单个 JSON：`result`（published/already-published）、`id`、
`kind`、`version`、`status`、`package_sha256`、`detail_url`。完整包摘要指向
商店实际保存的文件；同内容重签时可能与本次输入文件不同。所有 JSON 限制
1 MiB，签名信封64 KiB，下载64 MiB；拒绝 trailer、错类型/身份/路径/大小/摘要。
单次 PUT 总期限180秒，精确版本 GET 30秒，包下载180秒，宿主 check 180秒；
每个期限覆盖完整操作，不随帧或循环重置。

新增直接依赖：workspace 的 base64、ddns、dhttp、dhttp-home、dhttp-identity、
http、http-body-util、serde_json；sha2 0.10、tempfile 3、webc =12.0.1
（仅 v3），Unix 使用 libc 打开非阻塞/不跟随链接的普通文件。
测试另用 bytes、futures、qbase、qprotocol、qtls、rcgen、rustls-pemfile、
http-body、tower 和 Tokio test-util。未修改底层传输 API。

## 独立商店实际差异（只读评估，未实施）

核验商店 HEAD：`001fca1e9f1eb971f3ff9ca0ff1ee332afeefa63`；本地
`src/store.rs`、`src/schema.sql`、`CONTRACT.md`、`vendor/source.json`。
不以本地文档或源码变化推断生产部署已更新。

| 位置 | 当前实现 | 新规范所需修改 |
| --- | --- | --- |
| `versions.openapi_json` | NOT NULL；App 也保存旧 OpenAPI | 改为可空的真实 Lib API 文档；App 为 NULL，不能伪造 OpenAPI |
| `versions` 包声明 | 没有 manifest 投影列 | 提议增加 `manifest_json TEXT NOT NULL CHECK(json_valid(manifest_json))`，保存已验签 WEBC manifest 的 JSON 查询投影；原 CBOR 权威仍保留在签名包中 |
| 类型/文档约束 | kind 已有 app/lib，主键已含 kind | 保留 `(kind,publisher,name,version)` 主键；提议 CHECK：Lib 的 openapi_json 为合法 JSON 且非 NULL，App 为 NULL；schema 版本及旧数据处理须单独批准 |
| `Registry::open` | 查询固定列，读取/校验旧 OpenAPI、旧包 | 更新 schema 校验、SELECT 与启动逐包核验：manifest 投影必须与原包一致；Lib 额外核验真实 OpenAPI；不能自动迁移旧测试包 |
| `envelope` / `verify_publisher` / `validate_package` / `validate_manifest` | 包级签名既有；元数据与静态映射按旧 OpenAPI | 保留签名算法和握手证书链要求；从 manifest 读取包身份、kind、entry/host、dependencies、changelog、repository，App 零 atom/public；Lib 单 backend/metadata，复用已批准宿主校验逻辑 |
| `publish` 的事务与 INSERT | 从 `document["x-pishoo"]` 取 kind/依赖/changelog；INSERT 原 openapi_json | 写入 manifest_json 和可选真实 openapi_json；事务内核验 manifest 的每项精确 Lib 依赖。依赖拒绝应返回具体完整 ID/版本；同内容幂等和 yanked 状态保持 |
| `metadata`、目录、详情、updates | 从 openapi_json 派生依赖；full 响应总含 openapi | 从已验证 manifest 投影派生展示字段和可选 repository；只给 Lib 返回 openapi；保留 signer_certificates、固定 download_path、大小、完整包摘要和 publisher_owner_hash |

Registry 的 db/packages 两个成员、跨模块函数签名、身份库、原子文件保存、
namespace owner 绑定、现有 apps/libs 路由均无须新增状态容器。以上持久字段
与方法体适配属于待批准提案，本次没有修改商店 SQL、vendor 或部署。

## 上游同步来源与上线前事项

商店目前固定 Pishoo 快照为 `66a339ababed1339491a8a977a192ee5546137e0`；
已记录的批准回补为 `2f8bac1297f79dd990f7d4a397f49ad570c3724c` 的
identity@0.2.0 WIT/Host 兼容实现。核验的 Pishoo 本地 HEAD 为
`510e7075297a5c182fd55a74f699ac1932533440`；本地包规范实现及并行打包工具
工作不能自动成为商店获准 vendor 同步来源。新包校验所需的具体提交/文件
摘要和同步范围须另行确认并写入商店 source.json；不擅自改运行时来源。

临时兼容商店测试仅实现目标发布协议，使用临时 CA/凭据、真实 UDP/TLS/HTTP3
和宿主 check。它不证明当前独立商店已适配或生产发布成功。上线前仍需：

- 批准并实现上表具体商店字段/读写差异，核验已批准上游同步来源。
- 使用真实适配商店执行集成回归，确认 repository 从已验签 manifest 返回。
- 确认发行版附带当前 pishoo check，并完成单独授权的部署与上线验收。

本任务不向生产商店发布、删除或迁移任何包。

## 验证命令

```sh
cargo test -p genmeta upload::tests
# 需要当前 pishoo check、OpenSSL 和本机 UDP 权限；使用临时身份/商店。
cargo test -p genmeta upload::tests::real_http3 -- --ignored --nocapture
```

若父目录 Cargo 配置覆盖了部分本地底层库而造成重复 qtls 类型，可从
`/tmp` 运行同一命令并指定本仓 Cargo.toml 的绝对 `--manifest-path`，验证正式
crates.io 依赖。不要为测试修改底层库接口或生产信任锚。

macOS 系统 LibreSSL 不支持这里使用的 OpenSSL 参数；可通过
`DHTTP_TEST_OPENSSL=/opt/homebrew/opt/openssl@3/bin/openssl` 选择 OpenSSL 3。

本次验证结果：`cargo test -p genmeta` 的32项单元测试及3项 launcher 集成
测试通过；默认忽略的上传 HTTP/3 测试已单独运行通过。上传专属测试覆盖
App/Lib 真正 PUT、同内容重试/重签、409、精确依赖拒绝及发布顺序、下架重试、
500/非法 trailer 后的只读核实、无保存/不同内容、文件变化快照、repository、
商店 pin 与包证书链拒绝。`cargo clippy -p genmeta --all-targets -- -D warnings`
及 `git diff --check` 通过。所用临时 CA 仅在独立测试进程注册，不改生产锚。
