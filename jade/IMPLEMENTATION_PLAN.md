# Jade 实施规划

日期：2026-10-23。状态：首轮实现已落地，本地验收通过；跨平台结果由 CI 确认。用法见 [README](README.md)，领域术语见 [CONTEXT.md](../CONTEXT.md)。

## 1. 目标与边界

Jade 完成三件事：准备项目、生成签名包、发布指定包。首轮支持静态页面、通过 npm/pnpm/Bun 构建的静态前端，以及 Rust HTTP API。后端源码先支持 Rust，由 Jade 内置构建；已有 Component 也可直接打包。

源码编译复用项目原生工具链，身份与凭据复用 DHTTP，安装和运行端管理由 genmeta 提供。Jade 负责连接这些已有能力，完成校验、封装、签名和上传。

## 2. 命令

```sh
jade create hello
cd hello
rustup target add wasm32-wasip2
jade build --id alice.smith
jade publish build/hello-0.1.0.waz
```

| 命令 | 职责与选项 |
| --- | --- |
| `jade create PATH` | 创建新项目；`--name NAME` 指定包短名称，默认取目录名；`--template TEMPLATE` 选择初始文件，默认 fullstack（前端和后端 API） |
| `jade build [PATH]` | 构建、校验并签名；`--id AUTHOR` 选择身份，`-o/--output FILE` 指定包文件，`--overwrite` 允许替换显式指定的已有普通文件 |
| `jade publish FILE` | 校验并上传指定签名包，使用包内作者对应的凭据 |

三个命令共用 `--json` 和 `--verb`：前者输出机器结果，后者将调试日志写入 stderr。

build 的 PATH 可为项目目录或 Jade 配置文件，默认当前目录下的 `jade.toml`。CLI 相对路径以当前工作目录为基准，配置内路径以配置文件所在目录为基准。

create 提供 static、web、api、fullstack 四个初始文件预设；默认使用 fullstack，组合前后端模板。模板名称仅用于创建文件，生成的项目使用同一套配置与构建流程。create 生成 `.gitignore` 和工具链准备说明，无需身份凭据。

包文件默认写入配置目录下的 `build/NAME-VERSION.waz`，Rust 编译缓存放在 `build/target/`。`build/` 只存包文件和临时构建数据，可删除重建，并被版本控制和内容收集忽略。旧版 `.jade/` 也不参与内容收集；已有项目需将 `/build/` 加入 `.gitignore`。前端工具继续使用自己的输出目录，例如 `dist/`。

## 3. 作者与身份

包标识由规范作者身份和包短名称组成，例如 `alice.smith.dhttp.net/hello`。配置和命令中的 `alice.smith` 会规范化为完整名称，终端可展示为 `alice.smith~`。

build 按以下顺序确定签名身份：

1. 指定 `--id` 时使用该身份；若配置了 `package.author`，两者须一致。
2. 否则使用 `package.author`；未配置时使用已有的 DHTTP 默认身份。
3. 都未设置时，唯一可用身份自动选中；多个候选在交互终端中选择，非交互模式返回 `E_IDENTITY_REQUIRED`。

已指定的身份凭据不可用时报告错误。交互要求 stdin 和 stderr 均为 TTY，且未启用 `--json`。选择只作用于本次构建，证书和私钥继续由 DHTTP 管理。

publish 从包中取得作者和 owner，直接读取匹配凭据。首轮使用与包内证书一致的凭据；证书更换后重新 build 签名。本地校验通过后再准备认证网络端点。

## 4. 项目配置

### 4.1 示例

静态项目：

```toml
[package]
name = "hello"
version = "0.1.0"
description = "Hello application"
license = "Apache-2.0"

```

前端工程和 HTTP API 使用相同的 package 信息，不声明 `[frontend]` 或 `[backend]`。
前端优先识别根目录、web/、app/ 下含有效 scripts.build 的 package.json，构建输出固定为该目录的 dist/。
无构建工程时查找根目录、web/、app/、public/ 的 index.html；仍未找到时才查找 dist/、web/dist/、app/dist/。
同一阶段有多个候选时报错，旧构建产物不会覆盖源码选择。

后端自动识别根目录的 Cargo.toml、api/Cargo.toml 或 lib/Cargo.toml；
多个 Rust 工程时报错。无 Rust 源码时才使用根目录 lib.wasm，已有旧产物不影响源码构建。
纯后端项目只需 package，不再配置 backend。

### 4.2 字段

| 字段 | 要求或默认值 | 含义 |
| --- | --- | --- |
| `package.name` | 必填 | 包短名称 |
| `package.version` | 必填 | `MAJOR.MINOR.PATCH` 版本 |
| `package.description` | 必填 | 包的用途说明 |
| `package.license` | 必填 | 许可证声明，优先使用 SPDX 表达式 |
| `package.author` | 可选 | 作者的统一身份，同时约束签名身份 |
| `package.title` | 默认 name | 展示名称 |
| `package.release-notes` | 默认 `Release VERSION` | 本次版本说明，VERSION 取当前版本 |
| `package.repository` | 可选 | 源码仓库 HTTPS 地址 |
| `dependencies` | 默认空数组 | 运行时包依赖，每项包含 author、name、version |

至少存在可自动识别的前端或后端。除 dependencies 为表数组外，字段均为字符串。配置错误定位到具体字段。

包名以小写字母开头，最多 63 个小写字母、数字或连字符。版本各段为无多余前导零的非负整数，取 u64 范围。包依赖使用精确版本，同一标识仅出现一次，并排除自依赖；源码依赖由 Cargo/npm 管理。

运行时包依赖按需声明：

```toml
[[dependencies]]
author = "std.dhttp.net"
name = "message"
version = "1.2.3"
```

宿主能力不声明用途，也不与 imports 做声明比对；沙箱支持的接口检查保持。ZIP 清单与文件布局如下：

| 配置或产物 | 包内表示 |
| --- | --- |
| author、name、version、description、license、repository | `manifest.json` 的 `package` 对应字段 |
| title、release-notes | `package.title`、`package.release-notes` |
| dependencies | 清单根级显式数组，每项使用 author、name、version |
| 静态资源 | `public/` 文件目录，清单声明 `frontend = "public"` |
| Component | `backend.wasm`，清单声明 `backend = "backend.wasm"` |
| README.md、CHANGELOG.md | ZIP 根目录中的可选文档，自动按存在情况收集 |

## 5. 构建

### 5.1 复用原生构建入口

| 输入 | 处理方式 |
| --- | --- |
| 前端目录有有效的 `package.json` build 脚本 | 安装依赖（含开发依赖），调用该脚本，收集该目录的 dist/ 资源 |
| 前端目录无 build 脚本且包含 index.html | 直接收集静态资源 |
| 后端目录符合 Rust API 模板约定 | Jade 直接调用 Cargo，按内置组件目标编译并从构建结果定位产物，取得 Component 和生成的 OpenAPI |
| 后端路径为已有文件 | 按 Component 读取，检查宿主接口及内嵌 OpenAPI |

错误的脚本声明或不支持的工程给出具体配置提示；仅有 package.json 或 Cargo.toml 不构成构建入口。Node 构建复用 packageManager 声明或唯一锁文件确定的 npm/pnpm/Bun，均未提供时用 npm；冲突在原生项目配置中解决。

`jade create PATH --template api` 生成 Cargo 工程、wasip2 与 serde_json 依赖和示例接口。开发者编写路由、请求/响应类型和处理函数，然后执行 `jade build`。

Jade 内置 Cargo 调用、组件编译目标和产物定位。API 模板在 `lib.rs` 中直接使用 wasip2 与 serde_json，实现 WASI HTTP 入口和 JSON 示例接口，不生成本地 SDK 模块。修改路由时同步更新文件内的 `ROUTES` 元数据；Jade 从该元数据生成路由级 OpenAPI 并嵌入组件。开发者无需编写 build 脚本。详细请求/响应 schema 推导不在当前实现内。

源码工程使用已准备的工具链；前端每次构建先通过所选包管理器同步依赖，包含开发依赖，无需手动安装项目依赖；静态项目直接打包。前端目录位于项目根目录时，其 dist 输出与 Jade 的 `build/` 输出相互独立。

### 5.2 封装与写出

```text
读取配置与选择身份 → 执行原生构建或读取已有产物
→ 固定产物快照 → 校验宿主接口 → 生成清单并签名
→ 验证完整包 → 原子写出
```

收集声明或构建生成的运行产物及可选根目录文档。目录包含普通文件和子目录；项目根目录的 `build/` 和旧版 `.jade/` 始终排除，其他显式包输出位于收集范围之外。根目录文档进入 ZIP 根目录，不重复作为前端资源收集。文件顺序和元数据统一规范化，相同产物与元数据具有稳定的内容摘要。

发布包使用标准 ZIP、`.waz` 后缀和 `application/zip`。JSON 清单、目录布局、文件摘要和签名域以 [WAZ v1](FORMAT.md) 为准；不接受旧 WEBC 发布包。后端以 `pishoo:openapi` 自定义段携带 OpenAPI 3.1.x 文档，上限 1 MiB。完整包和解压后总内容分别限制为 64 MiB，单个静态或文档文件上限 16 MiB，内容条目预算 4096（含签名证明），包依赖最多 100 项。项目根目录的 `README.md`、`CHANGELOG.md` 自动按存在情况纳入，无需声明。

`payload_sha256` 标识元数据和运行内容，`package_sha256` 标识完整签名包字节。写出前验证容器、内容摘要、数字签名和作者绑定，记录实际完成的本地信任检查。

默认输出在验证旧包签名和归属后，可原子更新同包标识、版本和 owner 的产物；显式输出覆盖已有普通文件需要 `--overwrite`。同一路径写入串行化，失败保留已有包并清理本次临时文件。create 同样先生成完整模板，再提交到新目录。

## 6. 发布

publish 读取指定包的固定快照，完成本地校验，使用包内作者对应的凭据上传。校验商店身份及 owner，并核对返回的包标识、版本、所有者和摘要。

| 商店结果 | 命令行为 |
| --- | --- |
| 新版本保存成功 | 返回 published |
| 同包同版本具有相同内容摘要 | 返回 already-published，视为成功 |
| 同包同版本具有不同内容摘要 | 返回版本冲突，提示提升版本 |
| 请求后无法确认是否保存成功 | 返回 `E_PUBLISH_OUTCOME_UNKNOWN`，提示稍后重试同一文件 |

单次命令提交一次上传请求。响应丢失或服务端错误后执行有界的只读核验，确认后返回实际结果。重新签名可能改变文件摘要，重复发布按内容摘要判断。

## 7. 输出

默认输出阶段进度和最终摘要：进度、构建工具日志、诊断写 stderr，结果写 stdout。build 结果包含包标识、版本、文件路径、大小、两种摘要及可复制的 publish 命令。

`--json` 使用非交互模式，stdout 输出一个完整 JSON 文档；参数错误也遵守该规则。help/version 保持文本输出。示例：

```json
{
  "schema_version": 1,
  "command": "build",
  "status": "ok",
  "result": {
    "id": "alice.smith.dhttp.net/hello",
    "version": "0.1.0",
    "file": "/absolute/project/build/hello-0.1.0.waz",
    "size": 12697,
    "package_sha256": "<64 lowercase hex characters>",
    "payload_sha256": "<64 lowercase hex characters>"
  }
}
```

示例大小和摘要占位符用于说明结构。JSON 使用完整 ID、绝对路径、整数字节数和 64 个小写十六进制字符的摘要；缩写仅用于终端展示。

| 命令 | 成功时的 result 字段 |
| --- | --- |
| create | path、manifest、name |
| build | id、version、file、size、package_sha256、payload_sha256 |
| publish | id、version、outcome、package_sha256、payload_sha256 |

publish 的 outcome 为 published 或 already-published，摘要指向商店实际保存的包。失败时 status 为 error，返回含 code、message 和可选 hint/context 的 error 对象；context 为对象。结果未知时另含 `result.outcome = "unknown"`，其他错误省略 result；成功时省略 error。参数解析无法确定命令时 command 为 null。

退出码：0 成功，1 运行失败或发布结果未知，2 参数错误，130 用户取消。错误码用于脚本区分可采取的下一步：

| 场景 | 错误码 |
| --- | --- |
| 配置、产物或工具链问题 | E_CONFIG_INVALID、E_ARTIFACT_INVALID、E_TOOLCHAIN_UNAVAILABLE、E_BUILD_FAILED |
| 身份待选择、不可用或不匹配 | E_IDENTITY_REQUIRED、E_IDENTITY_UNAVAILABLE、E_IDENTITY_MISMATCH |
| 包、签名或输出文件问题 | E_PACKAGE_INVALID、E_SIGNATURE_INVALID、E_OUTPUT_CONFLICT |
| 发布拒绝、冲突或结果未知 | E_PUBLISH_REJECTED、E_VERSION_CONFLICT、E_PUBLISH_OUTCOME_UNKNOWN |
| 其他 | E_IO、E_INTERNAL、E_USAGE、E_CANCELLED |

新增可选字段保持 schema_version；既有字段语义改变时升级结构版本。

## 8. 实施与验收

| 阶段 | 交付及完成标准 |
| --- | --- |
| P0：协议与 SDK | 固定目标宿主/商店版本、组件接口、OpenAPI、签名与证书规则，提供可运行的正例及关键反例 |
| P1：项目与配置 | 创建模板，解析配置、路径和原生构建入口，完成人类与 JSON 输出基础 |
| P2：构建与签名 | 前端源码、Rust API、已有产物均可生成宿主可运行的签名包；API 模板只修改业务 Rust 代码即可构建，无需补写构建脚本；重复构建和失败保留行为通过 |
| P3：发布 | 本地商店验证发布、重复发布、版本冲突及响应丢失后的结果核验 |
| P4：完整流程 | 四个模板通过 create → build → publish；使用文档与行为一致，跨平台 CI 通过 |

P0 与 P1 可并行，P2 使用确定的协议和 SDK，P3、P4 依次完成。复用现有包读写、摘要和验签逻辑，CLI 负责参数与渲染，核心逻辑返回类型化结果；模块随实现需要拆分。

验收使用隔离身份、本地 HTTP/3 商店和隔离宿主。覆盖身份选择、JSON/非交互、取消、源码变化、构建失败、包内容与签名篡改、路径与覆盖、证书更换以及发布结果核验。根目录前端和静态目录包含项目根目录的场景均验证 `build/` 不参与收集。

Linux、macOS、Windows 运行构建与常规测试；HTTP/3 契约测试在具备 OpenSSL 3 和本地 UDP 条件的 CI 作业中显式执行。验收记录保留环境、目标版本和结果。

本地验收环境为 macOS arm64：CLI 使用 Rust 1.96 nightly，API 模板使用 Rust 1.97.1 的 wasm32-wasip2，前端使用 Node 23.11 与 Vite 8.3。Rust 业务代码修改后重建、Vite/Cargo 组合包构建和本地 HTTP/3 发布均通过。生成的组件另通过本地 Pishoo 的 OpenAPI 校验与实际宿主链接，并在同版本 Wasmtime 47.0.4 中验证 GET、JSON POST、无效 JSON、405 和 404。
