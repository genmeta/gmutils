# gmutils 命令使用指南

本文按当前仓库源码整理，核对日期：2026-10-20。主程序 `genmeta` 的版本为 `0.9.0-preview.3`，各工具子模块有各自的版本号。安装方式见 [README](../README.md#install)。

`gmutils` 是工具集名称，统一命令入口是：

```text
genmeta <命令> [参数]
genmeta --help
genmeta <命令> --help
genmeta --version
```

示例中的 `alice.smith`、`friend.name`、路径和包版本均为占位示例，使用前替换为自己的值。申请身份、修改监听、授权、发布和安装等命令会实际改变状态，按需执行。

## 目录

- [命令总览](#命令总览)
- [使用约定](#使用约定)
- [身份管理：identity](#身份管理identity)
- [监听配置：listen](#监听配置listen)
- [HTTP 挂载：mount/unmount](#http-挂载mountunmount)
- [访问控制：access](#访问控制access)
- [DHTTP 请求：curl](#dhttp-请求curl)
- [本地正向代理：proxy](#本地正向代理proxy)
- [名称解析：nslookup](#名称解析nslookup)
- [局域网发现：discover](#局域网发现discover)
- [网络诊断：doctor](#网络诊断doctor)
- [包构建与发布：build、publish](#包构建与发布buildpublish)
- [包安装与管理：install、update、uninstall、list、info](#包安装与管理installupdateuninstalllistinfo)
- [常见操作流程](#常见操作流程)
- [独立工具与源码入口](#独立工具与源码入口)

## 命令总览

| 命令 | 功能 | 使用条件 |
| --- | --- | --- |
| `genmeta identity`，别名 `genmeta id` | 申请、续期、查看身份和设置默认身份 | 申请、续期需要连接证书服务；查看本地身份无需运行 Pishoo |
| `genmeta listen` | 查询或修改身份服务的监听范围、停用身份服务 | 本地已有身份；修改本地配置，无需 Pishoo 正在运行 |
| `genmeta mount` / `genmeta unmount` | 查询、添加、更新或删除 HTTP 挂载规则 | 对应身份的 Pishoo 已运行并启用 |
| `genmeta access` | 管理 API 的允许、拒绝、审批策略 | 对应身份的 Pishoo 已运行并启用 |
| `genmeta curl` | 发送 DHTTP/3 请求，上传、下载、调试接口 | 目标 DHTTP 服务可达；可使用身份或匿名访问 |
| `genmeta proxy` | 启动本地 HTTP 正向代理，将 DHTTP 域名请求转为 DHTTP/3 | 本机可连接目标；不依赖本机 Pishoo |
| `genmeta nslookup` | 通过 mDNS、H3 或系统 DNS 查询地址 | 对应解析源可用 |
| `genmeta discover` | 持续发现局域网中的 DHTTP 服务 | 局域网支持 mDNS |
| `genmeta doctor net` | 检测 NAT、接口和公网地址映射 | 网络允许进行探测 |
| `genmeta build` | 执行项目构建并签名生成 WEBC 包 | 本地项目、构建工具和发布者凭据 |
| `genmeta publish` | 将已签名 WEBC 包发布到商店 | 本地发布者凭据，商店可达 |
| `genmeta install` | 安装商店中已发布的 App 或 Lib 及其精确依赖 | 本地身份的 Pishoo 已运行并启用，商店可达 |
| `genmeta update` | 从原发布者更新已安装的包 | 同上，且包已安装 |
| `genmeta uninstall` | 卸载包，保留数据和依赖 | 本地身份的 Pishoo 已运行并启用 |
| `genmeta install --list` | 列出已安装的 App、Lib | 同上 |
| `genmeta install --info` | 查看已安装包及其精确依赖 | 同上 |
| `genmeta version` | 查看主程序版本 | 无 |

## 申请名字时安装 Workspace

安装或升级 gmutils 不再自动安装 Workspace。交互执行 `genmeta identity apply` 成功后，会询问是否为刚申请的名字安装 Workspace；默认选“是”，直接回车就执行 `genmeta install workspace --id NAME`，输入 `n` 跳过。安装使用本次申请的身份和身份目录，不依赖默认身份的选择；对应的 Pishoo 服务需已运行并启用。跳过、非交互运行或安装失败时提示手动安装，已经完成的身份申请仍然有效；不后台补装或自动重试。

## 使用约定

### 身份与配置目录

默认使用当前账户的 `~/.dhttp`。支持 `--global` 的命令可切换到系统级 DHTTP 目录，具体位置由安装配置决定；写入可能需要相应的系统权限。

`--id` 不是顶层通用参数，应放在支持它的命令之后，例如 `genmeta curl --id alice.smith URL`。不同命令的身份选择规则如下：

| 命令 | 身份选择规则 |
| --- | --- |
| `identity apply/renew/default/info` | 身份名是位置参数；`renew`、`info` 不传名称时使用默认身份，`apply` 不传名称时进入交互选择 |
| `listen` | 必须显式传 `--id` |
| `access`、`mount`、`unmount`、包安装管理命令 | `--id` 选择管理和认证使用的身份；不传则使用默认身份 |
| `curl`、`proxy`、`nslookup` | 显式 `--id` 优先，否则尝试默认身份；找不到默认配置或身份时可退回匿名；显式身份加载失败会报错 |
| `doctor net` | 仅在显式传 `--id` 时加载身份，不自动选择默认身份 |
| `build`、`publish` | 使用包中声明的发布者身份；`--id` 用于校验匹配，不会改写发布者 |

`identity` 支持 `-g/--global`；`listen`、`access`、`curl`、`proxy`、`nslookup`、`doctor net` 支持 `--global`。`mount/unmount` 和包命令当前使用用户目录，没有 `--global` 参数。

### 身份名与查询名

身份管理可以使用 `alice.smith` 或 `alice.smith.dhttp.net`。申请目标支持主身份 `alice.smith` 和一级子身份 `device.alice.smith`。

DNS 查询名与身份参数有不同的展开规则：在 `nslookup` 和访问策略的联系人／组签发者名称中，只有显式的尾部 `~` 才展开为 `.dhttp.net`。

```sh
genmeta nslookup 'alice.smith~' h3          # 查询 alice.smith.dhttp.net
genmeta nslookup alice.smith.dhttp.net h3  # 同上
genmeta nslookup example.com system       # 查询普通域名
```

URL 示例统一使用完整域名。Shell 中的 `'*'`、`'**'`、`'?'`、`'*?'` 等应加引号，避免被 Shell 展开。

### Pishoo 与可达性

Pishoo 是承载身份服务、App、Lib 和管理 API 的独立程序。gmutils 提供管理客户端；Pishoo 的安装、进程启动和系统服务管理见相应部署说明。

保存监听配置不代表服务立即可用。正在运行的 Pishoo 会自动发现并应用配置，但仍需完成身份加载和凭据准备。已有凭据但没有监听配置的身份不会自动启用托管。

使用身份建立网络端点时，缺失或过期的 OCSP 缓存可能需要联网刷新；局域网可达不等于所有操作都可完全离线运行。

## 身份管理：identity

用途：申请并部署身份凭据、续期证书、查看本地状态、选择默认身份。

```text
genmeta identity [--global] <子命令> [参数]
genmeta id <子命令> [参数]
```

| 子命令 | 功能与参数 |
| --- | --- |
| `apply [IDENTITY]` | 交互申请或将身份部署到本机；别名 `create`；支持 `-e/--email`、`--device-name`、`-f/--force` |
| `renew [IDENTITY]` | 续期指定身份，省略名称时使用默认身份；支持 `--all`、`-e/--email`、`--device-name`、`-f/--force` |
| `default [IDENTITY]` | 不传名称时显示默认身份，传入名称时设置默认身份；查询支持 `-v/--verbose`，设置支持 `-f/--force` |
| `info [IDENTITY]` | 显示指定本地身份的详情，省略名称时查看默认身份 |
| `list` | 列出本地身份；`-v/--verbose` 显示证书详情 |
| `version` | 输出身份工具版本 |

```sh
genmeta identity apply
genmeta identity apply alice.smith --email alice@example.com --device-name laptop
genmeta identity list -v
genmeta identity info alice.smith
genmeta identity default alice.smith
genmeta identity default -v
genmeta identity renew alice.smith
genmeta identity renew --all
genmeta identity --global list
```

注意：

- `apply --force` 可跳过本地已有可用／过期身份的替换确认；它不跳过远端身份认证。已有正常凭据时，日常维护使用 `renew`。
- 交互申请成功后会询问是否启用服务；接受时才创建缺失的 `.volume/sys/setting/database` 监听配置，不创建默认欢迎页或 file 目录。拒绝或非交互申请不会创建服务配置，已有配置会保留。
- 随后询问是否安装 Workspace，默认回车即安装，输入 `n` 跳过；非交互申请跳过安装。`--global` 申请时，安装也使用本次申请的系统身份目录。
- `renew` 通常在证书剩余有效期不足 15 天时续期，否则跳过；`--force` 可提前续期。无效或不完整的本地身份即使使用 `--force`，也仍需有可读取的必要证书信息。
- `renew --all` 与具体身份名互斥。`default --force` 允许选择尚未就绪的本地身份，不会修复其凭据；它必须与名称一起使用，不能与 `--verbose` 一起使用。

## 监听配置：listen

```sh
genmeta listen --id NAME [internal|external|all|off] [--global] [--yes]
```

不传模式查询当前监听设置；internal 启用内网，external 启用外网，all 同时启用内外网。off 删除 listen KV，重启后仍关闭，保留挂载规则。写入会创建缺失配置，查询不会创建。listen off 需要 y/n 确认，脚本加 --yes。

## HTTP 挂载：mount/unmount

```sh
genmeta mount [--id NAME]
genmeta mount [--id NAME] LOCATION TARGET
genmeta unmount [--id NAME] LOCATION TARGET [--yes]
```

mount 不带位置和目标时列出挂载，否则添加或更新一条挂载。通过 GET/PATCH /std/sys/mount 访问运行中的身份服务。unmount 使用 DELETE /std/sys/mount?location=LOCATION&proxy_pass=TARGET，两个值都匹配才删除；需要 y/n 确认，脚本加 --yes。LOCATION 接受 / 前缀或精确匹配形式 `= /path`（需引号），TARGET 仅接受本机回环 HTTP/TCP 服务。挂载与监听独立；unmount 不停止监听。

```sh
genmeta listen --id alice.smith all
genmeta mount --id alice.smith /api 127.0.0.1:8080
genmeta unmount --id alice.smith /api 127.0.0.1:8080 --yes
genmeta listen --id alice.smith off --yes
```

监听配置保存在 `.volume/sys/setting/database`，命令在服务关闭时也可使用。`server`、`forward`、`unlisten` 旧命令不再提供。

## 访问控制：access

用途：按 API 路径前缀、HTTP 方法、被授权对象设置允许、拒绝或需要审批的策略。

```text
genmeta access [选项] <PATH> <操作> [参数]
genmeta access [选项] list [--wide]
genmeta access [选项] remove <PATH>...
```

公共选项：`--id NAME`（也可写 `--identity NAME`）、`--global`、`--method METHOD`、`--timeout SECONDS`。超时默认为每个管理请求 30 秒，必须大于 0。将身份和超时等公共选项放在路径之前，`--method` 也可放在路径操作之后。

| 路径操作 | 功能 |
| --- | --- |
| `PATH allow GRANTEE` | 允许对象访问 |
| `PATH deny GRANTEE` | 拒绝对象访问 |
| `PATH review GRANTEE` | 要求审批 |
| `PATH list` | 列出这个前缀上的策略 |
| `PATH remove GRANTEE...` | 删除指定对象的策略 |
| `PATH remove --all` 或 `PATH clear` | 删除这个前缀上的全部策略 |

`list` / `remove` 分别有 `ls` / `rm` 别名。全局 `remove PATH...` 可清空一个或多个精确前缀，不会删除子前缀上的记录。

| GRANTEE | 含义 |
| --- | --- |
| `friend.name.dhttp.net` 或 `'friend.name~'` | 指定联系人；一般需先登记为联系人，身份自身除外 |
| `'team@issuer.name~'` | 签发者名下的组 |
| `'**'` | 有名身份 |
| `'?'` | 匿名访问者 |
| `'*?'` | 所有访问者 |

```sh
genmeta access --id alice.smith /api allow '*?' --method GET
genmeta access --id alice.smith /api review '**' --method POST
genmeta access --id alice.smith /api deny '?'
genmeta access --id alice.smith /api allow 'friend.name~' --method POST
genmeta access --id alice.smith /api list
genmeta access --id alice.smith list --wide
genmeta access --id alice.smith /api remove '*?' --method GET
genmeta access --id alice.smith /api remove --all --method GET
genmeta access --id alice.smith remove /api /admin
```

行为约定：

- `PATH` 是以 `/` 开头的字面 API 前缀，不能带查询串、通配符或片段。命令修改的是这个精确前缀对应的策略记录。
- 同一 `(PATH, METHOD, GRANTEE)` 只有一个策略，重复设置会更新效果。
- 设置策略、删除指定对象时，默认方法为 `*`；列表、`clear`、`remove --all` 和全局路径删除默认涵盖所有方法。`--method` 可限定范围，方法写大写名称或 `'*'`。
- 普通 `list` 只列 API 前缀；`list --wide` 和路径 `list` 输出带表头的制表符分隔明细：`PATH`、`METHOD`、`EFFECT`、`GRANTEE`。
- 批量删除会逐条调用 API，不是原子操作。管理请求仅使用 mDNS 和直接本地网络端点；本地服务应保持可达。

查询全部规则用 `GET /std/acl/access`；指定路径的读取与写入用 `GET/POST /std/acl/access?api=PATH`；删除用 `DELETE /std/acl/allow?name=GRANTEE`，正文为 api/method。query 值由命令行编码，不再使用路径后缀。

App 公开开关统一设置根路径 `/app/NAME` 的 GET、`*?` 规则，页面、静态资源和深链接的 GET/HEAD 共用它：

```sh
genmeta access --id alice.smith /app/workspace allow '*?' --method GET
genmeta access --id alice.smith /app/workspace deny '*?' --method GET
```

## DHTTP 请求：curl

用途：通过 DHTTP/3 调用服务接口、下载内容、上传文件和查看传输信息。

```text
genmeta curl [选项] <URI>
```

| 参数 | 功能与默认值 |
| --- | --- |
| `-i, --id NAME` | 客户端身份；这里的 `-i` 表示身份 |
| `--global` | 从系统目录加载身份 |
| `--anonymous` | 跳过身份加载，与 `--id` 互斥 |
| `-X, --request METHOD` | 指定 HTTP 方法；无请求体默认 GET，`-d` 默认 POST，`-T` 默认 PUT |
| `-d, --data TEXT` | 发送字符串请求体，与 `-T` 互斥 |
| `-T, --upload-file PATH` | 将本地文件作为请求体上传 |
| `-H, --header 'Name: value'` | 自定义请求头，可重复 |
| `-o, --output PATH` | 保存响应正文，默认写 stdout |
| `-f, --fail` | HTTP 状态码 ≥ 400 时报错，适合脚本 |
| `-L, --location` | 跟随重定向；默认不跟随 |
| `--max-redirs N` | 跟随重定向的上限，默认 30 |
| `--connect-timeout SECONDS` | 连接阶段超时，默认 5 秒；0 表示禁用，不是整个传输的总时限 |
| `--compressed` | 请求压缩响应并解压，支持 deflate、gzip、zstd |
| `--raw` | 保留原始响应字节、不解压，与 `--compressed` 互斥 |
| `-4, --ipv4` / `-6, --ipv6` | 限定解析使用的地址族 |
| `-v, --verbose` | 显示请求和响应细节 |
| `-s, --silent` | 隐藏进度与错误提示 |
| `-S, --show-error` | 配合 `-s` 仍显示错误 |
| `-w, --write-out FORMAT` | 输出响应元数据和耗时 |

```sh
# 读取接口
genmeta curl --id alice.smith -f https://alice.smith.dhttp.net/std/sys/listen

# 提交 JSON（该业务接口需已存在）
genmeta curl --id alice.smith https://alice.smith.dhttp.net/api/items \
  -H 'Content-Type: application/json' -d '{"title":"hello"}'

# 上传与下载（目标接口需支持对应操作）
genmeta curl --id alice.smith -T ./data.bin https://alice.smith.dhttp.net/api/files/data.bin
genmeta curl --id alice.smith -f -L --compressed \
  -o ./result.json https://alice.smith.dhttp.net/api/export

# 查看状态码与耗时
genmeta curl --id alice.smith -sS -o ./body.json \
  -w 'status=%{response_code} total=%{time_total}\n' \
  https://alice.smith.dhttp.net/std/sys/listen

# 匿名请求
genmeta curl --anonymous -v https://alice.smith.dhttp.net/
```

`--write-out` 支持：`%{response_code}` / `%{http_code}`、`%{url}`、`%{method}`、`%{scheme}`、`%{http_version}`、`%{time_total}`、`%{time_connect}`、`%{time_starttransfer}`、`%{size_download}`、`%{header{name}}`，以及 `\n`、`\t`、`\r` 转义。

`-d` 按字面发送字符串，没有读取 `@file` 的语义；文件请求体使用 `-T`，需要其他方法时与 `-X` 配合。此工具使用 DHTTP/3 传输，URL 写作 `https://` 也不表示会改用普通 HTTPS 客户端。

进阶选项 `--dns mdns,h3` 可选择解析源；`--interface '*'` 是当前唯一支持的出站接口值。两项在 release 构建的帮助中隐藏。

## 本地正向代理：proxy

用途：为普通 HTTP 代理客户端提供入口，将 `.dhttp.net` 或尾部 `~` 域名的 HTTP 请求转为 DHTTP/3；其他 HTTP 请求正常转发，其他域名的 CONNECT 使用 TCP 隧道。

```sh
genmeta proxy [选项]
```

| 参数 | 功能 |
| --- | --- |
| `--listen IP:PORT`，别名 `--bind` | 本地监听地址，可重复；默认同时监听 `127.0.0.1:16080` 和 `[::1]:16080` |
| `-i, --id NAME` | 出站客户端身份 |
| `--global` | 使用系统身份目录 |
| `--anonymous` | 匿名出站，与 `--id` 互斥 |
| `-v, --verbose` | 详细请求日志 |
| `--log PATH` | 指定日志文件，默认 stderr |

```sh
# 终端一：运行代理
genmeta proxy --id alice.smith --listen 127.0.0.1:16080

# 终端二：使用系统 curl，通过代理访问 DHTTP 服务
curl --proxy http://127.0.0.1:16080 http://alice.smith.dhttp.net/
```

访问 DHTTP 目标时，代理客户端使用 `http://` URL；对 DHTTP 域名的 HTTPS CONNECT 当前返回 502。代理负责将 HTTP 请求转换为 DHTTP/3。

`--dns` 默认 `mdns,h3`，`--interface` 当前仅支持 `'*'`；两项在 release 帮助中隐藏。

当前 `-d/--daemon` 虽由共享参数解析器接受，但脱离前台运行的逻辑只在独立的 `genmeta-proxy` 程序入口执行；统一入口 `genmeta proxy` 使用前台运行。若安装了独立程序，可在 Unix 平台运行：

```sh
genmeta-proxy --id alice.smith --daemon --log /tmp/genmeta-proxy.log
```

`listen` 控制身份服务的范围，`mount/unmount` 配置身份服务到 HTTP 后端的转发，`proxy` 则启动本地客户端正向代理，三者用途不同。

## 名称解析：nslookup

用途：查询域名或 DHTTP 身份对应的地址，并按解析源输出结果。

```text
genmeta nslookup [选项] <NAME> [SCHEMES]
```

`SCHEMES` 是第二个位置参数，多个解析源用逗号分隔，默认 `mdns,h3`。常用值为 `mdns`（局域网）、`h3`（DDNS H3 解析）、`system`（系统 DNS）。

```sh
genmeta nslookup 'alice.smith~'
genmeta nslookup 'alice.smith~' mdns
genmeta nslookup alice.smith.dhttp.net h3
genmeta nslookup example.com system --anonymous
genmeta nslookup 'alice.smith~' mdns,h3 --id alice.smith
```

支持 `-i/--id`、`--global`、`--anonymous`。`-s/--streaming` 默认开启，地址解析出来即输出。`--interface` 在 release 帮助中隐藏，当前仅支持 `'*'`。

查询到地址不代表目标 API 已启用或允许当前身份访问，仍需用 `curl -f` 验证。

## 局域网发现：discover

用途：通过 mDNS 持续发现附近的 DHTTP 服务，输出名称和地址。运行后使用 Ctrl+C 结束。

```sh
genmeta discover [DOMAIN] [--interface NAME_OR_IP]
```

```sh
genmeta discover
genmeta discover --interface en0
genmeta discover --interface 192.168.1.10
```

省略 `DOMAIN` 时不限定发现结果名称。指定时按名称／后缀过滤，也会匹配补上当前构建所配置 DHTTP mDNS 服务后缀的名称。`--interface` 可重复，按接口名或本地 IP 筛选，默认 `'*'`；该选项在 release 帮助中隐藏。

## 网络诊断：doctor

用途：检测非回环接口的 NAT 类型和公网映射，输出接口、公网 IP 和探测完成数量。

```sh
genmeta doctor net [选项]
genmeta doctor version
```

```sh
genmeta doctor net
genmeta doctor net --verbose
genmeta doctor net --interface en0
genmeta doctor net --interface 192.168.1.10
genmeta doctor net --id alice.smith --global
```

支持 `-i/--id`、`--global`、`--anonymous`、`--interface` 和 `-v/--verbose`。接口筛选默认 `'*'`，可重复传接口名或本地 IP。探测最多等待约 30 秒；`--verbose` 还显示未获得公网映射的候选绑定。

接口筛选控制报告内容，不限制底层运行时只在指定接口上工作。未获得公网映射不等于已判定某种 NAT 类型；应结合详细输出判断。

## 包构建与发布：build、publish

### build：构建并签名

```sh
genmeta build [PATH] [--no-build] [-o FILE.webc] [--id PUBLISHER]
```

- `PATH` 为项目目录或 manifest 文件，默认当前目录；传目录时查找 `wasmer.toml`。
- 默认执行 manifest 的 `[build].command`，再签名。命令在该 manifest 所在目录运行，失败就停止，不签名。
- `[build].manifest` 可指定构建后生成的包 manifest，必须位于项目目录内。
- `--no-build` 跳过构建，直接对已有产物打包签名。
- `-o/--output` 指定输出路径；默认是最终包 manifest 所在目录下的 `dist/NAME-VERSION-KIND.webc`。已存在的输出文件不会被覆盖，输出不能落在打包的内容目录内。
- `-i/--id` 校验发布者与 manifest 一致；签名使用当前账户的本地发布者凭据，无需运行 Pishoo 或初始化网络。

构建配方示例：

```toml
[build]
command = ["sh", "build.sh"]
manifest = "dist/wasmer.toml"
```

`command` 是程序和参数数组。需要 Shell 语法时显式调用 Shell，例如上面的 `sh`。

最小静态 App 的包 manifest 示例，配合已有 `public/index.html` 使用：

```toml
[package]
name = "alice.smith.dhttp.net/hello"
version = "1.0.0"
description = "Hello DHTTP"
license = "Apache-2.0"

[package.pishoo]
kind = "app"
title = "Hello"
changelog = "Initial release"
entry = "/"
dependencies = []

[fs]
"/public" = "public"
```

```sh
# 有 [build] 配方的源码项目
genmeta build ./hello -o ./dist/hello.webc --id alice.smith

# 已有构建产物，例如上面的最小 App
genmeta build --no-build ./hello -o ./dist/hello.webc --id alice.smith
```

App 使用 `/public` 映射，必须包含 `index.html`，不能包含后端模块。Lib 需要一个名为 `backend` 的已构建 WASM component、`/metadata` 映射和显式的 `host` 用途声明；OpenAPI 从 component 中读取，或由 `metadata/openapi.json` 补入。必须显式写出 `dependencies` 数组，无依赖时填 `[]`；每项依赖都需声明精确的发布者、名称和版本。

包名使用规范化的 `publisher/name`，版本为 `MAJOR.MINOR.PATCH`，最终包不能超过 64 MiB。构建日志写 stderr，成功结果以 JSON 写 stdout，包含包 ID、类型、版本、文件、大小和 SHA-256。

### publish：发布已签名包

```sh
genmeta publish FILE.webc [--id PUBLISHER]
genmeta publish ./dist/hello.webc --id alice.smith
```

读取单个本地已签名 WEBC v3 常规文件，验证包及发布者凭据后上传到受信任的 `store.dhttp.net`。文件上限 64 MiB。省略 `--id` 时使用包内发布者；显式身份必须匹配包内发布者。发布不重新构建或改写包，成功输出 JSON，不依赖本机 Pishoo。

## 包安装与管理：install、update、uninstall、list、info

App 承载应用页面；Lib 提供后端能力。除 `install --list` 默认同时列出两种类型外，其余管理命令默认选择 App；`--lib` 选择 Lib，`--app` 与 `--lib` 互斥。

```sh
genmeta install TARGET [--version MAJOR.MINOR.PATCH] [--id NAME] [--app|--lib]
genmeta update TARGET [--version MAJOR.MINOR.PATCH] [--id NAME] [--app|--lib]
genmeta uninstall TARGET [--id NAME] [--app|--lib]
genmeta install --list [--id NAME] [--app|--lib]
genmeta install --info TARGET [--id NAME] [--app|--lib]
```

| 命令 | 行为 |
| --- | --- |
| `install` | 默认安装最新已发布版本，并由 Pishoo 安装精确 Lib 依赖；成功同版本重装更新 upgraded_at，保留 installed_at；也可用 `update` 选择版本 |
| `update` | 要求包已安装，保持原发布者，默认选择最新版本，也可显式指定版本 |
| `uninstall` | 卸载包但保留数据与依赖；若被其他 App/Lib 依赖，服务端会阻止并报告依赖者 |
| `list` | 查询所选身份服务上的已安装目录 |
| `info` | 查询所选身份服务上的已安装包和精确依赖 |

目标名称规则：

- 安装裸名 `workspace` 固定选择 `std.dhttp.net/workspace`。
- 安装时 `alice.smith/hello` 展开为 `alice.smith.dhttp.net/hello`，也可直接传完整包 ID。
- `update`、`uninstall`、`info` 的裸名查询已安装目录，并保留原注册发布者；完整 ID 必须匹配已安装发布者。

```sh
genmeta install workspace --id alice.smith
genmeta install dev.dhttp.net/hello --version 1.0.0 --id alice.smith
genmeta install std.dhttp.net/message --lib --id alice.smith
genmeta install --list --id alice.smith
genmeta install --list --lib --id alice.smith
genmeta install --info workspace --id alice.smith
genmeta install --info message --lib --id alice.smith
genmeta update workspace --id alice.smith
genmeta uninstall hello --id alice.smith
```

安装和更新只接受商店已发布版本，不支持直接安装本地 `.webc`、URL 或匿名安装。所有命令均需本地身份凭据及其已启用、可达的 Pishoo；`list`、`info`、`uninstall` 查询的是身份服务，不是商店。

成功结果写 stdout，格式为 JSON；进度和诊断写 stderr。App 安装结果包含 `entry_url`。商店版本解析期限为 120 秒，安装请求最多等待 15 分钟。中断或超时可能意味着结果未知，CLI 不自动重试写操作；先检查已安装目录和服务日志。父包安装失败时，此前已安装的依赖会保留。

安装包不会自动授予 API 访问权限。商店和 Pishoo 需支持当前 WEBC manifest 协议；卸载还要求 Pishoo 支持包详情响应中的 `Package-Id` 校验。

## 常见操作流程

### 申请身份并启用服务

首次使用时申请身份；已有身份可从查看状态开始：

```sh
genmeta identity apply alice.smith
genmeta identity list -v
genmeta identity default alice.smith
genmeta listen --id alice.smith all
```

确保 Pishoo 已启动，再检查局域网解析和实际 API：

```sh
genmeta nslookup 'alice.smith~' mdns
genmeta curl --id alice.smith -f https://alice.smith.dhttp.net/std/sys/listen
```

### 暴露本机 HTTP 服务

本机 `127.0.0.1:8080` 已有 HTTP 服务时，配置身份服务转发，再按需要授予访问权限：

```sh
genmeta mount --id alice.smith /api 127.0.0.1:8080
genmeta access --id alice.smith /api allow 'friend.name~' --method GET
genmeta mount --id alice.smith
genmeta access --id alice.smith /api list
```

指定联系人需已登记；查看规则只确认配置，实际访问还取决于目标后端和对应身份的权限。

### 安装并查看 Workspace

```sh
genmeta install workspace --id alice.smith
genmeta install --list --id alice.smith
genmeta install --info workspace --id alice.smith
```

使用安装结果的 `entry_url` 进入应用。联系人申请和审批的完整流程见 [从申请身份到 Workspace 和联系人](identity-workspace-contacts.md)；当前没有独立的联系人管理子命令，可通过 Workspace 或 `genmeta curl` 调用接口。

### 排查连接问题

```sh
genmeta identity info alice.smith
genmeta listen --id alice.smith
genmeta discover
genmeta nslookup 'alice.smith~' mdns
genmeta nslookup 'alice.smith~' h3
genmeta doctor net -v
genmeta curl --id alice.smith -v -f https://alice.smith.dhttp.net/
```

以上按需逐条运行；`discover` 为持续发现，Ctrl+C 结束后再执行下一条。`access` 和 `curl` 默认只记录 warning/error，需要底层传输日志时可使用：

```sh
RUST_LOG=debug genmeta curl --id alice.smith -v https://alice.smith.dhttp.net/
```

`curl -v` 的请求／响应输出与 `RUST_LOG` 控制的底层日志相互独立。默认连接超时为 5 秒，必要时可用 `--connect-timeout 15` 调整。

## 独立工具与源码入口

统一使用 `genmeta` 即可。仓库也提供以下独立二进制入口；系统安装包提供统一入口，独立工具是否可用取决于安装方式：

| 独立程序 | 对应功能 |
| --- | --- |
| `genmeta-identity` | `genmeta identity` |
| `genmeta-curl` | `genmeta curl` |
| `genmeta-proxy` | `genmeta proxy`，另有独立入口的 Unix daemon 处理 |
| `genmeta-nslookup` | `genmeta nslookup` |
| `genmeta-discover` | `genmeta discover` |
| `genmeta-doctor net` | `genmeta doctor net` |
| `genmeta-nat` | NAT 诊断，即 `genmeta doctor net` 的实现 |

`genmeta-access` 当前是库 crate，通过统一入口 `genmeta access` 调用。

维护文档时，以这些源码中的参数声明和执行逻辑为准：

- [统一入口与包命令](../genmeta/src/main.rs)
- [监听与转发](../genmeta/src/server.rs)
- [身份管理](../genmeta-identity/src/cli.rs)
- [访问控制](../genmeta-access/src/cli.rs)
- [DHTTP 请求](../genmeta-curl/src/cli.rs)
- [正向代理](../genmeta-proxy/src/lib.rs)
- [名称解析](../genmeta-nslookup/src/lib.rs)
- [局域网发现](../genmeta-discover/src/lib.rs)
- [诊断入口](../genmeta-doctor/src/lib.rs)与 [NAT 实现](../genmeta-nat/src/lib.rs)
- [构建与签名](../genmeta/src/pack.rs)、[发布](../genmeta/src/upload.rs)、[安装与包管理](../genmeta/src/install.rs)
