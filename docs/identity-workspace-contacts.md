# 从申请身份到 Workspace 和联系人

以下以本机身份 `zero.ai` 为例；`friend.name` 是对方身份的占位符，执行联系人命令前应替换为实际名称。需要同时安装支持商店安装的新版 `genmeta` 和 Pishoo，并让两者使用同一账户、同一身份目录。不要为已经申请好的身份重复执行 `apply`。

## 1. 申请并启用身份

```sh
genmeta identity apply zero.ai
```

按提示完成身份认证。交互流程询问是否启用服务时默认选“是”；非交互申请目前仍保持关闭。若没有启用，执行：

```sh
genmeta identity ensite --id zero.ai
```

已经运行的 Pishoo 会自动发现身份并应用配置，无需重启。只有尚未运行时才启动：

```sh
# 已安装系统服务时
pishoo start

# 或者，在单独终端运行开发版/前台进程（两者择一）
pishoo
```

`pishoo status` 只报告服务管理器管理的实例；手动运行的开发版不一定出现在其结果中。不要因为它显示未运行，就重复启动第二个进程。

验证身份服务已就绪：

```sh
genmeta nslookup zero.ai~ mdns
genmeta curl --id zero.ai -f https://zero.ai.dhttp.net/std/sys/settings
```

配置应返回 `enabled: true` 和非零 `listen`；`listen = 3` 表示局域网和公网监听。首次加载需要验证凭据和准备 OCSP，保存配置后不保证立即可用。若失败，检查 `~/.dhttp/logs/error.log` 中对应身份的错误。

`nslookup zero.ai` 查询的是普通域名；必须使用 `zero.ai~` 或 `zero.ai.dhttp.net` 才是在查这个身份。需要检查公网地址发布时，用 `genmeta nslookup zero.ai~ h3`；局域网解析成功不等于公网可达。

## 2. 安装 Workspace

对尚未安装 Workspace 的身份执行：

```sh
genmeta install std.dhttp.net/workspace --id zero.ai
```

裸名 `genmeta install workspace` 固定选择标准作者 `std.dhttp.net`；这里写出完整发布者名称，使安装来源明确。Pishoo 会验证包并安装精确版本的 Profile、Message 等 Lib 依赖，无需逐个安装。安装成功会立即更新运行中的应用，无需重启。

检查运行中的包和入口：

```sh
genmeta curl --id zero.ai -f https://zero.ai.dhttp.net/std/sys/app/list
genmeta curl --id zero.ai -f https://zero.ai.dhttp.net/std/sys/lib/list
genmeta curl --id zero.ai -f https://zero.ai.dhttp.net/workspace/
```

Workspace 的入口是 `https://zero.ai.dhttp.net/workspace/`。使用支持 DHTTP 的浏览器/访问环境，并以 `zero.ai` 身份进入自己的工作台；普通浏览器仅有常规 HTTPS 访问能力时，不能据此假定它能访问 DHTTP 服务。`genmeta curl` 可以验证服务，但不会渲染网页。

若已安装另一发布者的同名包，例如 `alice.smith.dhttp.net/workspace`，直接安装 `std.dhttp.net/workspace` 会被同名冲突检查拒绝。先检查现有包；能正常使用的旧包不必为完成后续联系人流程重新安装。迁移发布者需要单独处理现有包及依赖，不能将两条安装命令视为可互换的升级操作。

## 3. 添加联系人

推荐在 Workspace 的联系人页面发起申请，对方在自己的 Workspace 中批准。当前 `genmeta` 没有专门的 `friend add` 命令；命令行通过 `genmeta curl` 调用 Pishoo 的联系人接口。

以下命令会真实发出联系人申请。对方也需要启用身份服务；申请接口会查询对方的能力目录，所以提交时对方需要可达。

```sh
# 在自己的服务上创建出站申请，由本机 Pishoo 负责投递和跟踪
genmeta curl --id zero.ai -f \
  https://zero.ai.dhttp.net/std/contact/local/requests \
  -H 'Content-Type: application/json' \
  -d '{"target_name":"friend.name.dhttp.net","description":"希望添加你为联系人","requested_capabilities":[],"offered_capabilities":[]}'

# 查询申请状态
genmeta curl --id zero.ai -f \
  'https://zero.ai.dhttp.net/std/contact/local/requests?page=1&page_size=20'
```

创建返回 `queued` 仅表示已排队；投递后通常变成 `pending`，对方批准并被本机同步后才是 `active`。检查响应中的 `error_message`，不要反复创建同一申请；已有待处理申请会返回 409。

由对方在自己的设备、以自己的身份执行审批：

```sh
genmeta curl --id friend.name -f \
  https://friend.name.dhttp.net/std/contact/zero.ai.dhttp.net

genmeta curl --id friend.name -f -X PATCH \
  https://friend.name.dhttp.net/std/contact/zero.ai.dhttp.net \
  -H 'Content-Type: application/json' -d '{"status":"active"}'
```

申请方 Pishoo 会自动拉取审批结果，建立本地联系人记录。回到申请方检查：

```sh
genmeta curl --id zero.ai -f \
  https://zero.ai.dhttp.net/std/contact/friend.name.dhttp.net
```

## 4. 联系人和聊天权限分别确认

上面的最小申请使用空能力列表，批准联系人不自动授予聊天或其他业务权限。若要双向聊天，需要双方安装 Message，并各自明确允许对方调用接收消息接口。可以在 Workspace 中选择并审批“1v1 聊天”能力。

纯命令行操作时，先确认双方联系人已同步为 `active`，再分别执行：

```sh
# zero.ai 允许对方向自己发消息；在 zero.ai 的设备执行
genmeta access --id zero.ai /std/message allow friend.name.dhttp.net --method POST

# 对方允许 zero.ai 向自己发消息；在对方的设备执行
genmeta access --id friend.name /std/message allow zero.ai.dhttp.net --method POST
```

实际能力及其接口以各自的 `GET /std/acl/capabilities` 返回值为准。不要把安装成功、申请已排队、联系人批准或单向授权当作双向聊天已完成。

## 本次核对结果（2026-10-15）

- 已实测 `zero.ai` 启用后自动加载，无需重启；配置接口返回 `enabled: true, listen: 3`。
- 已实测运行中的 Workspace、Profile、Message 可查询，`/std/workspace/` 返回 200；旧 `/app/workspace/` 返回 404。已修正安装成功输出的入口地址。
- 商店查询确认 `std.dhttp.net/workspace 0.1.0` 已发布，精确依赖同发布者的 Profile 和 Message `0.1.0`。
- 当前 `zero.ai` 的已安装包来自 `alice.smith.dhttp.net`，不是 `std.dhttp.net`。本次没有覆盖这些包或重新申请身份。
- 联系人队列与能力目录 GET 接口返回 200。申请、审批及双向授权命令已对照服务端实现和 Workspace 调用核对，本次没有向真实联系人提交申请，因此不将其描述为完整端到端实测。
- 非交互申请默认关闭、没有专用联系人 CLI，以及不同发布者的同名包冲突，仍是这条链路的使用门槛。
- 另有配置兼容缺口：当前 `ensite` 只读写 `listen`，未处理新版 Pishoo 独立的 `enabled` 开关。若身份曾通过新版管理界面设为 `enabled=false`，仅执行 `ensite` 可能仍未恢复服务；不能以命令的成功提示代替就绪检查。这不影响本次从旧格式 `listen=0` 启用的 `zero.ai`，但需要后续统一两端配置语义。
