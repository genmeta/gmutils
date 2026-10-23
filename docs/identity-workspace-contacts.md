# 从申请身份到 Workspace 和联系人

以下以本机身份 `alice.smith` 为例；`bob.jones` 是对方身份的占位符，执行联系人命令前应替换为实际名称。需要同时安装支持商店安装的新版 `genmeta` 和 Pishoo，并让两者使用同一账户、同一身份目录。不要为已经申请好的身份重复执行 `apply`。

## 1. 申请并启用身份

```sh
genmeta identity apply alice.smith
```

按提示完成身份认证。交互流程询问是否启用服务时默认选“是”，随后也会询问是否安装 Workspace，直接回车即安装，输入 `n` 跳过。安装需要对应的 Pishoo 服务已经运行并就绪；服务尚未就绪时可按后文手动安装。非交互申请跳过这些确认，不启用服务或安装 Workspace。若没有启用，执行：

```sh
genmeta listen --id alice.smith all
```

已经运行的 Pishoo 会自动发现身份并应用配置，无需重启。只有尚未运行时才启动：

```sh
# macOS 已安装服务时
brew services start pishoo

# Linux 已安装服务时
sudo systemctl start pishoo

# 或者，在单独终端运行开发版/前台进程（两者择一）
pishoo
```

macOS 使用 `brew services info pishoo`、Linux 使用 `systemctl status pishoo` 查看服务状态。前台开发进程需单独检查，避免重复启动。Pishoo 自身只提供运行、reload、帮助和版本命令。

验证身份服务已就绪：

```sh
genmeta nslookup alice.smith~ mdns
genmeta curl --id alice.smith -f https://alice.smith.dhttp.net/std/sys/listen
```

配置应返回字符串 `listen`；`listen = "all"` 表示同时启用内外网监听，`off` 表示停用。首次加载需要验证凭据和准备 OCSP，保存配置后不保证立即可用。若失败，检查 `~/.dhttp/logs/error.log` 中对应身份的错误。

`nslookup alice.smith` 查询的是普通域名；必须使用 `alice.smith~` 或 `alice.smith.dhttp.net` 才是在查这个身份。需要检查公网地址发布时，用 `genmeta nslookup alice.smith~ h3`；局域网解析成功不等于公网可达。

## 2. 安装 Workspace

安装或升级 gmutils 不再自动安装 Workspace。交互申请名字成功后，会询问是否为该名字安装，默认回车即安装；安装使用刚申请的身份，不受默认身份选择影响。拒绝、非交互申请或安装失败时给出手动安装命令，已经完成的身份申请仍然有效，也不后台补装。

申请时跳过安装、Pishoo 尚未就绪，或要为已有身份安装时，执行：

```sh
genmeta install std.dhttp.net/workspace --id alice.smith
```

裸名 `genmeta install workspace` 固定选择标准作者 `std.dhttp.net`；这里写出完整发布者名称，使安装来源明确。Pishoo 会验证包并安装精确版本的 Profile、Message 等 Lib 依赖，无需逐个安装。安装成功会立即更新运行中的应用，无需重启。

检查运行中的包和入口：

```sh
genmeta install --list --id alice.smith
genmeta install --info workspace --id alice.smith
genmeta curl --id alice.smith -f https://alice.smith.dhttp.net/app/workspace/
```

Workspace 的入口是 `https://alice.smith.dhttp.net/app/workspace/`。使用支持 DHTTP 的浏览器/访问环境，并以 `alice.smith` 身份进入自己的工作台；普通浏览器仅有常规 HTTPS 访问能力时，不能据此假定它能访问 DHTTP 服务。`genmeta curl` 可以验证服务，但不会渲染网页。

若已安装另一发布者的同名包，例如 `alice.smith.dhttp.net/workspace`，直接安装 `std.dhttp.net/workspace` 会被同名冲突检查拒绝。先检查现有包；能正常使用的旧包不必为完成后续联系人流程重新安装。迁移发布者需要单独处理现有包及依赖，不能将两条安装命令视为可互换的升级操作。

## 3. 添加联系人

推荐在 Workspace 的联系人页面发起申请，对方在自己的 Workspace 中批准。当前 `genmeta` 没有专门的 `friend add` 命令；命令行通过 `genmeta curl` 调用 Pishoo 的联系人接口。

以下命令会真实发出联系人申请。对方需要启用身份服务才能收到申请。空能力列表可离线排队；选择能力时会核对相关目录，提供权限还需验证对方身份。

```sh
# 在自己的服务上创建出站申请，由本机 Pishoo 负责投递和跟踪
genmeta curl --id alice.smith -f \
  https://alice.smith.dhttp.net/std/contact \
  -H 'Content-Type: application/json' \
  -d '{"from":"alice.smith.dhttp.net","to":"bob.jones.dhttp.net","description":"希望添加你为联系人","requested_capabilities":[],"offered_capabilities":[]}'

# 查询申请状态
genmeta curl --id alice.smith -f \
  'https://alice.smith.dhttp.net/std/contact?name=bob.jones.dhttp.net'
```

创建返回的 `delivery_status: queued` 仅表示已排队；投递后通常为 pending，对方接受且本机同步后为 active。通过同一联系人 GET 查询 status、delivery_status、delivery_error；不要反复创建同一申请，已有待处理申请会返回 409。

由对方在自己的设备、以自己的身份执行审批：

```sh
genmeta curl --id bob.jones -f \
  'https://bob.jones.dhttp.net/std/contact?name=alice.smith.dhttp.net'

genmeta curl --id bob.jones -f -X PATCH \
  'https://bob.jones.dhttp.net/std/contact?name=alice.smith.dhttp.net' \
  -H 'Content-Type: application/json' -d '{"status":"active"}'
```

申请方 Pishoo 会自动拉取审批结果，建立本地联系人记录。回到申请方检查：

```sh
genmeta curl --id alice.smith -f \
  'https://alice.smith.dhttp.net/std/contact?name=bob.jones.dhttp.net'
```

## 4. 联系人和聊天权限分别确认

上面的最小申请使用空能力列表，批准联系人不自动授予聊天或其他业务权限。若要双向聊天，需要双方安装 Message，并各自明确允许对方调用接收消息接口。可以在 Workspace 中选择并审批接收消息能力。

纯命令行操作时，先确认双方联系人已同步为 `active`，再分别执行：

```sh
# alice.smith 允许对方向自己发消息；在 alice.smith 的设备执行
genmeta access --id alice.smith /std/message allow bob.jones.dhttp.net --method PUT

# 对方允许 alice.smith 向自己发消息；在对方的设备执行
genmeta access --id bob.jones /std/message allow alice.smith.dhttp.net --method PUT
```

实际能力及其接口以各自的 `GET /std/acl/permissions` 返回值为准。不要把安装成功、申请已排队、联系人批准或单向授权当作双向聊天已完成。

## 5. 挂载与监听分别管理

```sh
# 查询、添加或更新本地 HTTP 服务挂载
genmeta mount --id alice.smith
genmeta mount --id alice.smith /api http://127.0.0.1:8080/

# 同时匹配路径和上游；脚本删除使用 --yes
genmeta unmount --id alice.smith /api http://127.0.0.1:8080/ --yes

# 停用监听，保留挂载与数据
genmeta listen --id alice.smith off --yes
```

mount 使用 GET/PATCH `/std/sys/mount`；unmount 使用 DELETE 并对 location/proxy_pass 两项做 URL 编码。监听不再混合保存挂载；关闭后用本机 listen 显式恢复。

本文按 2026-10-21 的接口整理。命令示例不代表已执行真实联系人申请、线上安装或双向聊天验收；实际安装版本和权限以目标身份服务返回值为准。
