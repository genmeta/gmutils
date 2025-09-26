# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [0.4.1] - 2025-9-26

### Changed
- 使用genmeta-buildx构建系统自动打包
- genmeta-ssh3和genmeta-curl支持connect timeout参数
- genmeta-ssh3解析命令行-o选项，优先级高于配置文件
- 其他诸多琐碎问题...

### Components
- genmeta v0.4.1
- genmeta-ssh3 v0.4.1
- genmeta-curl v0.3.1

## [0.4.0] - 2025-9-23

### Changed
- 新增genmeta-doctor，genmeta-nat 移入其中作为net子命令
- 新增ssh-config crate用于处理openssh和genmeta配置文件（ssh config语法）
- genmeta-ssh3h和curl支持--id参数携带身份，解析profile身份配置文件，发起带有client name参数和tls证书的quic连接
- 重构了错误处理，使用snafu::report宏自动打印错误栈
- 修复tracing初始化方式和默认日志级别

### Components
- genmeta v0.4.0 ?
- genmeta-ssh3 v0.4.0 ?
- genmeta-curl v0.2.0 ?
- genmeta-doctor v0.1.0
- ssh-config v0.1.0

## [0.3.2] - 2025-7-30

### Changed
- ssh3支持了windows平台

### Components
- genmeta v0.3.2
- genmeta-ssh3 v0.3.1

## [0.3.1] - 2025-7-30

### Changed
- 依赖：更新gm-quic-traversal，适配windows

### Components
- genmeta v0.3.1

## [0.3.0] - 2025-07-29

### Changed
- 依赖：适配gm-quic-traversal v0.3
- 新增：nat探测工具
- 重构：将tracing_subscriber初始化交给子模块
- 重构：结构化ssh3和ssh3-proto的错误
- 重构：优化ssh3的命令行参数解析
- 重构：修复ssh3-proto的一些typo

### Components
- genmeta v0.3.0
- genmeta-ssh3 v0.3.0
- genmeta-curl v0.1.6
- genmeta-nslookup v0.1.3
- genmeta-discover v0.1.2
- genmeta-nat v0.1.0
- ssh3-proto v0.2.0

## [0.2.8] - 2025-06-26

### Changed
- 重构：将 genmeta-request 重命名为 genmeta-curl，更好地反映工具的用途
- genmeta-nslookup: 优化输出格式，提升可读性
- genmeta-discover: 优化输出格式，提升可读性

### Fixed
- genmeta-nslookup: DNS 结果去重，避免重复显示
- genmeta-discover: DNS 结果去重，避免重复显示

### Components
- genmeta v0.2.8
- genmeta-ssh3 v0.2.7
- genmeta-curl v0.1.4 (formerly genmeta-request)
- genmeta-nslookup v0.1.2
- genmeta-discover v0.1.1

## [0.2.7] - 2025-06-11

### Added
- ssh3, request, nslookup 支持使用~省略.genmeta.net

### Changed
- 更新依赖，提升打洞能力

### Components
- genmeta v0.2.7
- genmeta-ssh3 v0.2.7  
- genmeta-request v0.1.4
- genmeta-nslookup v0.1.1

## [0.2.6] - 2025-06-04

### Added
- 新工具：genmeta-nslookup，支持DNS查询
- 新工具：genmeta-discover，支持发现局域网中的设备（mdns）
- genmeta-ssh3 和 genmeta-request 支持 http dns 和 mdns 解析

### Components
- genmeta v0.2.6
- genmeta-ssh3 v0.2.6
- genmeta-request v0.1.3
- genmeta-nslookup v0.1.0
- genmeta-discover v0.1.0

## [0.2.5] - 2025-05-30

### Added
- request 发送请求时设置 http 版本为 h3
- request 发送请求时设置 Host, User-Agent, Accept 头
- ssh 支持 -l（登录用户名）选项，更好支持 rsync

### Fixed
- ssh 修复进程退出时没有恢复终端

### Components
- genmeta v0.2.5
- genmeta-ssh3 v0.2.5
- genmeta-request v0.1.2

## [0.2.4] - 2025-05-26

### Added
- 提取 gateway 和 gmutils 关于 ssh 协议的共通代码
- 支持本地转发和远程转发，整理动态转发
- 发送心跳保活包保持连接活跃
- session 结束时结束程序
- server 返回进程退出的状态码

### Components
- genmeta v0.2.4
- genmeta-ssh3 v0.2.4
- ssh3-proto v0.1.0

## [0.2.3] - 2025-05-21

### Changed
- 自己实现配置解析而不是使用 ssh_config（修复了难以交叉编译的问题）
- 跟进 gm-quic-traversal 更新

### Components
- genmeta v0.2.3
- genmeta-ssh3 v0.2.3

## [0.2.2] - 2025-05-19

### Added
- 支持加载系统 ssh 配置文件
- 将 fake-ssh.sh（genmeta-ssh3.sh）打包进 deb

### Fixed
- 修复 mux 不正确退出，收包完全惰性的问题

### Components
- genmeta v0.2.2
- genmeta-ssh3 v0.2.2

## [0.2.1] - 2025-05-19

### Added
- 加上了这个 changelog

### Changed
- 优化 mux 的行为，更贴近标准的 ssh，只有多路复用的所有Channel结束ssh才结束
- 优化了日志打印
- 让 ssh 不处理 heredoc

### Components
- genmeta v0.2.1
- genmeta-ssh3 v0.2.1

## [0.2.0] - 2025-05-17

### Changed
- 完全重写 ssh

### Components
- genmeta v0.2

