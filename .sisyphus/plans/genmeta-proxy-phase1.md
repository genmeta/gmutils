# genmeta-proxy Phase 1

## TL;DR

> **Quick Summary**: Build `genmeta-proxy`, a forward HTTP/1.1 proxy that routes `.genmeta.net` plain HTTP requests through H3 via h3x, returns 502 for `.genmeta.net` CONNECT, standard TCP tunnel for non-genmeta CONNECT, and standard HTTP forwarding for non-genmeta plain HTTP.
>
> **Deliverables**: New `genmeta-proxy` crate registered in workspace
> **Estimated Effort**: Medium
> **Parallel Execution**: YES - 4 waves
> **Critical Path**: Task 1 → Task 2 → Task 5 → Task 7 → Task 8

---

## Context

### Original Request
在 gmutils 工作区中新建 `genmeta-proxy` CLI crate，一个正向代理工具，将 HTTP/1.1 请求根据域名后缀 `.genmeta.net` 条件性地转发为 DHTTP/3 请求。

### Interview Summary
- .genmeta.net 服务器是纯 HTTP/3 (QUIC only)，完全没有 TCP listener
- Phase 1: 4 种请求分支处理（genmeta+plain→H3, genmeta+CONNECT→502, other+CONNECT→tunnel, other+plain→forward）
- Phase 2 (future): MITM TLS 拦截 — 本阶段不实现但代码结构需预留
- 技术选型: 仅 HTTP/1.1 入站, hyper client 处理非 genmeta 转发
- 遵循现有 crate 模式 (genmeta-curl 为参考)

### Key API Discovery
- 使用 `Connection::execute_hyper_request()` (h3x/src/hyper/client.rs:67) 而非 `new_request().execute()`
- 该 API 接受 `http::Request<B: Body>` 返回 `http::Response<impl Body>`, 自动处理 hyper body → H3 body 流式转换
- H3Client 内置连接池 (Pool), 无需额外池化

---

## Work Objectives

### Core Objective
实现一个 HTTP/1.1 正向代理，能根据目标域名将请求路由到 H3 或标准 HTTP 转发。

### Concrete Deliverables
- `genmeta-proxy/` crate with Cargo.toml, src/main.rs, src/lib.rs, src/route.rs, src/h3_forward.rs, src/tunnel.rs
- Workspace registration (root Cargo.toml + genmeta dispatcher)

### Must Have
- 域名后缀 `.genmeta.net` 路由判定
- Plain HTTP → H3 转发 (genmeta domains)
- CONNECT → 502 (genmeta domains, Phase 2 placeholder)
- CONNECT → TCP tunnel (non-genmeta domains)
- Plain HTTP → hyper client forwarding (non-genmeta domains)
- CLI 参数: listen addr, identity, DNS schemes, bind interfaces, verbose
- 与 genmeta-curl 一致的 identity/DNS/bind 初始化流程

### Must NOT Have (Guardrails)
- 不实现 MITM TLS 拦截 (Phase 2)
- 不实现 HTTP/2 入站
- 不使用 reqwest (非 genmeta 转发用 hyper client)
- 不引入额外连接池 (h3x 内置)
- 不实现黑名单过滤逻辑 (仅预留接口/字段)
- 不添加过度的注释或文档

---

## Verification Strategy

> **ZERO HUMAN INTERVENTION** — ALL verification is agent-executed.

### Test Decision
- **Infrastructure exists**: YES (cargo test)
- **Automated tests**: NO (网络代理难以单元测试, 依赖 QA 场景验证)
- **Framework**: cargo test (仅用于 route.rs 的域名匹配单元测试)

### QA Policy
- 每个任务包含 agent-executed QA scenarios
- Frontend/UI: N/A
- CLI: `cargo build -p genmeta-proxy`, `cargo check`
- 集成: 启动代理 → curl 通过代理请求 → 验证响应

---

## Execution Strategy

### Parallel Execution Waves

```
Wave 1 (Foundation — can start immediately):
├── Task 1: Crate scaffolding + workspace registration [quick]
├── Task 2: CLI Options + Error enum + tracing init [quick]
└── Task 3: Domain routing module (route.rs) [quick]

Wave 2 (Core modules — after Wave 1):
├── Task 4: TCP tunnel for CONNECT (tunnel.rs) [unspecified-high]
├── Task 5: H3 forwarding for genmeta (h3_forward.rs) [deep]
└── Task 6: Standard HTTP forwarding for non-genmeta [unspecified-high]

Wave 3 (Integration — after Wave 2):
└── Task 7: Main proxy server loop + handler wiring (lib.rs run()) [deep]

Wave 4 (Registration + QA — after Wave 3):
├── Task 8: Register in genmeta dispatcher [quick]
└── Task 9: Integration QA [unspecified-high]

Wave FINAL (Review — after ALL tasks):
├── F1: Plan compliance audit [oracle]
├── F2: Code quality review [unspecified-high]
├── F3: Real manual QA [unspecified-high]
└── F4: Scope fidelity check [deep]
```

### Dependency Matrix
- **1**: None → 2, 3
- **2**: 1 → 4, 5, 6, 7
- **3**: 1 → 7
- **4**: 2 → 7
- **5**: 2 → 7
- **6**: 2 → 7
- **7**: 3, 4, 5, 6 → 8, 9
- **8**: 7 → F*
- **9**: 7 → F*

### Agent Dispatch Summary
- **Wave 1**: 3 tasks — T1 `quick`, T2 `quick`, T3 `quick`
- **Wave 2**: 3 tasks — T4 `unspecified-high`, T5 `deep`, T6 `unspecified-high`
- **Wave 3**: 1 task — T7 `deep`
- **Wave 4**: 2 tasks — T8 `quick`, T9 `unspecified-high`
- **FINAL**: 4 tasks — F1 `oracle`, F2 `unspecified-high`, F3 `unspecified-high`, F4 `deep`

## TODOs


- [x] 1. Crate scaffolding + workspace registration

  **What to do**:
  - Create `genmeta-proxy/Cargo.toml` with dependencies: clap, genmeta-common (features: bind, dns, id, error), genmeta-home, h3x, http, hyper (features: http1, server), hyper-util (features: tokio), http-body-util, bytes, snafu, tokio, tracing, tracing-subscriber, tracing-appender
  - Add `hyper = { version = "1", features = ["http1", "server"] }` and `hyper-util = { version = "0.1", features = ["tokio"] }` and `http-body-util = "0.1"` to workspace dependencies in root Cargo.toml if not already present
  - Add `"genmeta-proxy"` to workspace members in root Cargo.toml
  - Add `genmeta-proxy = { path = "genmeta-proxy" }` to workspace dependencies
  - Create minimal `src/main.rs` following genmeta-curl pattern (parse + run + inspect_err)
  - Create minimal `src/lib.rs` with empty `Options` struct and stub `run()` that just inits tracing
  - Verify `cargo check -p genmeta-proxy` passes

  **Must NOT do**:
  - Do NOT register in genmeta dispatcher yet (Task 8)
  - Do NOT add reqwest as dependency

  **Recommended Agent Profile**:
  - **Category**: `quick`
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES (Wave 1, with Tasks 2, 3)
  - **Blocks**: Tasks 2, 3
  - **Blocked By**: None

  **References**:
  - `genmeta-curl/Cargo.toml` — dependency pattern to follow
  - `genmeta-curl/src/main.rs` — exact main.rs pattern (10 lines)
  - `Cargo.toml:3-14` — workspace members list (add "genmeta-proxy")
  - `Cargo.toml:16-98` — workspace dependencies (add hyper/hyper-util/http-body-util if missing, add genmeta-proxy)

  **Acceptance Criteria**:
  - [ ] `cargo check -p genmeta-proxy` passes
  - [ ] `genmeta-proxy` appears in workspace members

  **QA Scenarios**:
  ```
  Scenario: Crate compiles successfully
    Tool: Bash
    Steps:
      1. Run `cargo check -p genmeta-proxy`
      2. Assert exit code 0
    Expected Result: No errors
    Evidence: .sisyphus/evidence/task-1-cargo-check.txt
  ```

  **Commit**: YES
  - Message: `feat(proxy): scaffold genmeta-proxy crate with workspace registration`
  - Pre-commit: `cargo check -p genmeta-proxy`

- [ ] 2. CLI Options + Error enum + tracing init

  **What to do**:
  - In `src/lib.rs`, define `Options` struct with clap derive:
    - `--listen <addr>` (default `127.0.0.1:8080`): proxy listen address (SocketAddr)
    - `--id <name>`: client identity (Option<Name<'static>>)
    - `--dns <scheme>` (default `system, mdns, http`): DNS resolution schemes (Vec<dns::DnsScheme>)
    - `--interface <bind>` (default `*`): bind patterns (Vec<bind::Bind>)
    - `--verbose` / `-v`: verbose output (bool)
    - `--domain-suffix <suffix>` (default `.genmeta.net`): domain suffixes for H3 routing (Vec<String>), reserved for future extensibility
  - Define `Error` enum with snafu following genmeta-curl pattern, initially including:
    - LocateGenmetaHome (transparent)
    - BindConflict (transparent)
    - BuildDnsResolvers
    - BuildClient
    - Whatever (transparent, for dynamic errors)
  - Implement `snafu::FromString for Error` (for whatever! support)
  - In `run()`: init tracing, load identity, setup bind interfaces, build DNS resolvers, build H3Client — same flow as genmeta-curl
  - After building client: create TcpListener on `options.listen`, log listening address
  - Accept loop stub: accept connections, log, drop (actual handling in Task 7)

  **Must NOT do**:
  - Do NOT implement request handling logic yet
  - Do NOT implement any forwarding or tunneling

  **Recommended Agent Profile**:
  - **Category**: `quick`
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES (Wave 1, with Tasks 1, 3)
  - **Blocks**: Tasks 4, 5, 6, 7
  - **Blocked By**: Task 1 (needs Cargo.toml)

  **References**:
  - `genmeta-curl/src/lib.rs:28-104` — Options struct pattern (clap derive, dns/bind/id fields)
  - `genmeta-curl/src/lib.rs:106-173` — Error enum pattern with snafu
  - `genmeta-curl/src/lib.rs:195-244` — run() init pattern (tracing, identity, bind, dns, H3Client build)
  - `genmeta-common` features: `bind`, `dns`, `id`, `error` — same as genmeta-curl
  - `h3x/src/gm_quic/client.rs` — H3Client builder API

  **Acceptance Criteria**:
  - [ ] `cargo check -p genmeta-proxy` passes
  - [ ] Options struct has all 6 CLI fields
  - [ ] Error enum has all initial variants + FromString impl
  - [ ] run() initializes tracing, identity, bind, dns, H3Client, and starts TCP listener

  **QA Scenarios**:
  ```
  Scenario: Binary starts and listens
    Tool: interactive_bash (tmux)
    Steps:
      1. Start `cargo run -p genmeta-proxy -- --listen 127.0.0.1:18080` in background
      2. Wait 3s for startup
      3. Check process is running and port is bound: `ss -tlnp | grep 18080`
      4. Kill the process
    Expected Result: Process listening on port 18080
    Evidence: .sisyphus/evidence/task-2-listen.txt

  Scenario: Help text shows all options
    Tool: Bash
    Steps:
      1. Run `cargo run -p genmeta-proxy -- --help`
      2. Assert output contains: --listen, --id, --dns, --interface, --verbose, --domain-suffix
    Expected Result: All 6 options visible in help text
    Evidence: .sisyphus/evidence/task-2-help.txt
  ```

  **Commit**: YES
  - Message: `feat(proxy): add CLI options, error types, and server initialization`
  - Pre-commit: `cargo check -p genmeta-proxy`


- [ ] 3. Domain routing module (route.rs)

  **What to do**:
  - Create `src/route.rs` with a `Router` struct holding `domain_suffixes: Vec<String>` and a reserved `_blacklist: Vec<String>` field (unused in Phase 1)
  - Implement `Router::new(suffixes: Vec<String>) -> Self`
  - Implement `Router::is_genmeta(&self, host: &str) -> bool` — check if host (without port) ends with any configured suffix
  - Implement `classify(&self, req: &Request<Incoming>) -> Route` where `Route` is an enum:
    - `GenmetaPlainHttp { authority, uri }` — plain HTTP to genmeta domain
    - `GenmetaConnect { authority }` — CONNECT to genmeta domain (502 in Phase 1)
    - `TunnelConnect { authority }` — CONNECT to non-genmeta domain
    - `StandardForward { uri }` — plain HTTP to non-genmeta domain
  - Add unit tests for `is_genmeta()` (various suffix matches, non-matches, with/without port)
  - Add `mod route;` to lib.rs

  **Must NOT do**:
  - Do NOT implement blacklist filtering logic (just reserve the field)

  **Recommended Agent Profile**:
  - **Category**: `quick`
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES (Wave 1, with Tasks 1, 2)
  - **Blocks**: Task 7
  - **Blocked By**: Task 1 (needs crate to exist)

  **References**:
  - `genmeta-curl/src/lib.rs:20` — `http::Uri` usage
  - hyper `Request<Incoming>` — request.method() for CONNECT detection, request.uri() for host extraction

  **Acceptance Criteria**:
  - [ ] `cargo test -p genmeta-proxy` passes with route unit tests
  - [ ] Route enum has all 4 variants
  - [ ] is_genmeta correctly matches `.genmeta.net` suffix

  **QA Scenarios**:
  ```
  Scenario: Domain suffix matching
    Tool: Bash
    Steps:
      1. Run `cargo test -p genmeta-proxy -- route`
      2. Assert all tests pass
    Expected Result: All route unit tests pass
    Evidence: .sisyphus/evidence/task-3-route-tests.txt
  ```

  **Commit**: YES
  - Message: `feat(proxy): add domain routing module with suffix matching`
  - Pre-commit: `cargo test -p genmeta-proxy`

- [ ] 4. TCP tunnel for CONNECT (tunnel.rs)

  **What to do**:
  - Create `src/tunnel.rs`
  - Implement `pub async fn tunnel_connect(req: Request<Incoming>, addr: &str) -> Result<Response<...>, Error>` that:
    1. Extracts host:port from request URI authority
    2. Spawns a tokio task that:
       a. Calls `hyper::upgrade::on(req)` to get the upgraded connection
       b. Connects to target via `TcpStream::connect(addr)`
       c. Uses `tokio::io::copy_bidirectional` between upgraded and TcpStream
    3. Returns an empty `200 OK` response to signal tunnel established
  - Use `hyper_util::rt::TokioIo` for wrapping the upgraded connection
  - Add appropriate Error variants to lib.rs Error enum
  - Add `mod tunnel;` to lib.rs

  **Must NOT do**:
  - Do NOT handle genmeta CONNECT (that's a 502, handled in Task 7)

  **Recommended Agent Profile**:
  - **Category**: `unspecified-high`
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES (Wave 2, with Tasks 5, 6)
  - **Blocks**: Task 7
  - **Blocked By**: Task 2 (needs Error enum)

  **References**:
  - hyper proxy example pattern: `hyper::upgrade::on(req)` → `tokio::io::copy_bidirectional`
  - `hyper_util::rt::TokioIo` for wrapping Upgraded
  - `genmeta-curl/src/lib.rs:106-173` — Error enum pattern for adding new variants

  **Acceptance Criteria**:
  - [ ] `cargo check -p genmeta-proxy` passes
  - [ ] tunnel_connect function compiles with correct signature
  - [ ] Uses hyper upgrade + copy_bidirectional pattern

  **QA Scenarios**:
  ```
  Scenario: Tunnel module compiles
    Tool: Bash
    Steps:
      1. Run `cargo check -p genmeta-proxy`
      2. Assert exit code 0
    Expected Result: No compilation errors
    Evidence: .sisyphus/evidence/task-4-check.txt
  ```

  **Commit**: YES
  - Message: `feat(proxy): add TCP tunnel for CONNECT requests`
  - Pre-commit: `cargo check -p genmeta-proxy`

- [ ] 5. H3 forwarding for genmeta domains (h3_forward.rs)

  **What to do**:
  - Create `src/h3_forward.rs`
  - Implement `pub async fn forward_h3(req: Request<Incoming>, client: &H3Client) -> Result<Response<impl Body>, Error>` that:
    1. Extracts authority from request URI
    2. Calls `client.connect(authority)` to get/reuse a connection (h3x pools internally)
    3. Calls `connection.execute_hyper_request(req)` — this takes the full `http::Request<Incoming>` and returns `http::Response<impl Body>`, handling body streaming automatically
    4. Returns the H3 response
  - Map the response body type appropriately for hyper to send back to proxy client
  - Add Error variants: Connect, ExecuteRequest
  - Add `mod h3_forward;` to lib.rs

  **Must NOT do**:
  - Do NOT manually stream request/response body chunks — `execute_hyper_request` handles this
  - Do NOT implement a custom connection pool — h3x Pool is built-in

  **Recommended Agent Profile**:
  - **Category**: `deep`
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES (Wave 2, with Tasks 4, 6)
  - **Blocks**: Task 7
  - **Blocked By**: Task 2 (needs H3Client setup)

  **References**:
  - `h3x/src/hyper/client.rs:67-100` — `execute_hyper_request` full implementation. Takes `http::Request<B: Body>`, returns `http::Response<impl Body>`. This is THE key API.
  - `h3x/src/client.rs` — `Client::connect(authority)` → `Arc<Connection>`
  - `h3x/src/pool.rs` — Pool internals (DashMap, auto-cleanup). No manual pool management needed.
  - `genmeta-curl/src/lib.rs:251-260` — connect + timeout pattern
  - `h3x/tests/axum.rs:42-98` — execute_hyper_request usage examples

  **Acceptance Criteria**:
  - [ ] `cargo check -p genmeta-proxy` passes
  - [ ] forward_h3 uses `execute_hyper_request` (NOT manual stream read/write)
  - [ ] No custom connection pool code

  **QA Scenarios**:
  ```
  Scenario: H3 forward module compiles
    Tool: Bash
    Steps:
      1. Run `cargo check -p genmeta-proxy`
      2. Assert exit code 0
    Expected Result: No compilation errors
    Evidence: .sisyphus/evidence/task-5-check.txt
  ```

  **Commit**: YES
  - Message: `feat(proxy): add H3 forwarding for genmeta domains via execute_hyper_request`
  - Pre-commit: `cargo check -p genmeta-proxy`

- [ ] 6. Standard HTTP forwarding for non-genmeta (plain HTTP)

  **What to do**:
  - Implement in `src/lib.rs` or a new `src/forward.rs` module:
  - `pub async fn forward_http(req: Request<Incoming>) -> Result<Response<Incoming>, Error>` that:
    1. Extracts host:port from request URI
    2. Connects to target via `TcpStream::connect(addr)`
    3. Creates hyper HTTP/1.1 client connection: `hyper::client::conn::http1::handshake(TokioIo::new(stream))`
    4. Sends the request via `sender.send_request(req)`
    5. Returns the response
  - Spawn the connection task in background (hyper requires polling the connection)
  - Add Error variants: TcpConnect, Handshake, SendRequest
  - Add `mod forward;` to lib.rs if using separate file

  **Must NOT do**:
  - Do NOT use reqwest
  - Do NOT implement HTTP/2 client connections
  - Do NOT implement connection pooling for outbound HTTP (simple per-request connection is fine for Phase 1)

  **Recommended Agent Profile**:
  - **Category**: `unspecified-high`
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES (Wave 2, with Tasks 4, 5)
  - **Blocks**: Task 7
  - **Blocked By**: Task 2 (needs Error enum)

  **References**:
  - hyper HTTP/1 client example: `hyper::client::conn::http1::handshake(io)` → `(sender, connection)`, `tokio::spawn(connection)`, `sender.send_request(req)`
  - `hyper_util::rt::TokioIo` for wrapping TcpStream
  - `genmeta-curl/src/lib.rs:106-173` — Error enum pattern

  **Acceptance Criteria**:
  - [ ] `cargo check -p genmeta-proxy` passes
  - [ ] Uses `hyper::client::conn::http1::handshake` (NOT reqwest)
  - [ ] Request method, headers, body all forwarded

  **QA Scenarios**:
  ```
  Scenario: Forward module compiles
    Tool: Bash
    Steps:
      1. Run `cargo check -p genmeta-proxy`
      2. Assert exit code 0
    Expected Result: No compilation errors
    Evidence: .sisyphus/evidence/task-6-check.txt
  ```

  **Commit**: YES
  - Message: `feat(proxy): add standard HTTP forwarding via hyper client`
  - Pre-commit: `cargo check -p genmeta-proxy`

- [ ] 7. Main proxy server loop + handler wiring (lib.rs run())

  **What to do**:
  - In `run()`, after H3Client build and TcpListener bind, implement the accept loop:
    1. For each accepted TCP connection, spawn a tokio task
    2. Use `hyper::server::conn::http1::Builder::new()` with `.preserve_header_case(true).title_case_headers(true)`
    3. Call `.serve_connection(TokioIo::new(stream), service_fn(handler)).with_upgrades()` to support CONNECT
  - Implement `handler(req: Request<Incoming>) -> Result<Response<...>, ...>` that:
    1. Calls `router.classify(&req)` to determine route
    2. Match on Route:
       - `GenmetaPlainHttp` → call `h3_forward::forward_h3(req, &client)`
       - `GenmetaConnect` → return `Response::builder().status(502).body("HTTPS proxy to .genmeta.net not supported in Phase 1")`
       - `TunnelConnect` → call `tunnel::tunnel_connect(req, &addr)`
       - `StandardForward` → call `forward::forward_http(req)`
    3. Log each request (method, URI, route decision) via tracing
  - Share state (H3Client, Router) via `Arc` passed into the handler closure
  - Handle errors gracefully: return 502/500 responses instead of panicking

  **Must NOT do**:
  - Do NOT implement HTTP/2 inbound
  - Do NOT implement MITM for GenmetaConnect (just 502)

  **Recommended Agent Profile**:
  - **Category**: `deep`
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: NO (Wave 3, sequential)
  - **Blocks**: Tasks 8, 9
  - **Blocked By**: Tasks 3, 4, 5, 6

  **References**:
  - hyper proxy example pattern: `http1::Builder::new().preserve_header_case(true).title_case_headers(true).serve_connection(io, service_fn(handler)).with_upgrades()`
  - `genmeta-curl/src/lib.rs:195-352` — run() function structure
  - `src/route.rs` (Task 3) — Router::classify() + Route enum
  - `src/h3_forward.rs` (Task 5) — forward_h3()
  - `src/tunnel.rs` (Task 4) — tunnel_connect()
  - `src/forward.rs` (Task 6) — forward_http()

  **Acceptance Criteria**:
  - [ ] `cargo check -p genmeta-proxy` passes
  - [ ] All 4 route branches implemented
  - [ ] hyper server uses http1::Builder with preserve_header_case + with_upgrades
  - [ ] Handler logs each request via tracing
  - [ ] Errors return HTTP error responses, not panics

  **QA Scenarios**:
  ```
  Scenario: Proxy starts and accepts connections
    Tool: interactive_bash (tmux)
    Steps:
      1. Start `cargo run -p genmeta-proxy -- --listen 127.0.0.1:18080` in background
      2. Wait 3s
      3. Run `curl -x http://127.0.0.1:18080 http://example.com/ -v 2>&1`
      4. Assert response contains HTML or redirect (non-empty response from example.com)
      5. Kill proxy
    Expected Result: Proxy forwards plain HTTP to non-genmeta domain successfully
    Evidence: .sisyphus/evidence/task-7-plain-forward.txt

  Scenario: CONNECT tunnel to non-genmeta works
    Tool: interactive_bash (tmux)
    Steps:
      1. Start proxy on 127.0.0.1:18080
      2. Run `curl -x http://127.0.0.1:18080 https://example.com/ -v 2>&1`
      3. Assert response contains HTML (CONNECT tunnel established, TLS handshake through tunnel)
      4. Kill proxy
    Expected Result: HTTPS request via CONNECT tunnel succeeds
    Evidence: .sisyphus/evidence/task-7-tunnel.txt

  Scenario: CONNECT to genmeta domain returns 502
    Tool: interactive_bash (tmux)
    Steps:
      1. Start proxy on 127.0.0.1:18080
      2. Run `curl -x http://127.0.0.1:18080 https://test.genmeta.net/ -v 2>&1`
      3. Assert response status is 502
      4. Kill proxy
    Expected Result: 502 response for CONNECT to .genmeta.net
    Evidence: .sisyphus/evidence/task-7-genmeta-502.txt
  ```

  **Commit**: YES
  - Message: `feat(proxy): wire main proxy server loop with 4-branch request handler`
  - Pre-commit: `cargo check -p genmeta-proxy`

- [ ] 8. Register in genmeta dispatcher

  **What to do**:
  - Add `genmeta-proxy = { workspace = true }` to `genmeta/Cargo.toml` dependencies
  - In `genmeta/src/main.rs`:
    1. Add `Proxy(genmeta_proxy::Options)` variant to Options enum
    2. Add `Proxy { source: genmeta_proxy::Error }` to Error enum (transparent)
    3. Add `Options::Proxy(options) => genmeta_proxy::run(options).await?` to match arm in run()
  - Verify `cargo check -p genmeta` passes

  **Must NOT do**:
  - Do NOT change any other dispatcher entries

  **Recommended Agent Profile**:
  - **Category**: `quick`
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES (Wave 4, with Task 9)
  - **Blocks**: Final verification
  - **Blocked By**: Task 7

  **References**:
  - `genmeta/src/main.rs:6-18` — Options enum (add Proxy variant after Nslookup)
  - `genmeta/src/main.rs:21-37` — Error enum (add Proxy transparent variant)
  - `genmeta/src/main.rs:47-56` — run() match (add Proxy arm)
  - `genmeta/Cargo.toml:9-20` — dependencies (add genmeta-proxy)

  **Acceptance Criteria**:
  - [ ] `cargo check -p genmeta` passes
  - [ ] `cargo run -p genmeta -- proxy --help` shows proxy help

  **QA Scenarios**:
  ```
  Scenario: Proxy accessible via main genmeta binary
    Tool: Bash
    Steps:
      1. Run `cargo run -p genmeta -- proxy --help`
      2. Assert output contains --listen, --dns, --interface
    Expected Result: Proxy subcommand registered and shows help
    Evidence: .sisyphus/evidence/task-8-genmeta-proxy-help.txt
  ```

  **Commit**: YES
  - Message: `feat(genmeta): register proxy subcommand in main dispatcher`
  - Pre-commit: `cargo check -p genmeta`

- [ ] 9. Integration QA

  **What to do**:
  - Run full integration tests of the proxy:
    1. Start proxy with identity (if available) and DNS configured
    2. Test all 4 request branches end-to-end
    3. Verify logging output shows correct route decisions
    4. Test error handling (invalid URIs, unreachable hosts)
  - Fix any issues found during integration testing

  **Must NOT do**:
  - Do NOT add new features
  - Do NOT refactor existing code (only bug fixes)

  **Recommended Agent Profile**:
  - **Category**: `unspecified-high`
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES (Wave 4, with Task 8)
  - **Blocks**: Final verification
  - **Blocked By**: Task 7

  **References**:
  - All proxy source files: src/lib.rs, src/route.rs, src/h3_forward.rs, src/tunnel.rs, src/forward.rs
  - QA scenarios from Tasks 7 for test patterns

  **Acceptance Criteria**:
  - [ ] All 4 proxy branches work end-to-end
  - [ ] `cargo build -p genmeta-proxy` succeeds in release mode check
  - [ ] No panics on malformed requests

  **QA Scenarios**:
  ```
  Scenario: Plain HTTP to non-genmeta
    Tool: interactive_bash (tmux)
    Steps:
      1. Start proxy: `cargo run -p genmeta-proxy -- --listen 127.0.0.1:18080`
      2. `curl -x http://127.0.0.1:18080 http://httpbin.org/get -s | head -20`
      3. Assert JSON response with "url": "http://httpbin.org/get"
    Expected Result: Response body is valid JSON from httpbin
    Evidence: .sisyphus/evidence/task-9-plain-http.txt

  Scenario: CONNECT tunnel to non-genmeta
    Tool: interactive_bash (tmux)
    Steps:
      1. Start proxy
      2. `curl -x http://127.0.0.1:18080 https://httpbin.org/get -s | head -20`
      3. Assert JSON response with "url": "https://httpbin.org/get"
    Expected Result: HTTPS via CONNECT tunnel works
    Evidence: .sisyphus/evidence/task-9-connect-tunnel.txt

  Scenario: CONNECT to genmeta returns 502
    Tool: interactive_bash (tmux)
    Steps:
      1. Start proxy
      2. `curl -x http://127.0.0.1:18080 https://any.genmeta.net/ -v 2>&1`
      3. Assert 502 status in output
    Expected Result: 502 Bad Gateway
    Evidence: .sisyphus/evidence/task-9-genmeta-connect-502.txt

  Scenario: Malformed request handling
    Tool: interactive_bash (tmux)
    Steps:
      1. Start proxy
      2. `echo -e "GET / HTTP/1.1\r\nHost: \r\n\r\n" | nc 127.0.0.1 18080`
      3. Assert proxy does not crash (check process still running)
    Expected Result: Proxy stays alive, returns error response
    Evidence: .sisyphus/evidence/task-9-malformed.txt
  ```

  **Commit**: YES
  - Message: `test(proxy): integration QA pass - all 4 proxy branches verified`
  - Pre-commit: `cargo check -p genmeta-proxy`
---

## Final Verification Wave


- [ ] F1. **Plan Compliance Audit** — `oracle`
  Read the plan end-to-end. For each "Must Have": verify implementation exists (read file, run command). For each "Must NOT Have": search codebase for forbidden patterns. Check evidence files exist in .sisyphus/evidence/.
  Output: `Must Have [N/N] | Must NOT Have [N/N] | Tasks [N/N] | VERDICT: APPROVE/REJECT`

- [ ] F2. **Code Quality Review** — `unspecified-high`
  Run `cargo clippy -p genmeta-proxy` + `cargo fmt --check -p genmeta-proxy` + `cargo test -p genmeta-proxy`. Review all files for: `unwrap()` in production paths, empty catches, commented-out code, unused imports. Check error messages follow AGENTS.md conventions (lowercase, no period, backtick-quoted values).
  Output: `Clippy [PASS/FAIL] | Fmt [PASS/FAIL] | Tests [N pass/N fail] | Files [N clean/N issues] | VERDICT`

- [ ] F3. **Real Manual QA** — `unspecified-high`
  Start from clean state. Execute EVERY QA scenario from EVERY task — follow exact steps. Test cross-task integration (proxy handling mixed traffic). Save to `.sisyphus/evidence/final-qa/`.
  Output: `Scenarios [N/N pass] | Integration [N/N] | VERDICT`

- [ ] F4. **Scope Fidelity Check** — `deep`
  For each task: read "What to do", read actual diff (git log/diff). Verify 1:1 — everything in spec was built, nothing beyond spec. Check "Must NOT do" compliance. Detect cross-task contamination.
  Output: `Tasks [N/N compliant] | Contamination [CLEAN/N issues] | VERDICT`

---

## Commit Strategy


- **T1**: `feat(proxy): scaffold genmeta-proxy crate with workspace registration`
- **T2**: `feat(proxy): add CLI options, error types, and server initialization`
- **T3**: `feat(proxy): add domain routing module with suffix matching`
- **T4**: `feat(proxy): add TCP tunnel for CONNECT requests`
- **T5**: `feat(proxy): add H3 forwarding for genmeta domains via execute_hyper_request`
- **T6**: `feat(proxy): add standard HTTP forwarding via hyper client`
- **T7**: `feat(proxy): wire main proxy server loop with 4-branch request handler`
- **T8**: `feat(genmeta): register proxy subcommand in main dispatcher`
- **T9**: `test(proxy): integration QA pass - all 4 proxy branches verified`

---

## Success Criteria


### Verification Commands
```bash
cargo check -p genmeta-proxy   # Expected: success
cargo test -p genmeta-proxy    # Expected: route tests pass
cargo clippy -p genmeta-proxy  # Expected: no warnings
cargo check -p genmeta         # Expected: dispatcher compiles
cargo run -p genmeta -- proxy --help  # Expected: shows all CLI options
```

### Final Checklist
- [ ] All "Must Have" items present and functional
- [ ] All "Must NOT Have" items absent from codebase
- [ ] All 4 proxy branches work (plain HTTP genmeta→H3, CONNECT genmeta→502, CONNECT other→tunnel, plain HTTP other→forward)
- [ ] Proxy registered in genmeta dispatcher
- [ ] Code follows existing crate patterns (genmeta-curl)
- [ ] Error handling follows snafu/AGENTS.md conventions
- [ ] AGENTS.md updated with genmeta-proxy entry
