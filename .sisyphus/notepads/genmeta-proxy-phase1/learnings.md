# Learnings

## Key API: execute_hyper_request
- Location: `h3x/src/hyper/client.rs:67`
- Signature: `Connection::execute_hyper_request<B: Body>(req: http::Request<B>) -> Result<http::Response<impl Body>, RequestError<B::Error>>`
- This is THE correct API for H3 forwarding — handles body streaming automatically
- Do NOT use `new_request().execute()` for proxy use

## H3Client Connection Pool
- h3x has built-in Pool (DashMap keyed by authority+settings)
- `client.connect(authority)` automatically reuses connections
- No manual pooling needed

## genmeta-curl Pattern
- main.rs: 10 lines, `use genmeta_curl::{Options, run};`
- lib.rs: Options (clap derive) + Error (snafu) + run() with tracing init, identity, bind, dns, H3Client build
- Error enum uses `#[snafu(module)]` pattern
- Tracing init: tracing_appender::non_blocking(stderr) + registry().with(fmt layer).with(EnvFilter).init()

## hyper 1.x Proxy Pattern
- Server: `hyper::server::conn::http1::Builder::new().preserve_header_case(true).title_case_headers(true).serve_connection(io, service_fn(handler)).with_upgrades()`
- CONNECT tunnel: `hyper::upgrade::on(req)` → `TokioIo::new(upgraded)` + `TokioIo::new(tcp_stream)` → `tokio::io::copy_bidirectional`
- Client: `hyper::client::conn::http1::handshake(TokioIo::new(stream))` → `(sender, connection)`, `tokio::spawn(connection)`, `sender.send_request(req)`

## Workspace Deps Already Present
- hyper, hyper-util, http-body-util are transitive deps via h3x/reqwest
- Need to add them explicitly to workspace Cargo.toml with needed features
