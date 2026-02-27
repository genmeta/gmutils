- Copied initialization flow from genmeta-curl: tracing, identity load, bind setup, dns resolvers, H3Client build.
- Needed to add hyper/hyper-util/http-body-util to workspace and crate to satisfy existing modules (route.rs uses hyper types).
- Keep accept loop stub: log + drop to avoid implementing request handling now.

## Task 5: H3 forwarding module (h3_forward.rs)

### Import fixes required
- `http_body` is NOT a direct dep of genmeta-proxy; use `hyper::body::Body` (re-exported by hyper v1) instead of `http_body::Body`
- `Whatever::without_source` requires `snafu::FromString` trait in scope
- `.into()` for error conversion is ambiguous when multiple `From` impls exist; use `crate::Error::from(...)` explicitly

### Return type
- `execute_hyper_request` returns opaque body type; use `impl Body<Data = bytes::Bytes, Error = h3x::message::stream::StreamError>` in return position
- `H3Client::connect` takes `Authority` and returns `Arc<Connection<...>>`

### Error message style
- Always use `crate::Error::from(Whatever::without_source("...".to_string()))` pattern for dynamic errors

## Task 7: Main proxy accept loop with 4-branch request handler

### BoxBody / UnsyncBoxBody
- `http_body_util::combinators::BoxBody` requires `Body: Send + Sync`. h3x body types are only `Send` (internal `dyn ReadStream + Send` lacks `Sync`).
- Use `UnsyncBoxBody` instead: `http_body_util::combinators::UnsyncBoxBody<Bytes, BoxError>`. It boxes `dyn Body + Send` without requiring `Sync`.
- Use `.boxed_unsync()` method from `BodyExt` instead of `.boxed()`.
- `UnsyncBoxBody` itself IS `Send` (Pin<Box<dyn Body + Send>>), so works fine for hyper server.

### H3 body lifetime issue
- `forward_h3(req, client: &H3Client)` returns `Response<impl Body + use<B, C>>`.
- The opaque body type captures the connection lifetime, causing `'1 must outlive 'static` error when calling `.boxed_unsync()`.
- Workaround (without modifying h3_forward.rs): collect the body into `bytes::Bytes` using `body.collect().await?.to_bytes()`, then wrap in `Full::new(bytes).map_err(...).boxed_unsync()`.
- This sacrifices streaming for H3 responses but avoids the lifetime issue.

### Cargo.toml features
- Workspace `hyper = "1"` initially had no features. Need `features = ["http1", "server"]` for `hyper::server::conn::http1`.
- Workspace `hyper-util = "0.1"` needs `features = ["server", "tokio"]` for `TokioIo` and server utilities.
- `h3x` transitively pulls hyper with client/http1/http2 features but NOT server.

### Arc wrapping for multi-task sharing
- `H3Client` is `Client<Arc<QuicClient>>` which is Clone. Wrap in `Arc<H3Client>` to share across spawned tasks cheaply.
- `Router` is a plain struct, also wrap in `Arc<Router>`.
- Clone both Arcs into each spawned task closure.

### hyper server serve_connection + with_upgrades
- Must call `.with_upgrades()` for CONNECT tunnel support (HTTP upgrade protocol).
- Use `hyper::service::service_fn(move |req| { ... })` with cloned Arcs inside.
