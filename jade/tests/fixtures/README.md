# Upload protocol fixture

`upload-handler.wasm` is a standard WASI HTTP component copied unchanged from
`store-server/tests/fixtures/incoming-handler.wasm` at store-server revision
`001fca1e9f1eb971f3ff9ca0ff1ee332afeefa63`.

SHA-256: `4b210be20b4da473675e546b84deff326381e1d244c6c4dfa8f2e3cb37b4cfa0`.

The upload tests embed OpenAPI into this Component, wrap it in the unified Pkg
format and sign with new temporary credentials. Static fixtures are generated as
frontend-only ZIP packages. Package tests also use
`wasi-http-read-request-then-respond.wasm` to exercise the HTTP entry point and
public/backend combinations. All package inspection and signature checks are local.

`../support/upload_credentials.rs` adapts the existing DHTTP OpenSSL test helper
to assign explicit test owner hashes. All private keys and OCSP responses are
created under a temporary directory and removed afterwards; no credentials are
stored in these fixtures.
