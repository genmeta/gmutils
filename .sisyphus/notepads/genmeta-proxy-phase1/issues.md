# Issues & Gotchas

## Known Gotchas
- hyper CONNECT upgrade: must call `hyper::upgrade::on(req)` BEFORE returning the 200 response, then spawn task
- hyper requires connection task to be polled: `tokio::spawn(connection.await)` after handshake
- Route module needs hyper::body::Incoming in scope — use `hyper::body::Incoming` not `hyper::Body`
- Response body types: H3 response body and Incoming are different types — may need `BoxBody` or `Either` to unify in handler
- cargo edition 2024 is used in this workspace
