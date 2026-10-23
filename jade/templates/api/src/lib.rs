use std::io::Write;

use serde_json::json;
use wasip2::http::types::{
    Fields, IncomingRequest, Method, OutgoingBody, OutgoingResponse, ResponseOutparam,
};

fn hello() -> serde_json::Value {
    json!({"message": "Hello from Rust"})
}

struct Api;

impl wasip2::exports::http::incoming_handler::Guest for Api {
    fn handle(request: IncomingRequest, out: ResponseOutparam) {
        let uri = request.path_with_query().unwrap_or_else(|| "/".into());
        let path = uri.split('?').next().unwrap_or("/");
        let headers = Fields::new();
        headers
            .set("content-type", &[b"application/json".to_vec()])
            .unwrap();
        let (status, value) = match (request.method(), path) {
            (Method::Get, "/hello") => (200, hello()),
            (_, "/hello") => {
                headers.set("allow", &[b"GET".to_vec()]).unwrap();
                (405, json!({"error": "No matching route"}))
            }
            _ => (404, json!({"error": "No matching route"})),
        };
        let response = OutgoingResponse::new(headers);
        response.set_status_code(status).unwrap();
        let body = response.body().unwrap();
        let mut stream = body.write().unwrap();
        ResponseOutparam::set(out, Ok(response));
        let bytes = serde_json::to_vec(&value).unwrap();
        let result = stream
            .write_all(&bytes)
            .and_then(|_| Write::flush(&mut stream));
        drop(stream);
        if result.is_ok() {
            let _ = OutgoingBody::finish(body, None);
        }
    }
}

wasip2::http::proxy::export!(Api);

// Jade uses this metadata to generate OpenAPI. Keep it in sync with the routes above.
const ROUTES: &str = r#"[
    {"method":"get","path":"/hello","handler":"hello"}
]"#;

#[used]
#[unsafe(link_section = "jade:routes")]
static ROUTE_BYTES: [u8; ROUTES.len()] = {
    let mut bytes = [0; ROUTES.len()];
    bytes.copy_from_slice(ROUTES.as_bytes());
    bytes
};
