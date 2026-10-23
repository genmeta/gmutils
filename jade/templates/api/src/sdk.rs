//! HTTP bindings supplied by Jade's API template. The route declaration drives
//! both dispatch and the OpenAPI document embedded by `jade build`.
use std::io::{Read, Write};

use wasip2::http::types::*;

pub type Result<T = Response> = std::result::Result<T, Response>;
pub struct Request(pub IncomingRequest);
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, Vec<u8>)>,
    pub body: Vec<u8>,
}

impl Request {
    pub fn json<T: serde::de::DeserializeOwned>(&self) -> Result<T> {
        let body = self
            .0
            .consume()
            .map_err(|_| Response::error(400, "Body already consumed"))?;
        let stream = body
            .stream()
            .map_err(|_| Response::error(400, "Cannot read request body"))?;
        let mut data = Vec::new();
        stream
            .take(1024 * 1024 + 1)
            .read_to_end(&mut data)
            .map_err(|_| Response::error(400, "Cannot read request body"))?;
        if data.len() > 1024 * 1024 {
            return Err(Response::error(413, "Request body exceeds 1 MiB"));
        }
        serde_json::from_slice(&data)
            .map_err(|e| Response::error(400, &format!("Invalid JSON: {e}")))
    }
}

impl Response {
    pub fn json(value: impl serde::Serialize) -> Result {
        let body =
            serde_json::to_vec(&value).map_err(|_| Self::error(500, "Cannot encode response"))?;
        Ok(Self {
            status: 200,
            headers: vec![("content-type".into(), b"application/json".to_vec())],
            body,
        })
    }
    pub fn error(status: u16, message: &str) -> Self {
        Self {
            status,
            headers: vec![("content-type".into(), b"application/json".to_vec())],
            body: serde_json::to_vec(&serde_json::json!({"error":message})).unwrap(),
        }
    }
}

pub fn method(method: Method) -> String {
    match method {
        Method::Get => "get",
        Method::Head => "head",
        Method::Post => "post",
        Method::Put => "put",
        Method::Delete => "delete",
        Method::Patch => "patch",
        Method::Options => "options",
        Method::Trace => "trace",
        Method::Connect => "connect",
        Method::Other(value) => return value.to_ascii_lowercase(),
    }
    .into()
}

pub fn respond(out: ResponseOutparam, result: Result) {
    let response = result.unwrap_or_else(|response| response);
    let Ok(headers) = Fields::from_list(&response.headers) else {
        ResponseOutparam::set(
            out,
            Err(ErrorCode::InternalError(Some(
                "Invalid response headers".into(),
            ))),
        );
        return;
    };
    let outgoing = OutgoingResponse::new(headers);
    if outgoing.set_status_code(response.status).is_err() {
        ResponseOutparam::set(
            out,
            Err(ErrorCode::InternalError(Some(
                "Invalid response status".into(),
            ))),
        );
        return;
    }
    let body = outgoing.body().unwrap();
    let mut stream = body.write().unwrap();
    ResponseOutparam::set(out, Ok(outgoing));
    let result = stream
        .write_all(&response.body)
        .and_then(|_| Write::flush(&mut stream));
    drop(stream);
    if result.is_ok() {
        let _ = OutgoingBody::finish(body, None);
    }
}

macro_rules! api {
    ($method:ident $path:literal => $handler:ident $(, $other_method:ident $other_path:literal => $other_handler:ident)* $(,)?) => {
        struct JadeHttpHandler;
        impl wasip2::exports::http::incoming_handler::Guest for JadeHttpHandler {
            fn handle(request: wasip2::http::types::IncomingRequest, out: wasip2::http::types::ResponseOutparam) {
                let method = crate::sdk::method(request.method());
                let uri = request.path_with_query().unwrap_or_else(|| "/".into());
                let path = uri.split('?').next().unwrap_or("/");
                let result = match (method.as_str(), path) {
                    (stringify!($method), $path) => $handler(crate::sdk::Request(request)),
                    $((stringify!($other_method), $other_path) => $other_handler(crate::sdk::Request(request)),)*
                    _ => {
                        let allowed = [(stringify!($method), $path), $((stringify!($other_method), $other_path)),*]
                            .iter().filter(|(_, candidate)| *candidate == path).map(|(method,_)|method.to_ascii_uppercase()).collect::<Vec<_>>();
                        let mut response = crate::sdk::Response::error(if allowed.is_empty() { 404 } else { 405 }, "No matching route");
                        if !allowed.is_empty() { response.headers.push(("allow".into(),allowed.join(", ").into_bytes())); }
                        Err(response)
                    }
                };
                crate::sdk::respond(out, result);
            }
        }
        wasip2::http::proxy::export!(JadeHttpHandler);
        const JADE_ROUTES: &str = concat!(
            "[{\"method\":\"", stringify!($method), "\",\"path\":", stringify!($path), ",\"handler\":\"", stringify!($handler), "\"}",
            $(",{\"method\":\"", stringify!($other_method), "\",\"path\":", stringify!($other_path), ",\"handler\":\"", stringify!($other_handler), "\"}",)* "]"
        );
        #[used]
        #[unsafe(link_section = "jade:routes")]
        static JADE_ROUTE_BYTES: [u8; JADE_ROUTES.len()] = {
            let mut bytes = [0; JADE_ROUTES.len()];
            let mut i = 0;
            while i < bytes.len() { bytes[i] = JADE_ROUTES.as_bytes()[i]; i += 1; }
            bytes
        };
    };
}
pub(crate) use api;
