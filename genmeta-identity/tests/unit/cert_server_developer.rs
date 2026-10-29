use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

use super::*;
async fn mock(response: Value, status: &str) -> (CertServer, tokio::task::JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let body = serde_json::to_string(&response).unwrap();
    let status = status.to_owned();
    let task = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        loop {
            let mut chunk = [0u8; 4096];
            let n = socket.read(&mut chunk).await.unwrap();
            request.extend_from_slice(&chunk[..n]);
            if n == 0 {
                break;
            }
            if let Some(end) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                let headers = String::from_utf8_lossy(&request[..end]);
                let size = headers
                    .lines()
                    .find_map(|l| {
                        l.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .and_then(|v| v.trim().parse::<usize>().ok())
                    })
                    .unwrap_or(0);
                if request.len() >= end + 4 + size {
                    break;
                }
            }
        }
        socket.write_all(format!("HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).as_bytes()).await.unwrap();
        String::from_utf8(request).unwrap()
    });
    (CertServer::new(base).unwrap(), task)
}
#[tokio::test]
async fn purchase_uses_product_bearer_and_stable_key_without_price_or_csr() {
    let (server, request) = mock(
        json!({"subscription_no":"CS1","invoice_no":"INV1","payment_required":true}),
        "201 Created",
    )
    .await;
    assert_eq!(
        server
            .purchase_code_signing("account-token", "developer.dhttp.net", "purchase-retry-1")
            .await
            .unwrap()["invoice_no"],
        "INV1"
    );
    let request = request.await.unwrap();
    let (headers, body) = request.split_once("\r\n\r\n").unwrap();
    assert!(headers.starts_with("POST /v2/subscription "));
    assert!(
        headers
            .to_ascii_lowercase()
            .contains("authorization: bearer account-token")
    );
    assert!(
        headers
            .to_ascii_lowercase()
            .contains("idempotency-key: purchase-retry-1")
    );
    assert_eq!(
        serde_json::from_str::<Value>(body).unwrap(),
        json!({"domain":"developer.dhttp.net","product":"code_signing"})
    );
}
#[tokio::test]
async fn pending_purchase_preserves_numeric_error_and_original_invoice() {
    let (server, _) = mock(
        json!({"error":{"code":1435,"message":"Purchase in progress","invoice_no":"INVoriginal"}}),
        "409 Conflict",
    )
    .await;
    let error = server
        .purchase_code_signing("account-token", "developer.dhttp.net", "purchase-retry-1")
        .await
        .unwrap_err();
    assert!(error.is_api(reqwest::StatusCode::CONFLICT, "purchase_in_progress"));
    assert!(error.to_string().contains("INVoriginal"));
}
#[tokio::test]
async fn renew_rotates_via_exact_sequence_and_reuses_idempotency_without_billing() {
    let (server, request) = mock(
        json!({"error":{"code":1427,"message":"disabled"}}),
        "503 Service Unavailable",
    )
    .await;
    assert!(
        server
            .renew_developer_certificate(
                "account-token",
                "developer.dhttp.net",
                7,
                "NEW CSR",
                "pending-renewal-1"
            )
            .await
            .unwrap_err()
            .is_api_code("code_signing_unavailable")
    );
    let request = request.await.unwrap();
    assert!(request.starts_with("POST /v2/cert/renew "));
    assert!(
        request
            .to_ascii_lowercase()
            .contains("idempotency-key: pending-renewal-1")
    );
    let body: Value = serde_json::from_str(request.split_once("\r\n\r\n").unwrap().1).unwrap();
    assert_eq!(body["sequence"], 7);
    assert_eq!(body["purpose"], "code_signing");
    assert_eq!(body["csr"], "NEW CSR");
    assert!(body.get("price").is_none());
}
#[tokio::test]
async fn exact_status_is_public_uncached_and_has_no_filter_mixing() {
    let value: Value = serde_json::from_str(include_str!(
        "../fixtures/code-signing/developer.status.json"
    ))
    .unwrap();
    let fingerprint = value["fingerprint_sha256"].as_str().unwrap().to_owned();
    let (server, request) = mock(value, "200 OK").await;
    server
        .exact_certificate_status("developer.dhttp.net", &fingerprint)
        .await
        .unwrap();
    let request = request.await.unwrap();
    assert!(request.starts_with(&format!(
        "GET /v2/cert?domain=developer.dhttp.net&fingerprint_sha256={fingerprint} HTTP/1.1"
    )));
    assert!(!request.to_ascii_lowercase().contains("authorization:"));
    assert!(
        request
            .to_ascii_lowercase()
            .contains("cache-control: no-cache, no-store")
    );
}
