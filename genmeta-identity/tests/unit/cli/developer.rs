use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

use super::*;

async fn server(replies: Vec<(u16, Value)>) -> (CertServer, tokio::task::JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server = CertServer::new(format!("http://{}", listener.local_addr().unwrap())).unwrap();
    let task = tokio::spawn(async move {
        let mut requests = Vec::new();
        for (status, body) in replies {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut data = Vec::new();
            loop {
                let mut buffer = [0; 4096];
                let count = socket.read(&mut buffer).await.unwrap();
                data.extend_from_slice(&buffer[..count]);
                if count == 0 {
                    break;
                }
                if let Some(end) = data.windows(4).position(|w| w == b"\r\n\r\n") {
                    let headers = String::from_utf8_lossy(&data[..end]);
                    let size = headers
                        .lines()
                        .find_map(|line| {
                            line.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .and_then(|v| v.trim().parse::<usize>().ok())
                        })
                        .unwrap_or(0);
                    if data.len() >= end + 4 + size {
                        break;
                    }
                }
            }
            requests.push(String::from_utf8(data).unwrap());
            let body = body.to_string();
            socket.write_all(format!("HTTP/1.1 {status} response\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
        }
        requests
    });
    (server, task)
}
fn request_header<'a>(request: &'a str, name: &str) -> Option<&'a str> {
    request
        .lines()
        .take_while(|line| !line.is_empty())
        .find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.eq_ignore_ascii_case(name).then_some(value.trim())
        })
}
fn active() -> Value {
    json!({"items":[{"domain":"alice.dhttp.net","developer_domain":"dev.alice.dhttp.net","developer_ready":true,"status":"active","started_at":chrono::Utc::now().timestamp()-60,"paid_through":chrono::Utc::now().timestamp()+3600}]})
}
fn pending() -> Value {
    json!({"items":[{"domain":"alice.dhttp.net","developer_domain":"dev.alice.dhttp.net","status":"pending_payment","invoice_no":"INV1"}]})
}
fn invoice() -> Value {
    json!({"invoice_no":"INV1","domain":"alice.dhttp.net","status":"pending","amount":9900,"currency":"USD","url":"https://example.test/checkout"})
}
fn pricing() -> Value {
    json!({"code_signing":{"enabled":true,"amount":9900,"currency":"USD","billing_cycle":"yearly"}})
}
struct Ui {
    confirm: bool,
    waits: Vec<bool>,
    urls: Vec<String>,
}
impl Ui {
    fn paid() -> Self {
        Self {
            confirm: true,
            waits: vec![true],
            urls: Vec::new(),
        }
    }
}
impl CheckoutUi for Ui {
    async fn confirm(&mut self, price: &Value) -> Result<bool, Error> {
        assert_eq!(price, &pricing());
        Ok(self.confirm)
    }
    async fn open(&mut self, url: &str) -> Result<(), Error> {
        self.urls.push(url.into());
        Ok(())
    }
    async fn wait(&mut self) -> Result<bool, Error> {
        Ok(if self.waits.is_empty() {
            false
        } else {
            self.waits.remove(0)
        })
    }
}
#[test]
fn entitlement_requires_exact_domain_paid_period_and_operational_status() {
    let now = chrono::Utc::now().timestamp();
    assert!(has_entitlement(&active(), "alice.dhttp.net", now));
    assert!(!has_entitlement(&active(), "dev.alice.dhttp.net", now));
    for status in ["pending_payment", "expired", "suspended", "terminated"] {
        let mut invalid = active();
        invalid["items"][0]["status"] = json!(status);
        assert!(!has_entitlement(&invalid, "alice.dhttp.net", now));
    }
    let mut expired = active();
    expired["items"][0]["paid_through"] = json!(now);
    assert!(!has_entitlement(&expired, "alice.dhttp.net", now));
}
#[test]
fn developer_setup_preserves_the_exact_child_and_rejects_root_names() {
    assert_eq!(
        developer_target(&active(), "dev.alice.dhttp.net").unwrap(),
        ("alice.dhttp.net".into(), "dev.alice.dhttp.net".into())
    );
    assert!(developer_target(&active(), "alice.dhttp.net").is_err());
    assert!(developer_target(&json!({}), "dev.alex.chen.dhttp.net").is_err());
    let empty = json!({"items": []});
    for root in ["alex.chen.dhttp.net", "dev.wang.dhttp.net"] {
        assert!(developer_target(&empty, root).is_err());
    }
    assert_eq!(
        developer_target(&empty, "dev.dev.wang.dhttp.net").unwrap(),
        ("dev.wang.dhttp.net".into(), "dev.dev.wang.dhttp.net".into())
    );
    let bound = json!({"items": [{"domain":"dev.wang.dhttp.net", "developer_domain":"dev.dev.wang.dhttp.net", "status":"active"}]});
    assert_eq!(
        developer_target(&bound, "dev.dev.wang.dhttp.net").unwrap(),
        ("dev.wang.dhttp.net".into(), "dev.dev.wang.dhttp.net".into())
    );
    let mut wrong = active();
    wrong["items"][0]["developer_domain"] = json!("other.alice.dhttp.net");
    assert!(developer_target(&wrong, "dev.alice.dhttp.net").is_err());
}
#[tokio::test]
async fn existing_entitlement_skips_checkout() {
    let (server, requests) = server(vec![(200, active())]).await;
    ensure_entitlement(&server, "account", "alice.dhttp.net", "durable-key", false)
        .await
        .unwrap();
    assert_eq!(requests.await.unwrap().len(), 1);
}
#[tokio::test]
async fn noninteractive_setup_does_not_create_or_charge_an_order() {
    let (server, requests) = server(vec![(200, json!({"items":[]}))]).await;
    let error = ensure_entitlement(&server, "account", "alice.dhttp.net", "durable-key", false)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("no order was created"));
    assert_eq!(requests.await.unwrap().len(), 1);
}
#[tokio::test]
async fn cancellation_before_purchase_creates_no_invoice() {
    let (server, requests) = server(vec![(200, pending()), (200, pricing())]).await;
    let mut ui = Ui::paid();
    ui.confirm = false;
    assert!(
        ensure_entitlement_with_ui(
            &server,
            "account",
            "alice.dhttp.net",
            "durable-key",
            true,
            &mut ui
        )
        .await
        .is_err()
    );
    assert_eq!(requests.await.unwrap().len(), 2);
    assert!(ui.urls.is_empty());
}
#[tokio::test]
async fn payment_continues_only_after_authoritative_entitlement_refresh() {
    let (server, requests) = server(vec![
        (200, json!({"items":[]})),
        (200, pricing()),
        (201, json!({"invoice_no":"INV1"})),
        (200, pending()),
        (200, invoice()),
        (200, pending()),
        (200, invoice()),
        (200, active()),
    ])
    .await;
    let mut ui = Ui::paid();
    ui.waits = vec![true, true];
    ensure_entitlement_with_ui(
        &server,
        "account",
        "alice.dhttp.net",
        "durable-key",
        true,
        &mut ui,
    )
    .await
    .unwrap();
    assert_eq!(ui.urls, vec!["https://example.test/checkout"]);
    let requests = requests.await.unwrap();
    assert_eq!(requests.len(), 8);
    assert_eq!(
        request_header(&requests[2], "idempotency-key"),
        Some("durable-key")
    );
}
#[tokio::test]
async fn concurrent_purchase_recovers_original_invoice_without_second_purchase() {
    let (server, requests) = server(vec![
        (200, pending()),
        (200, pricing()),
        (
            409,
            json!({"error":{"code":1435,"message":"pending","invoice_no":"INV1"}}),
        ),
        (200, pending()),
        (200, pending()),
        (200, invoice()),
        (200, active()),
    ])
    .await;
    ensure_entitlement_with_ui(
        &server,
        "account",
        "alice.dhttp.net",
        "durable-key",
        true,
        &mut Ui::paid(),
    )
    .await
    .unwrap();
    let requests = requests.await.unwrap();
    assert_eq!(
        requests
            .iter()
            .filter(|r| r.starts_with("POST /v2/subscription "))
            .count(),
        1
    );
}
#[tokio::test]
async fn free_checkout_continues_after_confirmed_fulfillment_without_opening_a_payment_page() {
    let (server, requests) = server(vec![
        (200, json!({"items":[]})),
        (200, pricing()),
        (201, json!({"invoice_no":"INV1"})),
        (200, active()),
    ])
    .await;
    let mut ui = Ui::paid();
    ensure_entitlement_with_ui(
        &server,
        "account",
        "alice.dhttp.net",
        "durable-key",
        true,
        &mut ui,
    )
    .await
    .unwrap();
    assert!(ui.urls.is_empty());
    assert_eq!(requests.await.unwrap().len(), 4);
}
#[tokio::test]
async fn cancelling_payment_wait_preserves_the_original_operation() {
    let (server, requests) = server(vec![
        (200, pending()),
        (200, pricing()),
        (200, json!({"invoice_no":"INV1"})),
        (200, pending()),
        (200, invoice()),
    ])
    .await;
    let mut ui = Ui::paid();
    ui.waits = vec![false];
    assert!(
        ensure_entitlement_with_ui(
            &server,
            "account",
            "alice.dhttp.net",
            "durable-key",
            true,
            &mut ui
        )
        .await
        .unwrap_err()
        .to_string()
        .contains("preserved")
    );
    assert_eq!(requests.await.unwrap().len(), 5);
}
#[tokio::test]
async fn ended_checkout_gets_a_new_stable_key_bound_to_its_invoice() {
    let (server, requests) = server(vec![
        (200, pending()),
        (200, pricing()),
        (409, json!({"error":{"code":1436,"message":"ended"}})),
        (201, json!({"invoice_no":"INV2"})),
        (200, active()),
    ])
    .await;
    ensure_entitlement_with_ui(
        &server,
        "account",
        "alice.dhttp.net",
        "durable-key",
        true,
        &mut Ui::paid(),
    )
    .await
    .unwrap();
    let requests = requests.await.unwrap();
    assert_eq!(
        request_header(&requests[2], "idempotency-key"),
        Some("durable-key")
    );
    assert_eq!(
        request_header(&requests[3], "idempotency-key"),
        Some("durable-key-INV1")
    );
}
#[tokio::test]
async fn plain_root_apply_does_not_replace_the_root_with_a_developer_child() {
    let (server, requests) = server(vec![]).await;
    let tmp = tempfile::tempdir().unwrap();
    let home = DhttpHome::new(tmp.path().to_path_buf());
    assert!(
        !apply_for_account(&home, &server, "account", "alice.dhttp.net", "test", false)
            .await
            .unwrap()
    );
    assert_eq!(requests.await.unwrap().len(), 0);
}
#[tokio::test]
async fn explicit_developer_apply_uses_bound_child_csr_and_preserves_pending_on_failure() {
    let (server, requests) = server(vec![
        (200, active()),
        (200, active()),
        (200, active()),
        (
            503,
            json!({"error":{"code":1427,"message":"issuer unavailable"}}),
        ),
    ])
    .await;
    let tmp = tempfile::tempdir().unwrap();
    let home = DhttpHome::new(tmp.path().to_path_buf());
    let command = Developer {
        name: "dev.alice.dhttp.net".into(),
        email: None,
        verify_code: None,
        command: DeveloperCommand::Apply {
            device_name: "test".into(),
        },
    };
    assert!(
        command
            .run_authorized(&home, &server, "account", false)
            .await
            .is_err()
    );
    let requests = requests.await.unwrap();
    let issue = requests
        .iter()
        .find(|r| r.starts_with("POST /v2/cert "))
        .unwrap();
    let body = issue.split_once("\r\n\r\n").unwrap().1;
    assert_eq!(
        serde_json::from_str::<Value>(body).unwrap()["domain"],
        "dev.alice.dhttp.net"
    );
    let profile = home.identity_profile("dev.alice.dhttp.net").unwrap();
    assert!(
        code_signing::directory(&profile)
            .join("apply.pending.json")
            .exists()
    );
    assert!(!profile.ssl_dir().exists());
}
