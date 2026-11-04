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
    json!({"invoice_no":"INV1","domain":"alice.dhttp.net","status":"pending","amount":9900,"currency":"USD","url":"/v2/invoice?no=INV1","payment_entry":{"url":"https://dhttp.net/checkout/ckt_test","checkout_token":"ckt_test","expires_at":chrono::Utc::now().timestamp()+900}})
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
    async fn print_payment(&mut self, url: &str) -> Result<(), Error> {
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
    assert_eq!(
        developer_target(&empty, "dev.genmeta.tech.dhttp.net").unwrap(),
        (
            "genmeta.tech.dhttp.net".into(),
            "dev.genmeta.tech.dhttp.net".into()
        )
    );
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
    let mut paid_invoice = invoice();
    paid_invoice["status"] = json!("paid");
    paid_invoice
        .as_object_mut()
        .unwrap()
        .remove("payment_entry");
    let (server, requests) = server(vec![
        (200, json!({"items":[]})),
        (200, pricing()),
        (201, json!({"invoice_no":"INV1"})),
        (200, pending()),
        (200, paid_invoice.clone()),
        (200, pending()),
        (200, paid_invoice),
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
    assert!(ui.urls.is_empty());
    let requests = requests.await.unwrap();
    assert_eq!(requests.len(), 8);
    assert_eq!(
        request_header(&requests[2], "idempotency-key"),
        Some("durable-key")
    );
}

#[tokio::test]
async fn expired_checkout_preserves_operation_without_displaying_a_payment_link() {
    let mut expired = invoice();
    expired["expires_at"] = json!(chrono::Utc::now().timestamp() - 1);
    let (server, requests) = server(vec![
        (200, pending()),
        (200, pricing()),
        (200, json!({"invoice_no":"INV1"})),
        (200, pending()),
        (200, expired),
    ])
    .await;
    let mut ui = Ui::paid();
    let error = ensure_entitlement_with_ui(
        &server,
        "account",
        "alice.dhttp.net",
        "durable-key",
        true,
        &mut ui,
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("preserved"));
    assert!(ui.urls.is_empty());
    assert_eq!(requests.await.unwrap().len(), 5);
}

#[tokio::test(start_paused = true)]
async fn checkout_wait_honors_invoice_deadline_and_preserves_operation() {
    struct WaitingUi;
    impl CheckoutUi for WaitingUi {
        async fn confirm(&mut self, _: &Value) -> Result<bool, Error> {
            Ok(true)
        }
        async fn print_payment(&mut self, _: &str) -> Result<(), Error> {
            Ok(())
        }
        async fn wait(&mut self) -> Result<bool, Error> {
            std::future::pending().await
        }
    }
    let mut pending_invoice = invoice();
    pending_invoice["expires_at"] = json!(chrono::Utc::now().timestamp() + 30);
    let (server, requests) = server(vec![
        (200, pending()),
        (200, pricing()),
        (200, json!({"invoice_no":"INV1"})),
        (200, pending()),
        (200, pending_invoice),
    ])
    .await;
    let started = tokio::time::Instant::now();
    let error = ensure_entitlement_with_ui(
        &server,
        "account",
        "alice.dhttp.net",
        "durable-key",
        true,
        &mut WaitingUi,
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("preserved"));
    assert!((29..=30).contains(&started.elapsed().as_secs()));
    assert_eq!(requests.await.unwrap().len(), 5);
}

#[tokio::test]
async fn developer_renewal_keeps_code_signing_purpose_and_exact_sequence() {
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
        command: DeveloperCommand::Renew { sequence: 7 },
    };
    assert!(
        command
            .run_authorized(&home, &server, "account", false)
            .await
            .is_err()
    );
    let requests = requests.await.unwrap();
    assert!(requests[3].starts_with("POST /v2/cert/renew "));
    let body: Value = serde_json::from_str(requests[3].split_once("\r\n\r\n").unwrap().1).unwrap();
    assert_eq!(body["domain"], "dev.alice.dhttp.net");
    assert_eq!(body["purpose"], "code_signing");
    assert_eq!(body["sequence"], 7);
    let profile = home.identity_profile("dev.alice.dhttp.net").unwrap();
    assert!(
        code_signing::directory(&profile)
            .join("renew-7.pending.json")
            .exists()
    );
    assert!(!profile.ssl_dir().exists());
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
async fn publish_setup_requires_interaction_before_network_or_local_changes() {
    let (server, requests) = server(vec![]).await;
    let tmp = tempfile::tempdir().unwrap();
    let home = DhttpHome::new(tmp.path().to_path_buf());
    let error = prepare_for_publish(&home, &server, "dev.alice.dhttp.net", None, false)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("interactively"));
    assert_eq!(requests.await.unwrap().len(), 0);
    assert_eq!(std::fs::read_dir(tmp.path()).unwrap().count(), 0);
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

#[test]
fn developer_payment_link_requires_public_https_entry_and_renders_qr() {
    for invalid in [
        "/v2/invoice?no=INV1",
        "http://dhttp.net/checkout/ckt_test",
        "https://user:password@dhttp.net/checkout/ckt_test",
    ] {
        assert!(developer_payment_instructions(invalid).is_err());
    }
    let block = developer_payment_instructions("https://dhttp.net/checkout/ckt_test").unwrap();
    assert!(block.contains("Link: https://dhttp.net/checkout/ckt_test"));
    assert!(block.contains(['▀', '▄', '█']));
}

#[tokio::test]
async fn missing_or_expired_public_entry_never_uses_the_invoice_api_url() {
    for missing in [true, false] {
        let mut detail = invoice();
        if missing {
            detail.as_object_mut().unwrap().remove("payment_entry");
        } else {
            detail["payment_entry"]["expires_at"] = json!(chrono::Utc::now().timestamp() - 1);
        }
        let (server, requests) = server(vec![
            (200, pending()),
            (200, pricing()),
            (200, json!({"invoice_no":"INV1"})),
            (200, pending()),
            (200, detail),
        ])
        .await;
        let mut ui = Ui::paid();
        let error = ensure_entitlement_with_ui(
            &server,
            "account",
            "alice.dhttp.net",
            "durable-key",
            true,
            &mut ui,
        )
        .await
        .unwrap_err();
        let message = error.to_string();
        assert!(message.contains("preserved"));
        if missing {
            assert!(message.contains("no public checkout link"));
        } else {
            assert!(message.contains("expired"));
        }
        assert!(ui.urls.is_empty());
        let requests = requests.await.unwrap();
        assert_eq!(requests.len(), 5);
        assert_eq!(
            requests
                .iter()
                .filter(|request| request.starts_with("POST /v2/subscription "))
                .count(),
            1
        );
    }
}

#[tokio::test]
async fn pending_invoice_displays_public_checkout_qr_instead_of_api_url() {
    let (server, requests) = server(vec![
        (200, pending()),
        (200, pricing()),
        (200, json!({"invoice_no":"INV1"})),
        (200, pending()),
        (200, invoice()),
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
    assert_eq!(ui.urls, vec!["https://dhttp.net/checkout/ckt_test"]);
    let instructions = developer_payment_instructions(&ui.urls[0]).unwrap();
    assert!(instructions.contains("Link: https://dhttp.net/checkout/ckt_test"));
    assert!(instructions.contains("scan the QR code"));
    assert!(instructions.contains(['▀', '▄', '█']));
    assert!(!instructions.contains("/v2/invoice"));
    assert_eq!(requests.await.unwrap().len(), 6);
}
