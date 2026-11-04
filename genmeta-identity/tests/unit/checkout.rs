use super::*;
use crate::cert_server::CreateDomainResponse;

#[test]
fn completed_next_action_is_terminal() {
    let response: CreateDomainResponse = serde_json::from_str(
        r#"{"domain":"alice.smith.dhttp.net","quotes":{"currency":"USD","monthly":0,"yearly":0,"default_billing_cycle":"yearly"},"next_action":"completed"}"#,
    )
    .unwrap();
    assert_eq!(classify_checkout(&response), CheckoutState::Completed);
}

#[test]
fn expired_invoice_is_terminal() {
    let response: CreateDomainResponse = serde_json::from_str(
        r#"{"domain":"alice.smith.dhttp.net","quotes":{"currency":"USD","monthly":9900,"yearly":99000,"default_billing_cycle":"yearly"},"next_action":"payment","invoice":{"number":"INV1","status":"expired","amount":9900,"currency":"USD"}}"#,
    )
    .unwrap();
    assert_eq!(classify_checkout(&response), CheckoutState::Expired);
}

#[test]
fn terminal_qr_uses_the_compact_stable_layout() {
    let qr = render_terminal_qr("https://pay.example.test/checkout/ckt_123").unwrap();
    let rows = qr.lines().count();
    let columns = qr
        .lines()
        .map(str::chars)
        .map(Iterator::count)
        .max()
        .unwrap();

    assert!(rows <= 24, "QR uses {rows} terminal rows");
    assert!(columns <= 64, "QR uses {columns} terminal columns");
}

#[test]
fn payment_block_keeps_instruction_qr_and_link_in_order() {
    let rendered = payment_instruction_block("https://pay.example.test/checkout/ckt_123").unwrap();
    let notice = rendered
        .find("[!] Please complete your payment within 15 minutes.")
        .unwrap();
    let instruction = rendered
        .find("Open the link, or scan the QR code below")
        .unwrap();
    let qr = rendered.find('█').unwrap();
    let link = rendered
        .find("Link: https://pay.example.test/checkout/ckt_123")
        .unwrap();

    assert!(
        notice < instruction && instruction < qr && qr < link,
        "{rendered}"
    );
    assert!(!rendered.contains("Open the link below, or scan the QR code above"));
}

#[test]
fn payment_block_indents_every_qr_row_by_four_spaces() {
    let rendered = payment_instruction_block("https://pay.example.test/checkout").unwrap();
    let qr = rendered
        .split_once("Open the link, or scan the QR code below\n\n")
        .unwrap()
        .1
        .split_once("\n\n    Link: https://pay.example.test/checkout")
        .unwrap()
        .0;

    assert!(!qr.is_empty());
    assert!(
        qr.lines().all(|line| line.starts_with("    ")),
        "{rendered}"
    );
}

#[test]
fn payment_block_drops_the_blank_quiet_zone_rows_above_the_qr() {
    let rendered = payment_instruction_block("https://pay.example.test/checkout").unwrap();
    let first_qr_row = rendered
        .split_once("Open the link, or scan the QR code below\n\n")
        .unwrap()
        .1
        .lines()
        .next()
        .unwrap();

    assert!(first_qr_row.contains(['▀', '▄', '█']), "{rendered}");
}

#[test]
fn payment_block_falls_back_to_the_link_only_when_qr_encoding_is_impossible() {
    let url = format!("https://pay.example.test/{}", "x".repeat(10_000));
    let block = payment_instruction_block_or_link(&url);

    assert!(!block.contains(['▀', '▄', '█']));
    assert!(block.contains("Open the link below\n"));
    assert!(block.contains(&format!("Link: {url}")));
}

#[test]
fn unknown_invoice_state_is_a_terminal_failure() {
    let response: CreateDomainResponse = serde_json::from_str(
        r#"{"domain":"alice.smith.dhttp.net","quotes":{"currency":"USD","monthly":9900,"yearly":99000,"default_billing_cycle":"yearly"},"next_action":"payment","invoice":{"number":"INV1","status":"surprising","amount":9900,"currency":"USD"}}"#,
    )
    .unwrap();

    assert_eq!(classify_checkout(&response), CheckoutState::Failed);
}

#[test]
fn checkout_wait_uses_the_server_deadline_with_a_fifteen_minute_cap() {
    assert_eq!(checkout_wait_duration(999, 1_000), Duration::ZERO);
    assert_eq!(
        checkout_wait_duration(1_030, 1_000),
        Duration::from_secs(30)
    );
    assert_eq!(
        checkout_wait_duration(3_000, 1_000),
        Duration::from_secs(15 * 60)
    );
}

#[test]
fn developer_checkout_uses_the_same_compact_payment_layout() {
    let url = "https://www.dhttp.net/checkout/ckt_dev_0123456789abcdef0123456789abcdef";
    let qr = render_terminal_qr(url).unwrap();
    assert!(qr.lines().count() <= 24);
    assert!(qr.lines().all(|line| line.chars().count() <= 64));
    let block = payment_instruction_block_or_link(url);
    assert!(block.contains("scan the QR code below"));
    assert!(block.ends_with(&format!("Link: {url}")));
}
