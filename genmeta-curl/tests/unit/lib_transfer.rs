use std::io;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::transfer;
#[tokio::test]
async fn transfer_drains_duplex_response_during_large_upload() {
    let (mut upload_client, mut upload_server) = tokio::io::duplex(64);
    let (mut response_server, mut response_client) = tokio::io::duplex(64);
    let server = tokio::spawn(async move {
        tokio::io::copy(&mut upload_server, &mut response_server)
            .await
            .unwrap();
    });
    let payload = vec![42u8; 256 * 1024];
    let upload = async {
        upload_client.write_all(&payload).await?;
        upload_client.shutdown().await
    };
    let receive = async {
        let mut body = Vec::new();
        response_client.read_to_end(&mut body).await?;
        Ok::<_, io::Error>(body)
    };
    let body = tokio::time::timeout(std::time::Duration::from_secs(5), transfer(upload, receive))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(body, payload);
    server.await.unwrap();
}

#[tokio::test]
async fn early_rejection_does_not_wait_for_a_blocked_upload() {
    let uploading = std::future::pending::<Result<(), io::Error>>();
    let response = async { Ok::<_, io::Error>(http::StatusCode::PAYLOAD_TOO_LARGE) };
    let status = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        transfer(uploading, response),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(status, http::StatusCode::PAYLOAD_TOO_LARGE);
}
