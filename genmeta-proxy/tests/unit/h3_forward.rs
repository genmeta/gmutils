use super::*;

#[tokio::test]
async fn dropping_response_cancels_blocked_proxy_upload() {
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let (dropped_tx, dropped_rx) = tokio::sync::oneshot::channel();
    struct Guard(Option<tokio::sync::oneshot::Sender<()>>);
    impl Drop for Guard {
        fn drop(&mut self) {
            if let Some(sender) = self.0.take() {
                let _ = sender.send(());
            }
        }
    }
    let upload = tokio::spawn(async move {
        let _guard = Guard(Some(dropped_tx));
        let _ = started_tx.send(());
        std::future::pending::<Result<(), Error>>().await
    });
    started_rx.await.unwrap();
    let body = http_body_util::Empty::new()
        .map_err(|never| match never {})
        .boxed_unsync();
    drop(ForwardBody {
        body,
        upload: Some(upload),
        require_upload: true,
    });
    tokio::time::timeout(std::time::Duration::from_secs(1), dropped_rx)
        .await
        .unwrap()
        .unwrap();
}
