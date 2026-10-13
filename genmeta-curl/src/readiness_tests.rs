use std::{sync::Arc, time::Duration};

use dhttp::resolve::{EndpointAddr, Source};
use futures::{FutureExt, StreamExt, channel::mpsc, stream};
use qprotocol::{AddressBook, Dock, QuicProtocol, UdpSocket};

use super::wait_for_path;

fn socket(book: &AddressBook) -> Arc<UdpSocket> {
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
    Dock::global().add(socket.clone()).unwrap();
    book.insert_inner(&socket, socket.local_addr().unwrap().into())
        .unwrap();
    socket
}

fn cleanup(book: &AddressBook, socket: &Arc<UdpSocket>) {
    book.remove_bound(socket.local_addr().unwrap());
    Dock::global().remove(socket);
}

fn publish(book: &AddressBook, socket: &Arc<UdpSocket>, endpoint: EndpointAddr) {
    QuicProtocol::global().register(endpoint, socket).unwrap();
    book.insert_outer(socket, endpoint).unwrap();
}

#[tokio::test(start_paused = true)]
async fn loopback_path_does_not_wait_for_stun() {
    let book = AddressBook::new();
    let socket = socket(&book);
    let peer = EndpointAddr::direct("127.0.0.1:8443".parse().unwrap());
    wait_for_path(&book, stream::iter([(Source::System, peer)]).boxed())
        .now_or_never()
        .expect("ready loopback must not wait")
        .unwrap();
    cleanup(&book, &socket);
}

#[tokio::test(start_paused = true)]
async fn direct_remote_path_does_not_require_a_public_mapping() {
    let book = AddressBook::new();
    let socket = socket(&book);
    // Controlled private alias on a live socket, without changing host interfaces.
    let local = EndpointAddr::direct("192.168.215.2:55001".parse().unwrap());
    QuicProtocol::global().register(local, &socket).unwrap();
    book.insert_inner(&socket, local).unwrap();
    let peer = EndpointAddr::direct("8.8.4.4:443".parse().unwrap());
    wait_for_path(&book, stream::iter([(Source::System, peer)]).boxed())
        .now_or_never()
        .expect("direct target must not wait for STUN")
        .unwrap();
    cleanup(&book, &socket);
}

#[tokio::test(start_paused = true)]
async fn closed_dns_stream_waits_for_a_late_stun_mapping() {
    let book = AddressBook::new();
    let socket = socket(&book);
    let peer = EndpointAddr::mediate(
        "127.0.0.1:20002".parse().unwrap(),
        "8.8.4.4:55002".parse().unwrap(),
    );
    let mut wait = Box::pin(wait_for_path(
        &book,
        stream::iter([(Source::Dht, peer)]).boxed(),
    ));
    assert!(futures::poll!(&mut wait).is_pending());
    tokio::time::advance(Duration::from_secs(1)).await;
    assert!(futures::poll!(&mut wait).is_pending());
    publish(
        &book,
        &socket,
        EndpointAddr::mediate(
            "127.0.0.1:20003".parse().unwrap(),
            "8.8.8.8:55003".parse().unwrap(),
        ),
    );
    wait.await.unwrap();
    cleanup(&book, &socket);
}

#[tokio::test(start_paused = true)]
async fn mapping_event_can_finish_before_streaming_dns_ends() {
    let book = AddressBook::new();
    let socket = socket(&book);
    let peer = EndpointAddr::mediate(
        "127.0.0.1:20002".parse().unwrap(),
        "8.8.4.4:55004".parse().unwrap(),
    );
    let (send, records) = mpsc::unbounded();
    send.unbounded_send((Source::Dht, peer)).unwrap();
    let mut wait = Box::pin(wait_for_path(&book, records.boxed()));
    assert!(futures::poll!(&mut wait).is_pending());
    publish(
        &book,
        &socket,
        EndpointAddr::mediate(
            "127.0.0.1:20003".parse().unwrap(),
            "8.8.8.8:55005".parse().unwrap(),
        ),
    );
    wait.now_or_never()
        .expect("mapping must not wait for DNS EOF")
        .unwrap();
    drop(send);
    cleanup(&book, &socket);
}

#[tokio::test(start_paused = true)]
async fn ready_direct_dns_result_bypasses_a_pending_mediated_result() {
    let book = AddressBook::new();
    let socket = socket(&book);
    let mediated = EndpointAddr::mediate(
        "127.0.0.1:20002".parse().unwrap(),
        "8.8.4.4:55006".parse().unwrap(),
    );
    let (send, records) = mpsc::unbounded();
    send.unbounded_send((Source::Dht, mediated)).unwrap();
    let mut wait = Box::pin(wait_for_path(&book, records.boxed()));
    assert!(futures::poll!(&mut wait).is_pending());
    send.unbounded_send((
        Source::System,
        EndpointAddr::direct("127.0.0.1:8443".parse().unwrap()),
    ))
    .unwrap();
    wait.now_or_never()
        .expect("direct result must proceed immediately")
        .unwrap();
    cleanup(&book, &socket);
}

#[tokio::test(start_paused = true)]
async fn wrong_address_family_does_not_unblock_wait_and_timeout_cancels_it() {
    let book = AddressBook::new();
    let socket = socket(&book);
    let peer = EndpointAddr::mediate(
        "[::1]:20002".parse().unwrap(),
        "[2001:4860:4860::8888]:55007".parse().unwrap(),
    );
    let mut wait = Box::pin(wait_for_path(
        &book,
        stream::iter([(Source::Dht, peer)]).boxed(),
    ));
    assert!(futures::poll!(&mut wait).is_pending());
    publish(
        &book,
        &socket,
        EndpointAddr::mediate(
            "127.0.0.1:20003".parse().unwrap(),
            "8.8.8.8:55008".parse().unwrap(),
        ),
    );
    assert!(futures::poll!(&mut wait).is_pending());
    let start = tokio::time::Instant::now();
    assert!(
        tokio::time::timeout(Duration::from_secs(1), wait)
            .await
            .is_err()
    );
    assert_eq!(start.elapsed(), Duration::from_secs(1));
    cleanup(&book, &socket);
}

#[tokio::test(start_paused = true)]
async fn empty_dns_and_unregistered_direct_sockets_fail_without_waiting() {
    let book = AddressBook::new();
    assert_eq!(
        wait_for_path(&book, stream::empty().boxed())
            .now_or_never()
            .unwrap()
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::NotConnected
    );
    let socket = UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    book.insert_inner(&socket, socket.local_addr().unwrap().into())
        .unwrap();
    let peer = EndpointAddr::direct("127.0.0.1:8443".parse().unwrap());
    assert_eq!(
        wait_for_path(&book, stream::iter([(Source::System, peer)]).boxed())
            .now_or_never()
            .unwrap()
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::NotConnected
    );
}

#[test]
fn preflight_name_preserves_dns_ports_but_not_dhttp_certificate_sequences() {
    for (uri, expected) in [
        ("https://ALICE.DHTTP.NET:2/", "alice.dhttp.net"),
        ("https://alice.dhttp.net./", "alice.dhttp.net"),
        ("https://Example.COM:8443/", "example.com:8443"),
        ("https://user@example.com:443/", "example.com:443"),
        ("https://example.com/", "example.com"),
    ] {
        assert_eq!(super::lookup_name(&uri.parse().unwrap()).unwrap(), expected);
    }
}

#[test]
fn malformed_targets_fail_before_dns_or_stun_wait() {
    for uri in [
        "ftp://example.com/",
        "https://example.com:0/",
        "https://example.com:99999/",
        "https://127.0.0.1/",
        "https://bad_name.example/",
        "/relative",
    ] {
        assert!(super::lookup_name(&uri.parse().unwrap()).is_err(), "{uri}");
    }
}
