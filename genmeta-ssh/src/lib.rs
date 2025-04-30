use std::{io::Write, net::SocketAddr, time::Duration};

use bytes::Buf;
use clap::Parser;
use crossterm::{
    event::{self, Event, EventStream, KeyCode, KeyEvent, KeyModifiers},
    execute,
    terminal::{self},
};
use futures::{SinkExt, StreamExt, channel::mpsc};
use gateway::{Resolver, dns::UdpResolver, localhost::TraversalFactory};
use gm_quic::ToCertificate;
use http::Uri;
use serde::{Deserialize, Serialize};
use tracing::{error, info};

// 定义客户端与服务器通信的消息结构
#[derive(Serialize, Deserialize, Debug)]
enum TerminalMessage {
    Text(String),
    WindowSize { rows: u16, cols: u16 },
    Signal(i32),
    ControlSequence(String),
    Heartbeat,
}

#[derive(Parser, Debug)]
#[command(version, about)]
pub struct Options {
    #[arg(
        help = "Example: `ssh3://user:password@host:port/ssh`.\n Scheme is must not be present or be `ssh3`.\n Password is optional, if not present, prompt for it"
    )]
    uri: Uri,
}

type Error = Box<dyn core::error::Error + Send + Sync>;

pub async fn run(options: Options) -> Result<(), Error> {
    let (username, password) = parse_username_password(&options)?;

    if options.uri.scheme_str().is_some_and(|s| s != "ssh3") {
        return Err("Scheme in uri is must not be present or be `ssh3`".into());
    }

    // 创建通道用于异步通信
    let (tx, mut rx) = mpsc::channel::<TerminalMessage>(32);

    // 启动事件监听任务
    let event_task = tokio::spawn(handle_event(tx.clone()));

    let resolver = UdpResolver::new("1.12.74.4:5300".parse().unwrap());
    let server_name = options.uri.host().ok_or("Missing host in uri")?;
    let addrs = resolver.look_up(server_name).await?;

    let mut roots = rustls::RootCertStore::empty();
    roots.add_parsable_certificates(include_bytes!("../../root.crt").to_certificate());

    info!("resolved {} to address: {:?}", server_name, addrs);

    // NAT Traversal
    let agents = [
        "1.12.74.4:20004".parse().unwrap(),
        "[2402:4e00:c011:1700:8624:7e0:5c9a:2]:20004"
            .parse()
            .unwrap(),
    ];

    let factory = TraversalFactory::with(&agents[..]);

    let mut binds = Vec::new();

    for device_ip in factory.devices().keys() {
        let device_ip = match device_ip.parse() {
            Ok(ip) => ip,
            Err(e) => {
                error!("Invalid device IP {}: {:?}", device_ip, e);
                continue;
            }
        };
        // TODO 此处使用 0 端口, 测试通过, 但不太确定是否有什么问题
        binds.push(SocketAddr::new(device_ip, 0));
    }

    let quic_client = ::gm_quic::QuicClient::builder()
        .with_root_certificates(roots)
        .without_cert()
        .with_alpns(["h3"])
        .with_iface_factory(factory)
        .with_parameters(client_parameters())
        .enable_sslkeylog()
        .bind(&binds[..])
        .inspect_err(|e| {
            error!("bind addrs: {binds:?}  err {e:?}");
        })?
        .build();

    info!(server_name, ?addrs, "connect to server");

    let quic_conn = quic_client.connect(server_name, addrs[0])?;

    // create h3 client
    let (mut h3_conn, mut h3_client) =
        h3::client::new(h3_shim::QuicConnection::new(quic_conn.clone()).await).await?;
    let conn_close_monitor = h3_conn.wait_idle();

    // 构建 Basic Auth 头
    use base64::Engine;

    let credentials = format!("{username}:{password}");
    let basic_auth = base64::engine::general_purpose::STANDARD.encode(credentials.as_bytes());

    info!(%options.uri, "request");
    let request = http::Request::builder()
        .method("PUT")
        .uri(options.uri)
        .header("Authorization", format!("Basic {basic_auth}"))
        .body(())?;

    // sending request results in a bidirectional stream,
    // which is also used for receiving response
    let mut stream = h3_client.send_request(request).await?;
    let response = stream.recv_response().await?;
    info!(?response, "received");

    // 初始化终端
    // execute!(std::io::stdout(), EnterAlternateScreen, EnableMouseCapture)?;
    terminal::enable_raw_mode()?;

    let (mut sender, mut receiver) = stream.split();

    // read from stdin and write to the stream
    let send_task = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        loop {
            tokio::select! {
                msg = rx.next() => match msg {
                    Some(msg) => {
                        let serialized = serde_json::to_vec(&msg).unwrap();
                        if let Err(e) = sender.send_data(serialized.into()).await {
                            eprintln!("Write to peer error: {e}");
                            break;
                        }
                    }
                    None => {
                        if let Err(e) = sender.finish().await {
                            eprintln!("Finish stream error: {e}");
                        }
                        break;
                    }
                },
                _ = interval.tick() => {
                    let serialized = serde_json::to_vec(&TerminalMessage::Heartbeat).unwrap();
                    if let Err(e) = sender.send_data(serialized.into()).await {
                        eprintln!("Send heartbeat error: {e}");
                        break;
                    }
                }
            }
        }
    });

    // receive data from the stream and write to stdout
    let recv_task = tokio::spawn({
        let mut tx = tx.clone();
        async move {
            let stdout = std::io::stdout();
            loop {
                match receiver.recv_data().await {
                    Ok(Some(chunk)) => {
                        let response = String::from_utf8_lossy(chunk.chunk());
                        execute!(stdout.lock(), crossterm::style::Print(response)).unwrap();
                        stdout.lock().flush().unwrap();
                    }
                    Ok(None) => {
                        break;
                    }
                    Err(e) => {
                        eprintln!("Read from peer error: {e}");
                        receiver.stop_sending(h3::error::Code::H3_NO_ERROR);
                        break;
                    }
                }
            }
            // 接收关闭了，连带着发送也关闭
            tx.close_channel();
        }
    });

    // 等待所有任务完成（通常不会主动退出）
    tokio::select! {
        _ = event_task => (),
        _ = quic_conn.terminated() => (),
        _ = conn_close_monitor => (),
    }

    if let Err(e) = tokio::try_join!(send_task, recv_task) {
        eprintln!("Error: {e}");
    }

    // 清理
    // execute!(std::io::stdout(), LeaveAlternateScreen, DisableMouseCapture)?;
    terminal::disable_raw_mode()?;

    Ok(())
}

fn parse_username_password(options: &Options) -> Result<(String, String), Error> {
    let try_from_uri = |username_password: &str| {
        username_password
            .split_once(':')
            .map(|(username, password)| (username.to_string(), Some(password.to_string())))
            .unwrap_or((username_password.to_string(), None))
    };
    let (username, password) = options
        .uri
        .authority()
        .and_then(|authority| authority.as_str().rsplit_once('@'))
        .map(|(username_password, _host)| try_from_uri(username_password))
        .unwrap_or_else(|| (whoami::username(), None));

    let password = match password {
        Some(password) => password,
        None => rpassword::prompt_password(format!("Please input password for {username}: "))
            .map_err(|e| format!("Failed to read password: {e}"))?,
    };
    Ok((username, password))
}

async fn handle_event(mut tx: mpsc::Sender<TerminalMessage>) {
    let (cols, rows) = terminal::size().unwrap();
    _ = tx.send(TerminalMessage::WindowSize { rows, cols }).await;
    while let Some(Ok(event)) = EventStream::new().next().await {
        match event {
            Event::Resize(cols, rows) => {
                _ = tx.send(TerminalMessage::WindowSize { rows, cols }).await;
            }
            Event::Key(KeyEvent {
                code, modifiers, ..
            }) => {
                let send_result = match (code, modifiers) {
                    // Control 组合键
                    (KeyCode::Char('a'), KeyModifiers::CONTROL) => {
                        tx.send(TerminalMessage::ControlSequence("\x01".to_string()))
                            .await
                    }
                    (KeyCode::Char('b'), KeyModifiers::CONTROL) => {
                        tx.send(TerminalMessage::ControlSequence("\x02".to_string()))
                            .await
                    }
                    (KeyCode::Char('c'), KeyModifiers::CONTROL) => {
                        tx.send(TerminalMessage::Signal(2)).await
                    }
                    (KeyCode::Char('d'), KeyModifiers::CONTROL) => {
                        tx.send(TerminalMessage::ControlSequence("\x04".to_string()))
                            .await
                    }
                    (KeyCode::Char('e'), KeyModifiers::CONTROL) => {
                        tx.send(TerminalMessage::ControlSequence("\x05".to_string()))
                            .await
                    }
                    (KeyCode::Char('f'), KeyModifiers::CONTROL) => {
                        tx.send(TerminalMessage::ControlSequence("\x06".to_string()))
                            .await
                    }
                    (KeyCode::Char('g'), KeyModifiers::CONTROL) => {
                        tx.send(TerminalMessage::ControlSequence("\x07".to_string()))
                            .await
                    }
                    (KeyCode::Char('h'), KeyModifiers::CONTROL) => {
                        tx.send(TerminalMessage::ControlSequence("\x08".to_string()))
                            .await
                    }
                    (KeyCode::Char('i'), KeyModifiers::CONTROL) => {
                        tx.send(TerminalMessage::ControlSequence("\x09".to_string()))
                            .await
                    }
                    (KeyCode::Char('j'), KeyModifiers::CONTROL) => {
                        tx.send(TerminalMessage::ControlSequence("\x0a".to_string()))
                            .await
                    }
                    (KeyCode::Char('k'), KeyModifiers::CONTROL) => {
                        tx.send(TerminalMessage::ControlSequence("\x0b".to_string()))
                            .await
                    }
                    (KeyCode::Char('l'), KeyModifiers::CONTROL) => {
                        tx.send(TerminalMessage::ControlSequence("\x0c".to_string()))
                            .await
                    }
                    (KeyCode::Char('m'), KeyModifiers::CONTROL) => {
                        tx.send(TerminalMessage::ControlSequence("\x0d".to_string()))
                            .await
                    }
                    (KeyCode::Char('n'), KeyModifiers::CONTROL) => {
                        tx.send(TerminalMessage::ControlSequence("\x0e".to_string()))
                            .await
                    }
                    (KeyCode::Char('o'), KeyModifiers::CONTROL) => {
                        tx.send(TerminalMessage::ControlSequence("\x0f".to_string()))
                            .await
                    }
                    (KeyCode::Char('p'), KeyModifiers::CONTROL) => {
                        tx.send(TerminalMessage::ControlSequence("\x10".to_string()))
                            .await
                    }
                    (KeyCode::Char('q'), KeyModifiers::CONTROL) => {
                        tx.send(TerminalMessage::ControlSequence("\x11".to_string()))
                            .await
                    }
                    (KeyCode::Char('r'), KeyModifiers::CONTROL) => {
                        tx.send(TerminalMessage::ControlSequence("\x12".to_string()))
                            .await
                    }
                    (KeyCode::Char('s'), KeyModifiers::CONTROL) => {
                        tx.send(TerminalMessage::ControlSequence("\x13".to_string()))
                            .await
                    }
                    (KeyCode::Char('t'), KeyModifiers::CONTROL) => {
                        tx.send(TerminalMessage::ControlSequence("\x14".to_string()))
                            .await
                    }
                    (KeyCode::Char('u'), KeyModifiers::CONTROL) => {
                        tx.send(TerminalMessage::ControlSequence("\x15".to_string()))
                            .await
                    }
                    (KeyCode::Char('v'), KeyModifiers::CONTROL) => {
                        tx.send(TerminalMessage::ControlSequence("\x16".to_string()))
                            .await
                    }
                    (KeyCode::Char('w'), KeyModifiers::CONTROL) => {
                        tx.send(TerminalMessage::ControlSequence("\x17".to_string()))
                            .await
                    }
                    (KeyCode::Char('x'), KeyModifiers::CONTROL) => {
                        tx.send(TerminalMessage::ControlSequence("\x18".to_string()))
                            .await
                    }
                    (KeyCode::Char('y'), KeyModifiers::CONTROL) => {
                        tx.send(TerminalMessage::ControlSequence("\x19".to_string()))
                            .await
                    }
                    (KeyCode::Char('z'), KeyModifiers::CONTROL) => {
                        tx.send(TerminalMessage::ControlSequence("\x1a".to_string()))
                            .await
                    }
                    // 普通字符输入
                    (KeyCode::Char(c), _) => {
                        while let Ok(true) = event::poll(Duration::from_millis(0)) {
                            let _ = event::read();
                        }
                        tx.send(TerminalMessage::Text(c.to_string())).await
                    }
                    // 特殊键
                    (KeyCode::Enter, _) => {
                        while let Ok(true) = event::poll(Duration::from_millis(0)) {
                            let _ = event::read();
                        }
                        tx.send(TerminalMessage::Text("\n".to_string())).await
                    }
                    (KeyCode::Tab, _) => tx.send(TerminalMessage::Text("\t".to_string())).await,
                    (KeyCode::Backspace, _) => {
                        tx.send(TerminalMessage::ControlSequence("\x7f".to_string()))
                            .await
                    }
                    (KeyCode::Delete, _) => {
                        tx.send(TerminalMessage::ControlSequence("\x1b[3~".to_string()))
                            .await
                    }
                    (KeyCode::Esc, _) => {
                        tx.send(TerminalMessage::ControlSequence("\x1b".to_string()))
                            .await
                    }
                    // 方向键
                    (KeyCode::Up, _) => {
                        tx.send(TerminalMessage::ControlSequence("\x1b[A".to_string()))
                            .await
                    }
                    (KeyCode::Down, _) => {
                        tx.send(TerminalMessage::ControlSequence("\x1b[B".to_string()))
                            .await
                    }
                    (KeyCode::Right, _) => {
                        tx.send(TerminalMessage::ControlSequence("\x1b[C".to_string()))
                            .await
                    }
                    (KeyCode::Left, _) => {
                        tx.send(TerminalMessage::ControlSequence("\x1b[D".to_string()))
                            .await
                    }
                    // Home/End 键
                    (KeyCode::Home, _) => {
                        tx.send(TerminalMessage::ControlSequence("\x1b[H".to_string()))
                            .await
                    }
                    (KeyCode::End, _) => {
                        tx.send(TerminalMessage::ControlSequence("\x1b[F".to_string()))
                            .await
                    }
                    // Page Up/Down
                    (KeyCode::PageUp, _) => {
                        tx.send(TerminalMessage::ControlSequence("\x1b[5~".to_string()))
                            .await
                    }
                    (KeyCode::PageDown, _) => {
                        tx.send(TerminalMessage::ControlSequence("\x1b[6~".to_string()))
                            .await
                    }
                    _ => Ok(()),
                };
                // rx disconnected
                if send_result.is_err() {
                    break;
                }
            }
            _ => {}
        }
    }
}

fn client_parameters() -> gm_quic::ClientParameters {
    let mut params = gm_quic::ClientParameters::default();

    params.set_initial_max_streams_bidi(100u32);
    params.set_initial_max_streams_uni(100u32);
    params.set_initial_max_data(1u32 << 20);
    params.set_initial_max_stream_data_uni(1u32 << 20);
    params.set_initial_max_stream_data_bidi_local(1u32 << 20);
    params.set_initial_max_stream_data_bidi_remote(1u32 << 20);

    params
}
