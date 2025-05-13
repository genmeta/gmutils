use std::{io::Write, net::SocketAddr, time::Duration};

use bytes::{Buf, Bytes};
use clap::Parser;
use crossterm::{
    event::{self, Event, EventStream, KeyCode, KeyEvent, KeyModifiers},
    execute,
    terminal::{self},
};
use futures::{SinkExt, StreamExt, channel::mpsc};
use gm_quic::{QuicClient, ToCertificate};
use http::Uri;
use qdns::{Resolve, UdpResolver};
use qtraversal::iface::TraversalFactory;
use serde::{Deserialize, Serialize};
use tokio::time;
use tracing::{error, info};

// 定义客户端与服务器通信的消息结构
#[derive(Serialize, Deserialize, Debug)]
enum TerminalMessage {
    WindowSize { rows: u16, cols: u16 },
    ControlSequence(String),
    Heartbeat,
}

const URI_HELP: &str = "Example: `ssh3://user:password@host:port/ssh`.
    Scheme is optional, only `ssh3` is accepted.
    Username is optional, if not present, use current user.
    Password is optional, if not present, prompt for it.
    Path is optional, if not present, use `/ssh` as default.";

#[derive(Parser, Debug, Clone)]
#[command(version, about)]
pub struct Options {
    #[arg(help = URI_HELP)]
    uri: Uri,
}

type Error = Box<dyn core::error::Error + Send + Sync>;

pub async fn run(mut options: Options) -> Result<(), Error> {
    options.uri = {
        let mut uri_parts = options.uri.into_parts();
        uri_parts.scheme = match uri_parts.scheme {
            Some(ref scheme) if scheme.as_str() == "ssh3" => uri_parts.scheme,
            None => Some("ssh3".parse().unwrap()),
            Some(scheme) => {
                let message = format!(
                    "Unsupported scheme `{scheme}` for ssh. Scheme in uri is must not be present or be `ssh3`"
                );
                return Err(message.into());
            }
        };
        uri_parts.path_and_query = match uri_parts.path_and_query {
            root if root.as_ref().is_none_or(|path| path == "/") => {
                tracing::warn!("Path is empty, using `/ssh` as default");
                Some("/ssh".parse().unwrap())
            }
            path_and_query => path_and_query,
        };
        Uri::from_parts(uri_parts)?
    };

    // 创建通道用于异步通信
    let (mut tx, rx) = mpsc::channel::<TerminalMessage>(32);

    // 启动事件监听任务。不需要要await因为它结束时程序也结束了
    let _event_task = tokio::spawn(handle_event(tx.clone()));

    let resolver = UdpResolver::new("1.12.74.4:5300".parse().unwrap());
    let server_name = options.uri.host().ok_or("Missing host in uri")?;
    let server_addrs = resolver.lookup(server_name).await?;

    info!("resolved {} to address: {:?}", server_name, server_addrs);

    let quic_client = {
        let mut roots = rustls::RootCertStore::empty();
        roots.add_parsable_certificates(include_bytes!("../../root.crt").to_certificate());

        let factory = TraversalFactory::with(&[
            "1.12.74.4:20004".parse().unwrap(),
            "[2402:4e00:c011:1700:8624:7e0:5c9a:2]:20004"
                .parse()
                .unwrap(),
        ]);
        let binds = factory
            .devices()
            .keys()
            .map(|device_ip| SocketAddr::new(*device_ip, 0))
            .collect::<Vec<_>>();
        QuicClient::builder()
            .with_root_certificates(roots)
            .without_cert()
            .with_alpns(["h3"])
            .with_iface_factory(factory)
            .with_parameters(client_parameters())
            .enable_sslkeylog()
            .reuse_address()
            .bind(&binds[..])
            .inspect_err(|e| {
                error!("bind addrs: {binds:?}  err {e:?}");
            })?
            .build()
    };

    let (quic_conn, mut h3_conn, mut h3_client) = {
        info!(server_name, ?server_addrs, "connect to server");
        let mut connect_result = Result::Err(Error::from("Dns not found"));
        for server_addr in server_addrs {
            let attempt = async {
                let quic_conn = quic_client.connect(server_name, server_addr)?;
                let connect = async {
                    h3::client::new(h3_shim::QuicConnection::new(quic_conn.clone()).await).await
                };
                #[rustfmt::skip] // https://github.com/rust-lang/rustfmt/issues/6564
                let (h3_conn, h3_client) = time::timeout(Duration::from_secs(3), connect)
                    .await
                    .map_err(|_| {
                        quic_conn.close("connect timeout".into(), 0);
                        "connect timeout"
                })??;
                Result::<_, Error>::Ok((quic_conn, h3_conn, h3_client))
            };
            match attempt.await {
                Ok(connect) => {
                    connect_result = Ok(connect);
                    break;
                }
                Err(error) => {
                    tracing::error!("attempt connect to server {server_addr} failed: error");
                    connect_result = Err(error)
                }
            }
        }
        connect_result?
    };

    // 构建 Basic Auth 头
    let (username, password) = parse_username_password(&options).await?;
    let basic_auth = {
        use base64::Engine;
        let credentials = match password {
            Some(password) => format!("{username}:{password}"),
            None => username,
        };
        base64::engine::general_purpose::STANDARD.encode(credentials.as_bytes())
    };

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
    if response.status() != 200 {
        return Err(format!("Server response status: {}", response.status()).into());
    }

    // 初始化终端
    // execute!(std::io::stdout(), EnterAlternateScreen, EnableMouseCapture)?;
    terminal::enable_raw_mode()?;

    let (sender, receiver) = stream.split();

    tokio::select! {
        // read and encode messages from stdin
        // _ = event_task => (),
        // write messages to the stream
        _ = tokio::spawn(send(sender, rx)) => (),
        // receive data from the stream and write to stdout
        _ = tokio::spawn(recv(receiver)) => (),
        // wait for the quic connection to be terminated
        _ = quic_conn.terminated() => (),
        // wait for the h3 connection to be closed
        _ = h3_conn.wait_idle() => (),
    }
    // close the input channel when the connection is closed
    tx.close_channel();

    // 清理
    terminal::disable_raw_mode()?;

    Ok(())
}

async fn send(
    mut sender: h3::client::RequestStream<h3_shim::SendStream<Bytes>, Bytes>,
    mut rx: mpsc::Receiver<TerminalMessage>,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(30));
    loop {
        tokio::select! {
            msg = rx.next() => match msg {
                Some(msg) => {
                    let serialized = serde_json::to_vec(&msg).unwrap();
                    if let Err(e) = sender.send_data(serialized.into()).await {
                        tracing::error!("Send to peer error: {e}");
                        break;
                    }
                }
                None => {
                    if let Err(e) = sender.finish().await {
                        tracing::error!("Finish stream error: {e}");
                    }
                    break;
                }
            },
            _ = interval.tick() => {
                let serialized = serde_json::to_vec(&TerminalMessage::Heartbeat).unwrap();
                if let Err(e) = sender.send_data(serialized.into()).await {
                    tracing::error!("Send heartbeat error: {e}");
                    break;
                }
            }
        }
    }
}

async fn recv(mut receiver: h3::client::RequestStream<h3_shim::RecvStream, Bytes>) {
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
                tracing::error!("Read from peer error: {e}");
                receiver.stop_sending(h3::error::Code::H3_NO_ERROR);
                break;
            }
        }
    }
}

async fn parse_username_password(options: &Options) -> Result<(String, Option<String>), Error> {
    let try_from_uri = |username_password: &str| {
        username_password
            .split_once(':')
            .map(|(username, password)| (username.to_string(), Some(password.to_string())))
            .unwrap_or((username_password.to_string(), None))
    };
    Ok(options
        .uri
        .authority()
        .and_then(|authority| authority.as_str().rsplit_once('@'))
        .map(|(username_password, _host)| try_from_uri(username_password))
        .unwrap_or_else(|| (whoami::username(), None)))
}

async fn handle_event(mut tx: mpsc::Sender<TerminalMessage>) {
    // 初始化发送窗口大小
    let (cols, rows) = terminal::size().unwrap();
    _ = tx.send(TerminalMessage::WindowSize { rows, cols }).await;

    let mut event_stream = EventStream::new();
    while let Some(Ok(event)) = event_stream.next().await {
        let message = match event {
            // 处理窗口大小变化
            Event::Resize(cols, rows) => TerminalMessage::WindowSize { rows, cols },
            // 发送剪切板内容
            Event::Paste(text) => TerminalMessage::ControlSequence(text),
            // 处理键盘事件
            Event::Key(KeyEvent {
                code, modifiers, ..
            }) => {
                tracing::trace!("key event: {code:?} {modifiers:?}");
                match (code, modifiers).try_into() {
                    Ok(message) => message,
                    Err(()) => continue, // 不处理不支持的按键
                }
            }
            // 忽略其他类型的事件
            _ => continue,
        };
        // 发送终端消息
        let send_result = tx.send(message).await;

        // 检查连接是否断开
        if send_result.is_err() {
            break;
        }
    }
}

impl TryFrom<(KeyCode, KeyModifiers)> for TerminalMessage {
    type Error = ();

    fn try_from((code, modifiers): (KeyCode, KeyModifiers)) -> Result<Self, Self::Error> {
        // 清空输入缓冲区，避免输入延迟
        while let Ok(true) = event::poll(Duration::from_millis(0)) {
            let _ = event::read();
        }

        // 对所有键盘事件统一处理：转换为适当的序列
        Ok(TerminalMessage::ControlSequence(
            key_event_to_sequence(code, modifiers).ok_or(())?,
        ))
    }
}

/// 将键盘事件转换为控制序列或文本
fn key_event_to_sequence(code: KeyCode, modifiers: KeyModifiers) -> Option<String> {
    // 计算修饰键的数值
    fn calculate_modifier_value(modifiers: KeyModifiers) -> u8 {
        let mut value = 0;
        if modifiers.contains(KeyModifiers::SHIFT) {
            value |= 1;
        }
        if modifiers.contains(KeyModifiers::ALT) {
            value |= 2;
        }
        if modifiers.contains(KeyModifiers::CONTROL) {
            value |= 4;
        }
        value
    }

    // 根据基础序列和修饰键生成完整的控制序列
    fn with_modifiers(base_sequence: &str, modifiers: KeyModifiers) -> String {
        let mod_value = calculate_modifier_value(modifiers);

        // 无修饰键时直接返回基础序列
        if mod_value == 0 {
            return base_sequence.to_string();
        }

        // 处理特殊格式的序列（F1-F4使用O前缀）
        if base_sequence.starts_with("\x1bO") && base_sequence.len() == 3 {
            let key_char = base_sequence.chars().last().unwrap();
            return format!("\x1b[1;{}{}", mod_value + 1, key_char);
        }

        // 处理标准CSI序列
        if base_sequence.starts_with("\x1b[") {
            if let Some(pos) = base_sequence.find(|c: char| {
                c == '~' || c == 'A' || c == 'B' || c == 'C' || c == 'D' || c == 'H' || c == 'F'
            }) {
                let prefix = &base_sequence[2..pos];
                let suffix = &base_sequence[pos..];

                // 处理含数字的序列（如F5-F12, PageUp等）
                if prefix.chars().all(|c| c.is_ascii_digit()) {
                    return format!("\x1b[{};{}{}", prefix, mod_value + 1, suffix);
                } else {
                    // 处理不含数字的序列（如方向键）
                    return format!("\x1b[1;{}{}", mod_value + 1, suffix);
                }
            }
        }

        // 字符键的修饰键处理 - 使用 CSI u 格式（更标准的字符修饰键格式）
        if base_sequence.len() == 1 {
            let char_code = base_sequence.chars().next().unwrap() as u32;
            return format!("\x1b[{};{}u", char_code, mod_value + 1);
        }

        // 未识别的格式，返回原序列
        base_sequence.to_string()
    }

    match code {
        // 字符键的统一处理 - 包括普通字符和带修饰键的字符
        KeyCode::Char(c) => {
            // 处理无修饰键的普通字符
            if modifiers == KeyModifiers::NONE || modifiers == KeyModifiers::SHIFT {
                // 直接返回字符本身
                return Some(c.to_string());
            }

            // Ctrl+字母键：生成ASCII控制字符
            if modifiers == KeyModifiers::CONTROL && c.is_ascii_alphabetic() {
                let ctrl_code = (c.to_ascii_lowercase() as u8 & 0x1f) as char;
                return Some(ctrl_code.to_string());
            }

            // Alt+字符键：ESC前缀
            if modifiers == KeyModifiers::ALT {
                return Some(format!("\x1b{c}"));
            }

            // 其他修饰键组合：使用标准 CSI u 格式
            let char_code = c as u32;
            let mod_value = calculate_modifier_value(modifiers) + 1;
            Some(format!("\x1b[{char_code};{mod_value}u"))
        }

        // 基本控制键
        KeyCode::Backspace => Some("\x7f".to_string()),
        KeyCode::Delete => Some(with_modifiers("\x1b[3~", modifiers)),
        KeyCode::Esc => Some("\x1b".to_string()),

        // Enter和Tab现在也通过这里处理，而不是特殊处理
        KeyCode::Enter => Some("\r".to_string()),
        KeyCode::Tab => Some("\t".to_string()),

        // 方向键
        KeyCode::Up => Some(with_modifiers("\x1b[A", modifiers)),
        KeyCode::Down => Some(with_modifiers("\x1b[B", modifiers)),
        KeyCode::Right => Some(with_modifiers("\x1b[C", modifiers)),
        KeyCode::Left => Some(with_modifiers("\x1b[D", modifiers)),

        // 其他控制键
        KeyCode::Home => Some(with_modifiers("\x1b[H", modifiers)),
        KeyCode::End => Some(with_modifiers("\x1b[F", modifiers)),
        KeyCode::PageUp => Some(with_modifiers("\x1b[5~", modifiers)),
        KeyCode::PageDown => Some(with_modifiers("\x1b[6~", modifiers)),
        KeyCode::Insert => Some(with_modifiers("\x1b[2~", modifiers)),

        // 功能键 F1-F12
        KeyCode::F(n) => {
            let base = match n {
                1 => "\x1bOP",
                2 => "\x1bOQ",
                3 => "\x1bOR",
                4 => "\x1bOS",
                5 => "\x1b[15~",
                6 => "\x1b[17~",
                7 => "\x1b[18~",
                8 => "\x1b[19~",
                9 => "\x1b[20~",
                10 => "\x1b[21~",
                11 => "\x1b[23~",
                12 => "\x1b[24~",
                _ => return None, // 不支持的功能键
            };
            Some(with_modifiers(base, modifiers))
        }

        // 不支持的按键
        _ => None,
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
