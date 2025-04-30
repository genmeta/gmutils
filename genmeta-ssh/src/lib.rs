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
use tokio::time;
use tracing::{error, info};

// 定义客户端与服务器通信的消息结构
#[derive(Serialize, Deserialize, Debug)]
enum TerminalMessage {
    Text(String),
    WindowSize { rows: u16, cols: u16 },
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

    let mut connect_result = Result::Err(Error::from("Dns not found"));
    for addr in addrs {
        let connect = async {
            let quic_conn = quic_client.connect(server_name, addr)?;
            let (h3_conn, h3_client) =
                h3::client::new(h3_shim::QuicConnection::new(quic_conn.clone()).await).await?;
            Result::<_, Error>::Ok((quic_conn, h3_conn, h3_client))
        };
        match time::timeout(Duration::from_secs(3), connect).await {
            Ok(Ok(connect)) => {
                connect_result = Ok(connect);
                break;
            }
            Ok(Err(error)) => connect_result = Err(error),
            Err(_timeout) => connect_result = Err("Connect timeout".into()),
        }
    }

    let (quic_conn, mut h3_conn, mut h3_client) = connect_result?;
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
    // 初始化发送窗口大小
    let (cols, rows) = terminal::size().unwrap();
    _ = tx.send(TerminalMessage::WindowSize { rows, cols }).await;

    while let Some(Ok(event)) = EventStream::new().next().await {
        match event {
            // 处理窗口大小变化
            Event::Resize(cols, rows) => {
                _ = tx.send(TerminalMessage::WindowSize { rows, cols }).await;
            }

            // 处理键盘事件
            Event::Key(KeyEvent {
                code, modifiers, ..
            }) => {
                // 处理键盘事件并转换为相应的终端消息
                let message = match key_event_to_terminal_message(code, modifiers) {
                    Some(msg) => msg,
                    None => continue, // 不处理不支持的按键
                };

                // 发送终端消息
                let send_result = tx.send(message).await;

                // 检查连接是否断开
                if send_result.is_err() {
                    break;
                }
            }

            // 忽略其他类型的事件
            _ => {}
        }
    }
}

/// 将键盘事件转换为终端消息
fn key_event_to_terminal_message(
    code: KeyCode,
    modifiers: KeyModifiers,
) -> Option<TerminalMessage> {
    match (code, modifiers) {
        // 普通字符直接发送为文本
        (KeyCode::Char(c), KeyModifiers::NONE) => {
            // 清空输入缓冲区，避免输入延迟
            while let Ok(true) = event::poll(Duration::from_millis(0)) {
                let _ = event::read();
            }
            Some(TerminalMessage::Text(c.to_string()))
        }

        // 回车和Tab特殊处理
        (KeyCode::Enter, _) => {
            // 清空输入缓冲区，避免输入延迟
            while let Ok(true) = event::poll(Duration::from_millis(0)) {
                let _ = event::read();
            }
            Some(TerminalMessage::Text("\n".to_string()))
        }
        (KeyCode::Tab, _) => Some(TerminalMessage::Text("\t".to_string())),

        // Ctrl+C 特殊处理 - 发送 SIGINT 字符
        (KeyCode::Char('c'), m) if m == KeyModifiers::CONTROL => {
            Some(TerminalMessage::ControlSequence("\x03".to_string()))
        }

        // 其他所有键使用控制序列函数处理
        (code, modifiers) => {
            key_event_to_control_sequence(code, modifiers).map(TerminalMessage::ControlSequence)
        }
    }
}

/// 将键盘事件转换为控制序列
fn key_event_to_control_sequence(code: KeyCode, modifiers: KeyModifiers) -> Option<String> {
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

        // 未识别的格式，返回原序列
        base_sequence.to_string()
    }

    match code {
        // Ctrl+字母键：特殊处理，生成ASCII控制字符
        KeyCode::Char(c)
            if modifiers.contains(KeyModifiers::CONTROL) && c.is_ascii_alphabetic() =>
        {
            let ctrl_code = (c.to_ascii_lowercase() as u8 & 0x1f) as char;
            Some(ctrl_code.to_string())
        }

        // Alt+字符键：特殊处理，前缀为ESC
        KeyCode::Char(c) if modifiers.contains(KeyModifiers::ALT) => Some(format!("\x1b{c}")),

        // 普通字符键带其他修饰键：不处理，返回None
        KeyCode::Char(_) if modifiers != KeyModifiers::NONE => None,

        // 基本控制键
        KeyCode::Backspace => Some("\x7f".to_string()),
        KeyCode::Delete => Some(with_modifiers("\x1b[3~", modifiers)),
        KeyCode::Esc => Some("\x1b".to_string()),
        // Enter和Tab由上层代码特殊处理

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
