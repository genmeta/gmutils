use std::{fmt::Debug, net::SocketAddr, sync::Arc, time::Duration};

mod auth;
mod mux;
mod socks;
mod terminal;

use clap::Parser;
use genmeta_common::{
    AGENTS, ROOT_CERT, Resolvers, cbor_codec,
    h3_stream::{self, H3Stream},
};
use gm_quic::{QuicClient, ToCertificate};
use http::Uri;
use qdns::{Resolve, UdpResolver};
use qtraversal::iface::TraversalFactory;
use tokio::{net::TcpListener, task::JoinSet, time};
use tokio_util::{codec, io::StreamReader};

const URI_LONG_HELP: &str = "Example: `developer@ssh3.test.genmeta.net`
Scheme is optional, only `ssh3` is accepted.
Username is optional, if not present, use current user.
Password is optional, if not present, prompt for it.
Path is optional, if not present, use `/ssh` as default.";

const DYNAMIC_FORWARD_LONG_HELP: &str = "Example: `12345`, `127.0.0.1:12335`
Specify a local address port, which will forward the accepted TCP connection to the server's SOCKS server.
You can specify just the port, and the bind_address defaults to 127.0.0.1.";

#[derive(Parser, Debug, Clone)]
#[command(version, about)]
pub struct Options {
    #[arg(value_name = "[ssh3://][[username][:password]@]host[:port][path]", long_help = URI_LONG_HELP)]
    uri: Uri,
    #[arg(short = 'D', value_name = "[bind_address:]port", long_help = DYNAMIC_FORWARD_LONG_HELP)]
    dynamic_forward: Option<String>,

    #[arg(short = 'o', value_delimiter = ',')]
    options: Vec<String>,

    #[arg(
        short = 'T',
        default_value_t = true,
        action = clap::ArgAction::SetFalse,
        help = "Disable pseudo-terminal allocation."
    )]
    pseudo: bool,

    #[arg(
        trailing_var_arg = true,
        value_name = "[command [argument ...]]",
        help = "Command to execute on the remote server"
    )]
    commands: Vec<String>,
}

impl Options {
    fn complete_uri(self) -> Result<Self, Error> {
        let mut uri_parts = self.uri.into_parts();
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
                tracing::warn!(target: "connect", "Path is empty, using `/ssh` as default");
                Some("/ssh".parse().unwrap())
            }
            path_and_query => path_and_query,
        };
        Ok(Self {
            uri: Uri::from_parts(uri_parts)?,
            ..self
        })
    }

    fn username_password(&self) -> (String, Option<String>) {
        let try_from_uri = |username_password: &str| {
            username_password
                .split_once(':')
                .map(|(username, password)| (username.to_string(), Some(password.to_string())))
                .unwrap_or((username_password.to_string(), None))
        };
        self.uri
            .authority()
            .and_then(|authority| authority.as_str().rsplit_once('@'))
            .map(|(username_password, _host)| try_from_uri(username_password))
            .unwrap_or_else(|| (whoami::username(), None))
    }
}

type Error = Box<dyn core::error::Error + Send + Sync>;

struct TerminalGuard(());

impl TerminalGuard {
    pub fn new() -> Self {
        tracing::info!(target: "terminal", "Enable raw mode");
        crossterm::terminal::enable_raw_mode().expect("Failed to enable raw mode");
        TerminalGuard(())
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        tracing::info!(target: "terminal", "Disable raw mode(RAII)");
        crossterm::terminal::disable_raw_mode().expect("Failed to disable raw mode");
    }
}

pub async fn run(options: Options) -> Result<(), Error> {
    let options = options
        .complete_uri()
        .map_err(|e| format!("Failed to complete URI: {e:?}"))?;

    let dynamic_forward_server = match options.dynamic_forward_server().transpose()? {
        Some(bind_addr) => Some(
            TcpListener::bind(bind_addr)
                .await
                .map_err(|e| format!("Failed to bind local dynamic forward server: {e:?}"))?,
        ),
        None => None,
    };

    let resolvers = Resolvers::new()
        // .with(HttpResolver::new("http://127.0.0.1:20004/v1/dns/")?)
        .with(UdpResolver::new(Resolvers::UDP_DNS_SERVER));
    // let resolver = UdpResolver::new("1.12.74.4:5300".parse().unwrap());
    let server_name = options.uri.host().ok_or("Missing host in uri")?;
    let server_addrs = resolvers
        .lookup(server_name)
        .await
        .map_err(|e| format!("failed to resolve host {server_name}: {e:?}"))?;

    tracing::info!(target: "connect", "resolved {} to address: {:?}", server_name, server_addrs);

    let quic_client = {
        let mut roots = rustls::RootCertStore::empty();
        roots.add_parsable_certificates(ROOT_CERT.to_certificate());

        let factory = TraversalFactory::with(&AGENTS);
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
                tracing::error!("bind addrs {binds:?} failed: {e:?}");
            })?
            .build()
    };

    let (quic_conn, mut h3_conn, mut h3_client) = {
        tracing::info!(target: "connect", server_name, ?server_addrs, "connect to server");
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
                    tracing::error!(target: "connect", "attempt connect to server {server_addr} failed: error");
                    connect_result = Err(error)
                }
            }
        }
        connect_result?
    };

    let request = http::Request::builder()
        .method("PUT")
        .uri(options.uri.clone())
        .body(())?;
    tracing::info!(target: "connect", ?request, "request");

    // sending request results in a bidirectional stream,
    // which is also used for receiving response
    let mut stream = h3_client.send_request(request).await?;
    let response = stream.recv_response().await?;
    tracing::info!(target: "connect", ?response, "received");
    if response.status() != 200 {
        return Err(format!("Server response status: {}", response.status()).into());
    }

    let (sender, recver) = stream.split();
    let (mux, _incomings) = mux::Mux::new(
        mux::Role::Client,
        codec::FramedRead::new(
            StreamReader::new(H3Stream::new(recver)),
            cbor_codec::CborDecoder::default(),
        ),
        codec::FramedWrite::new(
            h3_stream::H3Sink::new(sender),
            cbor_codec::CborEncoder::default(),
        ),
    );

    let run = async move {
        let (username, password) = options.username_password();

        let mut channels = JoinSet::new();

        auth::login(&mux, &username, password.as_deref())
            .await
            .map_err(|e| format!("Failed to login: {e:?}"))?;

        channels.spawn({
            let mux = mux.clone();
            let command = options.command();
            async move {
                // 初始化终端。guard自动释放
                let _raw_terminal_guard = TerminalGuard::new();
                if let Err(e) = command.run(&mux, options.pseudo).await {
                    tracing::error!(target: "terminal", "Failed to run command: {e:?}");
                }
            }
        });

        if let Some(socks_listener) = dynamic_forward_server {
            let server = Arc::new(socks::SocksForwardServer::new(mux.clone()));
            channels.spawn({
                let server = server.clone();
                async move {
                    let error = server.listen(socks_listener).await;
                    tracing::error!(target: "socks", "Socks forward server error: {error:?}");
                }
            });
        }

        channels.join_all().await;

        Result::<(), Error>::Ok(())
    };

    let error = tokio::select! {
        // send heartbeat messages to keep ssh connection alive
        result = run => result.err(),
        // wait for the quic connection to be terminated
        _ = quic_conn.terminated() => None,
        // wait for the h3 connection to be closed
        _ = h3_conn.wait_idle() => None,
    };

    // 清理
    quic_conn.close("Bye bye".into(), h3::error::Code::H3_NO_ERROR.value());

    error.map_or(Ok(()), Err)
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
