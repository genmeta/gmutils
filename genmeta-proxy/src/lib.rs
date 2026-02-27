use std::{mem, sync::Arc};

use clap::Parser;
use genmeta_common::{bind, dns, id};
use genmeta_home::identity::Name;
use h3x::gm_quic::{BuildClientError, H3Client, prelude::handy::NoopLogger};
use snafu::{ResultExt, Snafu};
use tokio::net::TcpListener;
use tracing_subscriber::prelude::*;

#[derive(Parser, Debug, Clone)]
#[command(version, about)]
pub struct Options {
    /// Proxy listen address
    #[arg(long, default_value = "127.0.0.1:8080")]
    pub listen: std::net::SocketAddr,

    /// Client identity
    #[arg(long, value_name = "client_identity")]
    pub id: Option<Name<'static>>,

    /// DNS resolution schemes
    #[arg(long, value_name = "scheme", default_value = "system, mdns, http")]
    pub dns: Vec<dns::DnsScheme>,

    /// Bind patterns for DHTTP/3 connections
    #[arg(long = "interface", value_name = "bind", default_value = "*")]
    pub binds: Vec<bind::Bind>,

    /// Verbose output
    #[arg(short, long)]
    pub verbose: bool,

    /// Domain suffixes for H3 routing
    #[arg(long = "domain-suffix", default_value = ".genmeta.net")]
    pub domain_suffixes: Vec<String>,
}

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(transparent)]
    LocateGenmetaHome {
        source: genmeta_home::LocateGenmetaHomeError,
    },

    #[snafu(transparent)]
    BindConflict { source: bind::BindConflictError },

    #[snafu(display("failed to build DNS resolvers"))]
    BuildDnsResolvers { source: BuildClientError },

    #[snafu(display("failed to build HTTP/3 client"))]
    BuildClient { source: BuildClientError },

    #[snafu(display("failed to bind proxy listener"))]
    BindListener { source: std::io::Error },

    #[snafu(display("failed to connect to tunnel target `{addr}`"))]
    TunnelConnect {
        addr: String,
        source: std::io::Error,
    },

    #[snafu(display("failed to upgrade tunnel connection"))]
    TunnelUpgrade { source: hyper::Error },

    #[snafu(display("failed to connect to `{addr}`"))]
    ForwardConnect {
        addr: String,
        source: std::io::Error,
    },

    #[snafu(display("failed to perform HTTP handshake with `{addr}`"))]
    ForwardHandshake { addr: String, source: hyper::Error },

    #[snafu(display("failed to send HTTP request"))]
    ForwardSendRequest { source: hyper::Error },

    #[snafu(display("missing host in request"))]
    ForwardMissingHost {},

    #[snafu(transparent)]
    Whatever {
        source: genmeta_common::error::Whatever,
    },
}

impl snafu::FromString for Error {
    type Source = <genmeta_common::error::Whatever as snafu::FromString>::Source;

    fn without_source(message: String) -> Self {
        genmeta_common::error::Whatever::without_source(message).into()
    }

    fn with_source(source: Self::Source, message: String) -> Self {
        genmeta_common::error::Whatever::with_source(source, message).into()
    }
}

pub async fn run(mut options: Options) -> Result<(), Error> {
    let (stderr, _guard) = tracing_appender::non_blocking(std::io::stderr());
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_target(false)
                .with_timer(tracing_subscriber::fmt::time::LocalTime::rfc_3339())
                .with_writer(stderr),
        )
        .with(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(tracing_subscriber::filter::LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .init();

    let id = id::load_home_and_identity(
        options.id.is_some(),
        options
            .id
            .as_ref()
            .map(|id| (&"command line option" as &dyn std::fmt::Display, id.clone())),
    )
    .await?;

    let bind_setup = bind::setup_bind_interfaces_with(
        bind::Binds::new(mem::take(&mut options.binds)),
        dns::handy::ensure_default_mdns_prop,
    )
    .await?;

    let dns_setup = dns::handy::build_resolvers(
        options.dns.iter().copied(),
        &bind_setup.bind_interfaces,
        id.as_ref(),
    )
    .context(BuildDnsResolversSnafu)?;

    let client = match &id {
        Some(id) => H3Client::builder().with_identity(id.name().as_full(), id.certs(), id.key()),
        None => H3Client::builder().without_identity(),
    }
    .context(BuildClientSnafu)?
    .with_iface_manager(bind_setup.iface_manager)
    .with_resolver(Arc::new(dns_setup.resolvers))
    .bind(&bind_setup.bind_uris)
    .await
    .with_qlog(Arc::new(NoopLogger))
    .build();

    let listener = TcpListener::bind(options.listen)
        .await
        .context(BindListenerSnafu)?;

    tracing::info!(addr = %options.listen, "Proxy listening");

    loop {
        let (stream, addr) = listener.accept().await.context(BindListenerSnafu)?;
        tracing::debug!(%addr, "connection accepted");
        drop(stream);
        if options.verbose {
            tracing::debug!(%addr, "dropped connection");
        }
    }
}

pub mod forward;
pub mod h3_forward;
pub mod route;
pub mod tunnel;
