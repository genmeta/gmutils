use std::{
    io::{IsTerminal, Write as _},
    net::SocketAddr,
    str::FromStr,
    sync::Arc,
};

use clap::Parser;
use dhttp::{
    ddns::DnsScheme,
    dquic::{
        binds::BindPattern,
        net::{BindInterface, BindUri},
        qtraversal::{self, nat::client::StunClientsComponent},
    },
    endpoint::Endpoint,
    home::{self, DhttpHome, identity::IdentityHome},
    name::DhttpName as Name,
};
use futures::StreamExt;
use snafu::{IntoError, ResultExt};
use tracing_subscriber::prelude::*;

#[derive(Parser, Debug, Clone)]
#[command(name = "nat-detect", version, about)]
pub struct Options {
    /// Client identity
    #[arg(short, long)]
    pub id: Option<Name<'static>>,

    /// Skip identity loading and use anonymous mode
    #[arg(long, conflicts_with = "id")]
    pub anonymous: bool,

    /// Bind patterns for local network interfaces
    #[arg(long = "interface", value_name = "bind", default_value = "*",
          hide = cfg!(not(debug_assertions)))]
    pub binds: Vec<BindPattern>,

    /// Show detailed output
    #[arg(short, long)]
    pub verbose: bool,
}

#[derive(Debug, snafu::Snafu)]
#[snafu(module)]
pub enum Error {
    #[snafu(display("failed to locate dhttp home"))]
    LocateDhttpHome { source: home::LocateDhttpHomeError },

    #[snafu(display("failed to load explicit identity `{name}`"))]
    LoadExplicitIdentity {
        name: Name<'static>,
        source: home::identity::ssl::LoadIdentityError,
    },

    #[snafu(display("failed to load identity certificate and key"))]
    LoadIdentitySsl {
        source: home::identity::ssl::LoadIdentitySslError,
    },

    #[snafu(display(
        "failed to detect external address on `{bind_uri}` via STUN server {stun_server}"
    ))]
    DetectExternalAddr {
        bind_uri: Box<BindUri>,
        stun_server: SocketAddr,
        source: std::io::Error,
    },

    #[snafu(display("failed to detect NAT type on `{bind_uri}` via STUN server {stun_server}"))]
    DetectNatType {
        bind_uri: Box<BindUri>,
        stun_server: SocketAddr,
        source: std::io::Error,
    },

    #[snafu(display("no STUN client component found on interface `{bind_uri}`"))]
    NoStunClients { bind_uri: Box<BindUri> },

    #[snafu(display("no STUN agent discovered on interface `{bind_uri}`"))]
    NoStunAgent { bind_uri: Box<BindUri> },

    #[snafu(display("no NAT observation found among {candidates} candidate interfaces"))]
    NoNatObservation { candidates: usize },
}

struct NatObservation {
    bind_uri: BindUri,
    stun_server: SocketAddr,
    external_addr: SocketAddr,
    nat_type: qtraversal::nat::client::NatType,
}

type NatReport = Result<NatObservation, Error>;

struct NatSummary {
    candidates: usize,
    successes: usize,
    failures: usize,
}

impl NatSummary {
    fn new(candidates: usize) -> Self {
        Self {
            candidates,
            successes: 0,
            failures: 0,
        }
    }

    fn record(&mut self, report: &NatReport) {
        match report {
            Ok(_) => self.successes += 1,
            Err(_) => self.failures += 1,
        }
    }
}

fn init_tracing() -> tracing_appender::non_blocking::WorkerGuard {
    let (stderr, guard) = tracing_appender::non_blocking(std::io::stderr());
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(std::io::stderr().is_terminal())
                .with_timer(tracing_subscriber::fmt::time::LocalTime::rfc_3339())
                .with_writer(stderr),
        )
        .with(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(tracing_subscriber::filter::LevelFilter::INFO.into())
                .from_env_lossy()
                .add_directive(
                    "netlink_packet_route=error"
                        .parse()
                        .expect("BUG: static tracing directive is valid"),
                ),
        )
        .init();
    guard
}

pub async fn run(mut options: Options) -> Result<(), Error> {
    let _guard = init_tracing();
    diagnose_nat(&mut options).await
}

async fn load_identity_home(options: &Options) -> Result<Option<IdentityHome>, Error> {
    if options.anonymous {
        return Ok(None);
    }

    let home = match DhttpHome::load_from_environment() {
        Ok(home) => home,
        Err(source) if options.id.is_none() => {
            tracing::warn!(
                error = %snafu::Report::from_error(&source),
                "failed to locate dhttp home, using anonymous endpoint"
            );
            return Ok(None);
        }
        Err(source) => return Err(error::LocateDhttpHomeSnafu.into_error(source)),
    };

    if let Some(name) = &options.id {
        tracing::debug!(%name, "trying to load command line identity");
        return home
            .load_identity(name.clone())
            .await
            .context(error::LoadExplicitIdentitySnafu { name: name.clone() })
            .map(Some);
    }

    match home.load_default_identity().await {
        Ok(identity) => {
            tracing::debug!(name = %identity.name(), "using default identity");
            Ok(Some(identity))
        }
        Err(source) => {
            tracing::debug!(
                error = %snafu::Report::from_error(&source),
                "failed to load default identity, using anonymous endpoint"
            );
            Ok(None)
        }
    }
}

async fn diagnose_nat(options: &mut Options) -> Result<(), Error> {
    if options.verbose {
        qtraversal::nat::client::VISUALIZE_NAT_DETECTION
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }

    let identity_home = load_identity_home(options).await?;
    let identity = match &identity_home {
        Some(home) => Some(Arc::new(
            home.identity().await.context(error::LoadIdentitySslSnafu)?,
        )),
        None => None,
    };

    let bind_patterns = Arc::new(options.binds.clone());
    let endpoint = Endpoint::builder()
        .bind(bind_patterns)
        .maybe_identity(identity)
        .dns(DnsScheme::H3)
        .dns(DnsScheme::System)
        .build()
        .await;

    let interfaces = endpoint.network().interfaces();
    let candidates = interfaces.len();
    let show_failed_details = options.verbose || has_explicit_bind_patterns(&options.binds);
    let mut summary = NatSummary::new(candidates);
    let mut wrote_report = false;

    for iface in interfaces {
        for report in observe_interface(iface).await {
            summary.record(&report);
            if show_failed_details || report.is_ok() {
                print_nat_report(&report, wrote_report);
                wrote_report = true;
            }
        }
    }

    if show_failed_details && !wrote_report {
        let report = Err(Error::NoNatObservation { candidates });
        print_nat_report(&report, false);
    } else if !show_failed_details {
        print_nat_summary(&summary, wrote_report);
    }

    Ok(())
}

fn has_explicit_bind_patterns(binds: &[BindPattern]) -> bool {
    let default_bind = BindPattern::from_str("*").expect("BUG: static bind pattern is valid");
    binds != [default_bind]
}

async fn observe_interface(iface: BindInterface) -> Vec<NatReport> {
    let bind_uri = iface.bind_uri();
    let clients = iface.with_components(|components, _iface| {
        components.with(|clients: &StunClientsComponent| clients.clone())
    });
    let Some(clients) = clients else {
        return vec![Err(Error::NoStunClients {
            bind_uri: Box::new(bind_uri),
        })];
    };

    let mut tasks = clients.with_clients(|clients| {
        clients
            .values()
            .cloned()
            .map(|client| {
                let bind_uri = bind_uri.clone();
                async move {
                    let stun_server = client.agent_addr();
                    let external_addr =
                        client
                            .outer_addr()
                            .await
                            .context(error::DetectExternalAddrSnafu {
                                bind_uri: Box::new(bind_uri.clone()),
                                stun_server,
                            })?;
                    let nat_type = client.nat_type().await.context(error::DetectNatTypeSnafu {
                        bind_uri: Box::new(bind_uri.clone()),
                        stun_server,
                    })?;
                    Ok(NatObservation {
                        bind_uri,
                        stun_server,
                        external_addr,
                        nat_type,
                    })
                }
            })
            .collect::<futures::stream::FuturesUnordered<_>>()
    });

    if tasks.is_empty() {
        return vec![Err(Error::NoStunAgent {
            bind_uri: Box::new(bind_uri),
        })];
    }

    let mut observations = Vec::new();
    while let Some(observation) = tasks.next().await {
        observations.push(observation);
    }
    observations
}

fn print_nat_report(report: &NatReport, needs_separator: bool) {
    let mut output = String::new();
    write_nat_report(&mut output, report, needs_separator).expect("writing to String cannot fail");
    print!("{output}");
    std::io::stdout().flush().expect("failed to flush stdout");
}

fn print_nat_summary(summary: &NatSummary, needs_separator: bool) {
    let mut output = String::new();
    write_nat_summary(&mut output, summary, needs_separator)
        .expect("writing to String cannot fail");
    print!("{output}");
    std::io::stdout().flush().expect("failed to flush stdout");
}

fn write_nat_report(
    output: &mut impl std::fmt::Write,
    report: &NatReport,
    needs_separator: bool,
) -> std::fmt::Result {
    if needs_separator {
        writeln!(output)?;
    }

    match report {
        Ok(observation) => {
            writeln!(output, "Interface: {}", observation.bind_uri)?;
            writeln!(output, "STUN server: {}", observation.stun_server)?;
            writeln!(output, "NAT type: {:?}", observation.nat_type)?;
            writeln!(output, "External IP: {}", observation.external_addr.ip())?;
        }
        Err(error) => {
            if let Some(bind_uri) = error_bind_uri(error) {
                writeln!(output, "Interface: {bind_uri}")?;
            }
            if let Some(stun_server) = error_stun_server(error) {
                writeln!(output, "STUN server: {stun_server}")?;
            }
            writeln!(output, "Error: {}", snafu::Report::from_error(error))?;
        }
    }

    Ok(())
}

fn write_nat_summary(
    output: &mut impl std::fmt::Write,
    summary: &NatSummary,
    needs_separator: bool,
) -> std::fmt::Result {
    if needs_separator {
        writeln!(output)?;
    }

    if summary.successes == 0 {
        writeln!(
            output,
            "No NAT observation was detected among {} candidate {}.",
            summary.candidates,
            plural(summary.candidates, "interface", "interfaces")
        )?;
    } else {
        writeln!(
            output,
            "Detected NAT on {} {}.",
            summary.successes,
            plural(summary.successes, "interface", "interfaces")
        )?;
    }

    if summary.failures == 0 {
        return Ok(());
    }

    writeln!(
        output,
        "Skipped {} failed interface {}.",
        summary.failures,
        plural(summary.failures, "probe", "probes")
    )?;
    writeln!(
        output,
        "Use -v to show failed interface details, or pass --interface <bind-pattern> to select matching interfaces."
    )?;

    Ok(())
}

fn plural(count: usize, singular: &'static str, plural: &'static str) -> &'static str {
    if count == 1 { singular } else { plural }
}

fn error_bind_uri(error: &Error) -> Option<&BindUri> {
    match error {
        Error::DetectExternalAddr { bind_uri, .. }
        | Error::DetectNatType { bind_uri, .. }
        | Error::NoStunClients { bind_uri }
        | Error::NoStunAgent { bind_uri } => Some(bind_uri),
        Error::LocateDhttpHome { .. }
        | Error::LoadExplicitIdentity { .. }
        | Error::LoadIdentitySsl { .. }
        | Error::NoNatObservation { .. } => None,
    }
}

fn error_stun_server(error: &Error) -> Option<SocketAddr> {
    match error {
        Error::DetectExternalAddr { stun_server, .. }
        | Error::DetectNatType { stun_server, .. } => Some(*stun_server),
        Error::LocateDhttpHome { .. }
        | Error::LoadExplicitIdentity { .. }
        | Error::LoadIdentitySsl { .. }
        | Error::NoStunClients { .. }
        | Error::NoStunAgent { .. }
        | Error::NoNatObservation { .. } => None,
    }
}

#[cfg(test)]
mod tests {
    use std::{io, net::SocketAddr};

    use dhttp::dquic::{net::BindUri, qtraversal::nat::client::NatType};

    use super::*;

    #[test]
    fn write_nat_report_prints_failures_without_hiding_successes() {
        let failed_bind_uri = BindUri::from("iface://v4.fail0:0");
        let failed_stun_server: SocketAddr =
            "192.0.2.10:20004".parse().expect("valid socket address");
        let success_bind_uri = BindUri::from("iface://v4.ok0:0");
        let success_stun_server: SocketAddr =
            "192.0.2.20:20004".parse().expect("valid socket address");

        let reports = [
            Err(Error::DetectExternalAddr {
                bind_uri: Box::new(failed_bind_uri),
                stun_server: failed_stun_server,
                source: io::Error::new(io::ErrorKind::TimedOut, "probe timed out"),
            }),
            Ok(NatObservation {
                bind_uri: success_bind_uri,
                stun_server: success_stun_server,
                external_addr: "203.0.113.7:51820".parse().expect("valid socket address"),
                nat_type: NatType::FullCone,
            }),
        ];

        let mut output = String::new();
        write_nat_report(&mut output, &reports[0], false).expect("writing to String cannot fail");
        write_nat_report(&mut output, &reports[1], true).expect("writing to String cannot fail");

        assert!(output.contains("Interface: iface://v4.fail0:0"));
        assert!(output.contains("Error: failed to detect external address"));
        assert!(output.contains("probe timed out"));
        assert!(output.contains("Interface: iface://v4.ok0:0"));
        assert!(output.contains("NAT type: FullCone"));
        assert!(output.contains("External IP: 203.0.113.7"));
    }

    #[test]
    fn write_nat_report_renders_one_report_independently() {
        let report = Ok(NatObservation {
            bind_uri: BindUri::from("iface://v4.ok0:0"),
            stun_server: "192.0.2.20:20004".parse().expect("valid socket address"),
            external_addr: "203.0.113.7:51820".parse().expect("valid socket address"),
            nat_type: NatType::FullCone,
        });
        let mut output = String::new();

        write_nat_report(&mut output, &report, false).expect("writing to String cannot fail");

        assert_eq!(
            output,
            "Interface: iface://v4.ok0:0/\n\
             STUN server: 192.0.2.20:20004\n\
             NAT type: FullCone\n\
             External IP: 203.0.113.7\n"
        );
    }

    #[test]
    fn write_nat_summary_uses_concise_failure_count() {
        let reports = [
            Ok(NatObservation {
                bind_uri: BindUri::from("iface://v4.ok0:0"),
                stun_server: "192.0.2.20:20004".parse().expect("valid socket address"),
                external_addr: "203.0.113.7:51820".parse().expect("valid socket address"),
                nat_type: NatType::FullCone,
            }),
            Err(Error::NoStunAgent {
                bind_uri: Box::new(BindUri::from("iface://v4.veth0:0")),
            }),
            Err(Error::DetectExternalAddr {
                bind_uri: Box::new(BindUri::from("iface://v4.br0:0")),
                stun_server: "192.0.2.20:20004".parse().expect("valid socket address"),
                source: io::Error::new(io::ErrorKind::TimedOut, "probe timed out"),
            }),
        ];
        let summary = reports
            .iter()
            .fold(NatSummary::new(3), |mut summary, report| {
                summary.record(report);
                summary
            });
        let mut output = String::new();

        write_nat_summary(&mut output, &summary, true).expect("writing to String cannot fail");

        assert!(output.contains("Detected NAT on 1 interface."));
        assert!(output.contains("Skipped 2 failed interface probes."));
        assert!(
            output.contains(
                "Use -v to show failed interface details, or pass --interface <bind-pattern> to select matching interfaces."
            )
        );
        assert!(!output.contains("did not discover a STUN agent"));
        assert!(!output.contains("did not receive a response from the STUN server"));
    }
}
