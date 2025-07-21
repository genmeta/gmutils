use clap::Parser;

#[derive(Parser, Debug, Clone)]
#[command(version)]
enum Options {
    Ssh3(genmeta_ssh3::Options),
    Curl(genmeta_curl::Options),
    Nslookup(genmeta_nslookup::Options),
    Discover(genmeta_discover::Options),
    NatDetect(genmeta_nat::Options),
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(tracing_subscriber::filter::LevelFilter::OFF.into())
                .from_env_lossy(),
        )
        .with_writer(std::io::stderr)
        .init();

    if let Err(error) = run(Options::parse()).await {
        eprintln!("{error}");
        tracing::error!("Error: {error}");
        std::process::exit(1);
    }
}

async fn run(options: Options) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match options {
        Options::Ssh3(options) => genmeta_ssh3::run(options).await,
        Options::Curl(options) => genmeta_curl::run(options).await,
        Options::Nslookup(options) => Ok(genmeta_nslookup::run(options).await?),
        Options::Discover(options) => genmeta_discover::run(options).await,
        Options::NatDetect(options) => genmeta_nat::run(options).await,
    }
}
