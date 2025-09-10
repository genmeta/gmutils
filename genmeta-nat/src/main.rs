use clap::Parser;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(tracing_subscriber::filter::LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .with_writer(std::io::stderr)
        .init();
    if let Err(error) = genmeta_nat::run(genmeta_nat::Options::parse()).await {
        eprintln!("{error}");
        tracing::error!("Exit with error: {}", error);
        std::process::exit(1);
    }
}
