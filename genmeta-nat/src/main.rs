use clap::Parser;
#[tokio::main(flavor = "current_thread")]
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
        eprintln!("ERROR: {error}");
        tracing::error!("Error: {}", error);
        std::process::exit(1);
    }
}
