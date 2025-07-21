use clap::Parser;
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

    if let Err(error) = genmeta_nslookup::run(genmeta_nslookup::Options::parse()).await {
        eprintln!("{error}");
        tracing::error!("Error: {}", error);
        std::process::exit(1);
    }
}
