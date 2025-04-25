use clap::Parser;

mod imp;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    if let Err(error) = imp::run(imp::Options::parse()).await {
        eprintln!("Error: {error}");
        tracing::error!("Error: {}", error);
        std::process::exit(1);
    }
}
