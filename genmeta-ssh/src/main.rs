use clap::Parser;

pub mod imp;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stdout)
        .init();

    if let Err(error) = imp::run(imp::Options::parse()).await {
        tracing::error!("Error: {}", error);
        std::process::exit(1);
    }
}
