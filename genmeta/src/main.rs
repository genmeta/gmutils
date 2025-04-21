use clap::Parser;

#[derive(Parser)]
enum Options {
    Ssh(genmeta_ssh::Options),
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stdout)
        .init();

    if let Err(error) = run(Options::parse()).await {
        tracing::error!("Error: {}", error);
        std::process::exit(1);
    }
}

async fn run(options: Options) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match options {
        Options::Ssh(options) => genmeta_ssh::run(options).await,
    }
}
