use clap::Parser;

#[derive(Parser)]
enum Options {
    Ssh(genmeta_ssh::Options),
    Request(genmeta_request::Options),
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    match Options::try_parse() {
        Ok(options) => {
            if let Err(error) = run(options).await {
                eprintln!("Error: {error}");
                tracing::error!("Error: {}", error);
                std::process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("Failed to parse command line arguments");
            e.exit()
        }
    }
}

async fn run(options: Options) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match options {
        Options::Ssh(options) => genmeta_ssh::run(options).await,
        Options::Request(options) => genmeta_request::run(options).await,
    }
}
