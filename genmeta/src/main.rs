use clap::Parser;

#[derive(Parser, Debug, Clone)]
#[command(version)]
enum Options {
    Ssh3(genmeta_ssh3::Options),
    Request(genmeta_request::Options),
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

    match Options::try_parse() {
        Ok(options) => {
            if let Err(error) = run(options).await {
                eprintln!("ERROR: {error}");
                tracing::error!("Error: {error}");
                std::process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("Failed to parse command line arguments");
            e.exit()
        }
    };
}

async fn run(options: Options) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match options {
        Options::Ssh3(options) => genmeta_ssh3::run(options).await,
        Options::Request(options) => genmeta_request::run(options).await,
    }
}
