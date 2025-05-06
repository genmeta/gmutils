use clap::Parser;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    match genmeta_ssh3::Options::try_parse() {
        Ok(options) => {
            if let Err(error) = genmeta_ssh3::run(options).await {
                eprintln!("ERROR: {error}");
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
