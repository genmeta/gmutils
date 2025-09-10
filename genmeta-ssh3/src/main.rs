use clap::Parser;

#[tokio::main]
async fn main() {
    if let Err(error) = genmeta_ssh3::run(genmeta_ssh3::Options::parse()).await {
        eprintln!("{error}");
        tracing::error!("Exit with error: {}", error);
        std::process::exit(1);
    }
}
