#[tokio::main]
async fn main() {
    use clap::Parser;
    use genmeta_doctor::{Options, run};
    if let Err(error) = run(Options::parse()).await {
        eprintln!("{error}");
        tracing::error!("Error: {error}");
        std::process::exit(1);
    }
}
