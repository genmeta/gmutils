use clap::Parser;
use genmeta_discover::{Options, run};

#[tokio::main]
async fn main() {
    run(Options::parse()).await;
}
