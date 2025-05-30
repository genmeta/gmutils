use clap::Parser;
use gmdns::mdns::Mdns;
use tokio_stream::StreamExt;

#[derive(Parser, Debug, Clone)]
#[command(name = "discover")]
pub struct Options {
    /// Target domain name or IP address to resolve (default: test.genmeta.net)
    #[arg(
        value_name = "DOMAIN",
        index = 1,
        default_value = "",
        help = "Domain name to discover eg. _genmeta.local, default is empty"
    )]
    domain: String,
}

type Error = Box<dyn core::error::Error + Send + Sync>;

pub async fn run(options: Options) -> Result<(), Error> {
    let mut mdns_resolver = Mdns::new("_genmeta.local")?;
    let mut stream = mdns_resolver.discover();

    while let Some((_, packet)) = stream.next().await {
        let relevant_answers: Vec<_> = packet
            .answers
            .iter()
            .filter(|a| a.name().contains(&options.domain))
            .collect();

        if !relevant_answers.is_empty() {
            println!("Name: {}", relevant_answers[0].name());
            relevant_answers.iter().for_each(|a| {
                println!("{:?}", a.data());
            });
            println!();
        }
    }
    Ok(())
}
