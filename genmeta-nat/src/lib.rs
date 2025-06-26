use std::{net::SocketAddr, sync::Arc};

use clap::Parser;
use qtraversal::{iface::Interface, nat::client::Client};

#[derive(Parser, Debug, Clone)]
#[command(name = "nat-detect", version, about)]
pub struct Options {
    #[arg(
        short,
        default_value = "0.0.0.0:5379",
        help = "Bind address to detect NAT"
    )]
    pub bind: SocketAddr,
    #[arg(short, default_value = "1.12.74.4:20004", help = "STUN server address")]
    pub stun_svr: SocketAddr,
}

type Error = Box<dyn core::error::Error + Send + Sync>;

pub async fn run(options: Options) -> Result<(), Error> {
    let iface = Arc::new(Interface::new(options.bind).expect("failed to bind socket"));
    let client = Client::new(iface.clone(), options.stun_svr);
    let outer_addr = client.outer_addr().await.expect("failed to get outer addr");
    let nat_type = client.nat_type().await?;
    println!("NAT type: {nat_type:?}");
    println!("External Address: {outer_addr}");
    Ok(())
}
