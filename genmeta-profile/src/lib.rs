use std::path::PathBuf;

use bytes::Bytes;
use clap::Parser;
use snafu::{ResultExt, Whatever};
use ssh_config::genmeta::Profile;

#[derive(Parser, Debug, Clone)]
#[command(version, about)]
pub struct Options {
    /// Path to the genemta config file, default to be `$XDG_CONFIG_HOME/genmeta/profile`
    #[arg(short, long)]
    path: Option<PathBuf>,

    /// Diagnose possible configuration errors when using a certain ID
    id: Option<String>,
}

pub async fn run(options: Options) -> Result<(), Whatever> {
    match options.id {
        Some(id) => {
            let Profile { id, key, cert } =
                ssh_config::genmeta::read_config(&id, options.path.as_deref())
                    .await
                    .whatever_context(format!("Cannot read profile for `{id}`"))?;
            // Print in hex format
            let key = Bytes::from(key);
            let cert = Bytes::from(cert);
            println!("    Id: {id}");
            // user x509 format?
            println!("    Key: {key:x}");
            println!("    Cert: {cert:x}");
            Ok(())
        }
        None => {
            ssh_config::genmeta::check_config(options.path.as_deref())
                .await
                .whatever_context("Config file maybe invalid")?;
            Ok(())
        }
    }
}
