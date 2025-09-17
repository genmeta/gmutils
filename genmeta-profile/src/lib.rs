use std::{ops::Deref, path::PathBuf};

use clap::Parser;
use genmeta_common::error::Whatever;
use snafu::{OptionExt, ResultExt};
use ssh_config::{
    ast::{ConfigFile, Pair},
    error::*,
    genmeta::*,
};
use tokio::fs;

#[derive(Parser, Debug, Clone)]
#[command(version, about)]
pub struct Options {
    /// Path to the genemta config file, default to be `$XDG_CONFIG_HOME/genmeta/profile`
    #[arg(short, long)]
    path: Option<PathBuf>,

    /// Diagnose possible configuration errors when using a certain ID
    id: Option<String>,
}

#[derive(snafu::Snafu, Debug)]
pub enum Error {
    #[snafu(transparent)]
    Whatever { source: Whatever },
    #[snafu(transparent)]
    ReadConfig { source: ReadConfigError },
    #[snafu(transparent)]
    CheckConfig { source: CheckConfigError },
}

pub async fn run(options: Options) -> Result<(), Error> {
    let config_path = options.path.or_else(user_config_file_path).context(
        LocateConfigFileSnafu {
            message: "No path passed from argument, and user-wide configuration cannot be located",
        },
    )?;

    let path = &config_path;

    let data = fs::read_to_string(path)
        .await
        .context(ReadConfigFileSnafu { path })?;
    let config = ConfigFile::new(&data).context(LexConfigSnafu { path })?;

    match options.id {
        Some(ref id) => {
            let map = config.query(keywords::MATCHERS, id);

            let (key_path, key) = parse_key(id, map.get(&keywords::KEY))
                .await
                .context(ParseConfigSnafu { path })?;

            let (cert_path, cert) = parse_cert(id, map.get(&keywords::CERT))
                .await
                .context(ParseConfigSnafu { path })?;
            println!("Profile `{id}` configured in `{}`:", path.display());
            // Print in hex format
            println!("    Id: {id}");
            // user x509 format?
            println!(
                "    Key at `{}` ({}B)",
                cert_path.as_ref().display(),
                cert.len()
            );
            println!(
                "    Cert at `{}` ({}B)",
                key_path.as_ref().display(),
                key.len()
            );
            Ok(())
        }
        None => {
            for Pair { keyword, arguments } in config.pairs() {
                let location = config.locate(keyword);
                let arguments = Some((location, arguments));
                match keyword.deref() {
                    keyword if keyword == &keywords::KEY => {
                        parse_key("", arguments.as_ref()).await.map(|_| ())
                    }
                    keyword if keyword == &keywords::CERT => {
                        parse_cert("", arguments.as_ref()).await.map(|_| ())
                    }
                    keyword if keywords::MATCHERS.contains(keyword) => Ok(()),
                    _ => {
                        return UnknownKeywordSnafu {
                            keyword: keyword.to_string(),
                            path,
                            location,
                        }
                        .fail()?;
                    }
                }
                .context(ParseConfigSnafu { path })?;
            }
            println!("Your profile configuration looks OK!");
            Ok(())
        }
    }
}
