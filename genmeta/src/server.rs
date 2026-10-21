//! Local listening configuration and HTTP mount rules for identity services.
use http::Method;
use serde_json::json;
use snafu::{ResultExt, Whatever, ensure_whatever};

#[derive(clap::Subcommand, Debug, Clone)]
pub(super) enum Command {
    /// Query listening or select internal, external, all, or off
    Listen {
        #[arg(short, long)]
        id: String,
        /// Omit to query the saved mode
        #[arg(value_parser = ["internal", "external", "all", "off"])]
        mode: Option<String>,
        #[arg(long)]
        global: bool,
        /// Confirm listen off in scripts
        #[arg(long)]
        yes: bool,
    },
    /// List mounts or mount LOCATION on a local HTTP TARGET
    Mount {
        #[arg(short, long)]
        id: Option<String>,
        #[arg(requires = "target")]
        location: Option<String>,
        #[arg(requires = "location")]
        target: Option<String>,
    },
    /// Remove the mount matching both LOCATION and TARGET
    Unmount {
        #[arg(short, long)]
        id: Option<String>,
        location: String,
        target: String,
        #[arg(long)]
        yes: bool,
    },
}

pub(super) async fn run(command: Command) -> Result<(), Whatever> {
    match command {
        Command::Listen {
            id,
            mode,
            global,
            yes,
        } => {
            if mode.as_deref() == Some("off") && !confirm_delete(&id, "listening", yes)? {
                println!("Cancelled.");
                return Ok(());
            }
            let home = dhttp_home::DhttpHome::load(if global {
                dhttp_home::HomeScope::Global
            } else {
                dhttp_home::HomeScope::User
            })
            .whatever_context("Cannot load DHTTP home")?;
            if global && mode.is_some() {
                tracing::warn!(path = %home.as_path().display(), "using the global dhttp home; this operation may require elevated privileges");
            }
            genmeta_identity::run_listen(&id, mode.as_deref(), &home)
                .await
                .whatever_context("Cannot read or change listening configuration")
        }
        Command::Mount {
            id,
            location,
            target,
        } => {
            let payload = location
                .zip(target)
                .map(|(location, target)| json!({"location":location,"proxy_pass":target}));
            let method = if payload.is_some() {
                Method::PATCH
            } else {
                Method::GET
            };
            let bytes = payload
                .map(|value| serde_json::to_vec(&value))
                .transpose()
                .whatever_context("Cannot encode mount")?
                .unwrap_or_default();
            let value = crate::install::host_request(
                id,
                method,
                "/std/sys/mount",
                bytes,
                "application/json",
            )
            .await?;
            println!(
                "{}",
                serde_json::to_string_pretty(&value).whatever_context("Cannot encode response")?
            );
            Ok(())
        }
        Command::Unmount {
            id,
            location,
            target,
            yes,
        } => {
            if !confirm_delete(id.as_deref().unwrap_or("default identity"), "mount", yes)? {
                println!("Cancelled.");
                return Ok(());
            }
            let path = format!(
                "/std/sys/mount?location={}&proxy_pass={}",
                urlencoding::encode(&location),
                urlencoding::encode(&target)
            );
            crate::install::host_request(id, Method::DELETE, &path, Vec::new(), "application/json")
                .await?;
            Ok(())
        }
    }
}

fn confirm_delete(id: &str, resource: &str, yes: bool) -> Result<bool, Whatever> {
    use std::io::{IsTerminal, Write};
    if yes {
        return Ok(true);
    }
    ensure_whatever!(
        std::io::stdin().is_terminal(),
        "Non-interactive deletion requires --yes"
    );
    print!("Delete {resource} for {id}? [y/n] ");
    std::io::stdout()
        .flush()
        .whatever_context("Cannot show confirmation")?;
    let mut answer = String::new();
    std::io::stdin()
        .read_line(&mut answer)
        .whatever_context("Cannot read confirmation")?;
    Ok(matches!(
        answer.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}
