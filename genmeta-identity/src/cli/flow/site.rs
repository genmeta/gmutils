use std::path::{Path, PathBuf};

use dhttp_home::{
    DhttpHome,
    identity::{IdentityProfile, ssl::ResolveIdentityProfileError},
};
use snafu::{ResultExt, Snafu};
use tokio::fs;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ServerConfigState {
    Enabled,
    Disabled,
    Missing,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConfigChange {
    Changed,
    Unchanged,
}
#[derive(Debug)]
pub(crate) struct ServerConfig {
    path: PathBuf,
}

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum Error {
    #[snafu(transparent)]
    ResolveIdentityProfile { source: ResolveIdentityProfileError },
    #[snafu(display("failed to inspect Pishoo configuration {}", path.display()))]
    Inspect {
        path: PathBuf,
        source: std::io::Error,
    },
    #[snafu(display("Pishoo configuration is not a regular file: {}", path.display()))]
    NotRegularFile { path: PathBuf },
    #[snafu(display("Pishoo configuration is missing at {}; use `genmeta listen --id NAME internal` to create it", path.display()))]
    MissingConfiguration { path: PathBuf },
    #[snafu(display("invalid Pishoo configuration at {}: {message}", path.display()))]
    InvalidConfiguration { path: PathBuf, message: String },
    #[snafu(display(
        "cannot run Pishoo; install the matching Pishoo release or set PISHOO_BIN: {source}"
    ))]
    PishooUnavailable { source: std::io::Error },
}

impl ServerConfig {
    pub(crate) fn for_profile(profile: &IdentityProfile) -> Self {
        Self {
            path: profile.join(".volume/sys/setting/database"),
        }
    }

    // The host executable owns all schema creation, validation and configuration writes.
    async fn configure(&self, arguments: &[&str]) -> Result<String, Error> {
        let profile = self
            .path
            .ancestors()
            .nth(4)
            .expect("identity configuration path");
        let executable = std::env::var_os("PISHOO_BIN").unwrap_or_else(|| "pishoo".into());
        let output = tokio::process::Command::new(executable)
            .arg("configure")
            .arg("--profile")
            .arg(profile)
            .args(arguments)
            .kill_on_drop(true)
            .output()
            .await
            .context(error::PishooUnavailableSnafu)?;
        let invalid = |message| Error::InvalidConfiguration {
            path: self.path.clone(),
            message,
        };
        if !output.status.success() {
            return Err(invalid(format!(
                "Pishoo configuration command failed ({}): {}",
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        let response: serde_json::Value = serde_json::from_slice(&output.stdout)
            .map_err(|e| invalid(format!("invalid Pishoo response: {e}")))?;
        let listen = response["listen"]
            .as_str()
            .filter(|value| matches!(*value, "internal" | "external" | "all" | "off"))
            .ok_or_else(|| invalid("invalid Pishoo listen response".into()))?;
        Ok(listen.into())
    }

    pub(crate) async fn state(&self) -> Result<ServerConfigState, Error> {
        if !regular_file_exists(&self.path).await? {
            // Legacy paths are not current host configuration; Pishoo owns fresh initialization.
            return Ok(ServerConfigState::Missing);
        }
        Ok(if self.configure(&["--init"]).await? == "off" {
            ServerConfigState::Disabled
        } else {
            ServerConfigState::Enabled
        })
    }

    pub(crate) async fn enable(&self) -> Result<ConfigChange, Error> {
        match self.state().await? {
            ServerConfigState::Enabled => Ok(ConfigChange::Unchanged),
            _ => {
                self.configure(&["--listen", "all"]).await?;
                Ok(ConfigChange::Changed)
            }
        }
    }
}

async fn regular_file_exists(path: &Path) -> Result<bool, Error> {
    match fs::symlink_metadata(path).await {
        Ok(metadata) if metadata.file_type().is_file() => Ok(true),
        Ok(_) => Err(Error::NotRegularFile {
            path: path.to_path_buf(),
        }),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(Error::Inspect {
            path: path.to_path_buf(),
            source,
        }),
    }
}

pub(crate) const SERVICE_HINT: &str =
    "Running Pishoo applies listening changes automatically. Start Pishoo if it is not running.";

/// Delegate local configuration to Pishoo even when its HTTP listener is off.
pub async fn run_listen(
    id: &str,
    scope: Option<&str>,
    home: &DhttpHome,
) -> Result<(), crate::cli::Error> {
    let identity = super::target::IdentityTarget::parse(id)?.into_dhttp_name();
    let profile = home
        .resolve_identity_profile_exactly(identity.as_full())
        .await?;
    let config = ServerConfig::for_profile(&profile);
    if scope.is_some_and(|mode| !matches!(mode, "internal" | "external" | "all" | "off")) {
        return Err(Error::InvalidConfiguration {
            path: config.path,
            message: "invalid listening scope".into(),
        }
        .into());
    }
    let listen = match scope {
        Some(mode) => config.configure(&["--listen", mode]).await?,
        None => config.configure(&["--init"]).await?,
    };
    println!("{}", serde_json::json!({"listen":listen}));
    if scope.is_some() {
        super::transcript::print_line(SERVICE_HINT);
    }
    Ok(())
}

#[cfg(test)]
#[path = "../../../tests/unit/cli/flow/site.rs"]
mod tests;
