//! Delegate source building and signing to the installed Pishoo tool without interpreting a shell.
use std::{path::PathBuf, process::Stdio};

use snafu::{ResultExt, Whatever, whatever};

pub(super) async fn run(
    path: PathBuf,
    output: Option<PathBuf>,
    id: Option<String>,
) -> Result<(), Whatever> {
    let executable =
        std::env::current_exe().whatever_context("Cannot locate genmeta executable")?;
    let sibling = executable.with_file_name(format!("pishoo-pack{}", std::env::consts::EXE_SUFFIX));
    let tool = if sibling.is_file() {
        sibling
    } else {
        PathBuf::from(format!("pishoo-pack{}", std::env::consts::EXE_SUFFIX))
    };
    let mut command = tokio::process::Command::new(tool);
    command.arg("--build");
    if let Some(output) = output {
        command.arg("--output").arg(output);
    }
    if let Some(id) = id {
        command.arg("--id").arg(id);
    }
    // A local filename beginning with '-' must stay a positional path.
    command.arg("--").arg(path);
    command.stdin(Stdio::null());
    let status = match command.status().await {
        Ok(status) => status,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            whatever!("pishoo-pack is missing; install a Pishoo release that includes pishoo-pack");
        }
        Err(error) => {
            return Err(error).whatever_context("Cannot launch pishoo-pack");
        }
    };
    if !status.success() {
        whatever!("pishoo-pack failed ({status})");
    }
    Ok(())
}
