//! Human rendering is separate from the canonical machine result.
use std::{borrow::Cow, io::Write, path::Path, process::ExitCode};

use serde_json::{Value, json};

use crate::error::{Error, Result};

pub(super) fn identity(name: &str) -> Cow<'_, str> {
    match name.strip_suffix(dhttp_home::DHTTP_SUFFIX) {
        Some(short) if !short.is_empty() => Cow::Owned(format!("{short}~")),
        _ => Cow::Borrowed(name),
    }
}
pub(super) fn publisher(name: &str) -> Cow<'_, str> {
    if name == "std.dhttp.net" {
        Cow::Borrowed("std")
    } else {
        identity(name)
    }
}
pub(super) fn package_id(id: &str) -> Cow<'_, str> {
    match id.split_once('/') {
        Some((author, name)) => Cow::Owned(format!("{}/{name}", publisher(author))),
        None => Cow::Borrowed(id),
    }
}

fn path(value: &Value) -> String {
    let path = Path::new(value.as_str().unwrap_or_default());
    std::env::current_dir()
        .ok()
        .and_then(|cwd| path.strip_prefix(cwd).ok())
        .unwrap_or(path)
        .display()
        .to_string()
}

fn argument(text: &str) -> String {
    if !text.is_empty()
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "/._-~".contains(c))
    {
        return text.to_owned();
    }
    #[cfg(windows)]
    {
        format!("'{}'", text.replace('\'', "''"))
    }
    #[cfg(not(windows))]
    {
        format!("'{}'", text.replace('\'', "'\"'\"'"))
    }
}

pub(super) fn success(command: &str, machine: bool, result: Value) -> Result<()> {
    let mut stdout = std::io::stdout().lock();
    if machine {
        let envelope = json!({"schema_version":1,"command":command,"status":"ok","result":result});
        writeln!(stdout, "{envelope}")?;
    } else if command == "create" {
        let project = path(&result["path"]);
        writeln!(
            stdout,
            "Created {} at {}",
            result["name"].as_str().unwrap_or_default(),
            project
        )?;
        writeln!(stdout, "Build: jade build {}", argument(&project))?;
    } else {
        writeln!(
            stdout,
            "Package:        {}",
            package_id(result["id"].as_str().unwrap_or_default())
        )?;
        writeln!(
            stdout,
            "Version:        {}",
            result["version"].as_str().unwrap_or_default()
        )?;
        if command == "build" {
            let file = path(&result["file"]);
            writeln!(stdout, "File:           {file}")?;
            writeln!(stdout, "Size:           {} bytes", result["size"])?;
            writeln!(
                stdout,
                "Package SHA256: {}",
                result["package_sha256"].as_str().unwrap_or_default()
            )?;
            writeln!(
                stdout,
                "Payload SHA256: {}",
                result["payload_sha256"].as_str().unwrap_or_default()
            )?;
            writeln!(stdout, "\nPublish: jade publish {}", argument(&file))?;
        } else {
            writeln!(
                stdout,
                "Result:         {}",
                result["outcome"].as_str().unwrap_or_default()
            )?;
            writeln!(
                stdout,
                "Package SHA256: {}",
                result["package_sha256"].as_str().unwrap_or_default()
            )?;
            writeln!(
                stdout,
                "Payload SHA256: {}",
                result["payload_sha256"].as_str().unwrap_or_default()
            )?;
        }
    }
    Ok(())
}

pub(super) fn failure(command: Option<&str>, machine: bool, error: &Error) -> ExitCode {
    if machine {
        let mut envelope =
            json!({"schema_version":1,"command":command,"status":"error","error":error.json()});
        if error.code == "E_PUBLISH_OUTCOME_UNKNOWN" {
            envelope["result"] = json!({"outcome":"unknown"});
        }
        let _ = writeln!(std::io::stdout().lock(), "{envelope}");
    }
    eprintln!("error[{}]: {}", error.code, error.message);
    if let Some(hint) = &error.hint {
        eprintln!("hint: {hint}");
    }
    ExitCode::from(error.exit_code())
}
