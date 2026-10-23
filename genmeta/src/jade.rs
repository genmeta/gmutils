//! Project creation, local package builds, and store publication.
use std::{fs, path::PathBuf};

use serde_json::json;
use snafu::{OptionExt, ResultExt, Whatever, ensure_whatever};

#[derive(clap::Subcommand, Debug, Clone)]
pub(super) enum Command {
    /// Create a static package project in a new directory
    #[command(version)]
    Create {
        /// New project directory; its final component becomes the package name
        path: PathBuf,
        /// Publisher identity to record in the manifest (no credentials required)
        #[arg(short, long, value_name = "PUBLISHER")]
        id: String,
    },
    /// Build a local project and create a signed Pkg package
    #[command(version)]
    Build {
        /// Project directory or build manifest
        #[arg(default_value = ".")]
        path: PathBuf,
        /// Sign already-built artifacts without running the source build
        #[arg(long)]
        no_build: bool,
        /// Signed output file (defaults to the built manifest's dist directory)
        #[arg(short, long, value_name = "FILE.waz")]
        output: Option<PathBuf>,
        /// Check the signing identity against the built manifest publisher
        #[arg(short, long, value_name = "PUBLISHER")]
        id: Option<String>,
    },
    /// Publish a signed Pkg package to the trusted store
    #[command(version)]
    Publish {
        /// Existing signed .waz file
        file: PathBuf,
        #[arg(short, long, value_name = "PUBLISHER")]
        id: Option<String>,
    },
}

pub(super) async fn run(command: Command) -> Result<(), Whatever> {
    match command {
        Command::Create { path, id } => create(path, id),
        Command::Build {
            path,
            output,
            id,
            no_build,
        } => crate::pack::run(path, output, id, no_build).await,
        Command::Publish { file, id } => crate::upload::run(file, id).await,
    }
}

fn create(path: PathBuf, id: String) -> Result<(), Whatever> {
    if let Err(error) = crate::pack::reject_url(path.as_os_str()) {
        snafu::whatever!("Invalid project path: {error}");
    }
    let publisher =
        dhttp_home::normalize_name(&id).whatever_context("Invalid publisher identity")?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .whatever_context("Project path must end with a package name")?;
    let package_id = format!("{publisher}/{name}");
    ensure_whatever!(
        crate::pack::valid_id(&package_id),
        "Package name must start with a lowercase letter and contain at most 63 lowercase letters, digits or hyphens"
    );
    let manifest = toml::to_string_pretty(&json!({
        "package": {
            "name": package_id,
            "version": "0.1.0",
            "description": format!("{name} package"),
            "license": "Apache-2.0",
            "pishoo": {
                "title": name,
                "changelog": "Initial release",
                "entry": "/",
                "dependencies": []
            }
        },
        "fs": {"/public": "public"}
    }))
    .whatever_context("Cannot encode package manifest")?;
    fs::create_dir(&path).whatever_context("Cannot create project directory; use a new path")?;
    fs::create_dir(path.join("public")).whatever_context("Cannot create public directory")?;
    fs::write(path.join("wasmer.toml"), manifest)
        .whatever_context("Cannot write package manifest")?;
    fs::write(
        path.join("public/index.html"),
        format!(
            "<!doctype html>\n<html lang=\"en\">\n<head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>{name}</title></head>\n<body><h1>{name}</h1></body>\n</html>\n"
        ),
    )
    .whatever_context("Cannot write index page")?;
    fs::write(path.join(".gitignore"), "/dist/\n").whatever_context("Cannot write .gitignore")?;
    eprintln!("Static project ready; package it with genmeta jade build --no-build PATH");
    println!(
        "{}",
        crate::display::package_output(json!({"id": package_id, "path": path}))
    );
    Ok(())
}
