//! Project commands and atomic template creation.
use std::{fs, path::PathBuf};

use serde_json::{Value, json};

use crate::error::{Error, Result};

#[derive(clap::ValueEnum, Debug, Clone, Copy)]
pub(super) enum Template {
    Static,
    Web,
    Api,
    Fullstack,
}

#[derive(clap::Subcommand, Debug)]
pub(super) enum Command {
    /// Create a project in a new directory
    #[command(
        version,
        after_help = "Examples:\n  jade create hello                             # Vite frontend + Rust API (default)\n  jade create website --template static         # Static HTML\n  jade create frontend --template web           # Vite frontend\n  jade create service --template api            # Rust HTTP API\n  jade create application --template fullstack  # Frontend calling a Rust API\n\nAPI and fullstack templates include GET /hello."
    )]
    Create {
        path: PathBuf,
        /// Package name, independent of the directory name
        #[arg(long)]
        name: Option<String>,
        /// Initial source files to generate
        #[arg(long, value_enum, default_value = "fullstack")]
        template: Template,
    },
    /// Build sources or declared artifacts and sign a package
    #[command(version)]
    Build {
        /// Project directory or Jade configuration file
        #[arg(default_value = ".")]
        path: PathBuf,
        /// Signing identity; must match package.author when configured
        #[arg(short, long, value_name = "AUTHOR")]
        id: Option<String>,
        /// Package output file (default build/NAME-VERSION.waz)
        #[arg(short, long, value_name = "FILE.waz")]
        output: Option<PathBuf>,
        /// Replace an existing explicit output file
        #[arg(long, requires = "output")]
        overwrite: bool,
    },
    /// Publish one signed package using its author's credentials
    #[command(version)]
    Publish { file: PathBuf },
}

impl Command {
    pub(super) fn name(&self) -> &'static str {
        match self {
            Self::Create { .. } => "create",
            Self::Build { .. } => "build",
            Self::Publish { .. } => "publish",
        }
    }
}
pub(super) async fn run(command: Command, machine: bool) -> Result<Value> {
    match command {
        Command::Create {
            path,
            name,
            template,
        } => create(path, name, template),
        Command::Build {
            path,
            id,
            output,
            overwrite,
        } => crate::pack::run(path, output, id, overwrite, machine).await,
        Command::Publish { file } => crate::upload::run(file).await,
    }
}

fn create(path: PathBuf, name: Option<String>, template: Template) -> Result<Value> {
    crate::pack::reject_url(path.as_os_str()).map_err(|e| Error::new("E_CONFIG_INVALID", e))?;
    let name = name
        .or_else(|| {
            path.file_name()
                .and_then(|name| name.to_str())
                .map(str::to_owned)
        })
        .ok_or_else(|| {
            Error::new(
                "E_CONFIG_INVALID",
                "Specify --name for this project directory",
            )
        })?;
    if !crate::pack::valid_id(&format!("jade-template.dhttp.net/{name}")) {
        return Err(Error::new("E_CONFIG_INVALID","Package name must start with a lowercase letter and contain at most 63 lowercase letters, digits or hyphens").hint("Use --name to choose a package name independently of the directory"));
    }
    if fs::symlink_metadata(&path).is_ok() {
        return Err(Error::new(
            "E_OUTPUT_CONFLICT",
            "Project path already exists; use a new path",
        ));
    }
    let path =
        crate::pack::resolved_output(&path).map_err(|e| Error::new("E_OUTPUT_CONFLICT", e))?;
    let parent = path
        .parent()
        .ok_or_else(|| Error::new("E_CONFIG_INVALID", "Project path has no parent"))?;
    let parent = fs::canonicalize(parent).map_err(|e| {
        Error::new(
            "E_CONFIG_INVALID",
            format!("Project parent must exist: {e}"),
        )
    })?;
    let target = parent.join(path.file_name().unwrap());
    let temporary = tempfile::Builder::new()
        .prefix(".jade-create-")
        .tempdir_in(&parent)?;
    let root = temporary.path();
    let config = json!({"package":{"name":name,"version":"0.1.0","description":format!("{name} application"),"license":"Apache-2.0"}});
    let mut ignore = format!("/{}/\n", crate::project::BUILD_DIR);
    match template {
        Template::Static => {
            fs::create_dir(root.join("public"))?;
            fs::write(
                root.join("public/index.html"),
                format!(
                    "<!doctype html>\n<html lang=\"en\"><meta charset=\"utf-8\"><title>{name}</title><h1>{name}</h1></html>\n"
                ),
            )?;
        }
        Template::Web | Template::Fullstack => {
            fs::create_dir_all(root.join("web/src"))?;
            fs::write(root.join("web/package.json"),serde_json::to_string_pretty(&json!({"name":name,"version":"0.1.0","private":true,"type":"module","scripts":{"dev":"vite","build":"vite build"},"devDependencies":{"vite":"^8.3.0"}})).map_err(|e|Error::new("E_INTERNAL",e))?)?;
            fs::write(
                root.join("web/vite.config.js"),
                "export default { base: './' };\n",
            )?;
            fs::write(
                root.join("web/index.html"),
                format!(
                    "<!doctype html>\n<html lang=\"en\"><meta charset=\"utf-8\"><title>{name}</title><main id=\"app\"></main><script type=\"module\" src=\"/src/main.js\"></script></html>\n"
                ),
            )?;
            let content = if matches!(template, Template::Fullstack) {
                format!(
                    "const app = document.querySelector('#app');\napp.textContent = 'Loading…';\nfetch('/{name}/hello').then(response => {{ if (!response.ok) throw new Error(`HTTP ${{response.status}}`); return response.json(); }}).then(data => app.textContent = data.message).catch(error => app.textContent = error.message);\n"
                )
            } else {
                format!("document.querySelector('#app').textContent = 'Hello from {name}';\n")
            };
            fs::write(root.join("web/src/main.js"), content)?;
            ignore.push_str("/web/node_modules/\n/web/dist/\n");
        }
        Template::Api => {}
    }
    if matches!(template, Template::Api | Template::Fullstack) {
        fs::create_dir_all(root.join("api/src"))?;
        fs::write(
            root.join("api/Cargo.toml"),
            format!(
                r#"[package]
name = "{name}"
version = "0.1.0"
edition = "2024"
publish = false

[workspace]

[lib]
crate-type = ["cdylib"]

[dependencies]
wasip2 = "=1.0.4"
serde_json = "1"
"#
            ),
        )?;
        fs::write(
            root.join("api/src/lib.rs"),
            include_str!("../templates/api/src/lib.rs"),
        )?;
        ignore.push_str("/api/target/\n");
    }
    fs::write(
        root.join("jade.toml"),
        toml::to_string_pretty(&config).map_err(|e| Error::new("E_INTERNAL", e))?,
    )?;
    fs::write(root.join(".gitignore"), ignore)?;
    let mut readme = format!("# {name}\n\n");
    if matches!(template, Template::Web | Template::Fullstack) {
        readme.push_str("Edit files under `web/`. `jade build` installs frontend dependencies, including build tools, before running the build script. Install Node.js and npm before building.\n\n");
    }
    if matches!(template, Template::Api | Template::Fullstack) {
        readme.push_str("Install the component target with `rustup target add wasm32-wasip2`. Edit handlers and the WASI HTTP entry point in `api/src/lib.rs`, and keep its `ROUTES` metadata in sync when changing routes. The template uses `wasip2` directly. Jade invokes Cargo and embeds OpenAPI from the route metadata; no build script is needed.\n\n");
    }
    readme.push_str(&format!("Build and publish using your signing identity (replace `alice.smith` below). Provision credentials using the DHTTP identity tools.\n\n```sh\njade build --id alice.smith\njade publish build/{name}-0.1.0.waz\n```\n\nSigned packages and Cargo's `target/` cache are written under `build/`.\n"));
    readme.push_str("\nJade automatically includes root-level `README.md` and `CHANGELOG.md` when present. No declaration in `jade.toml` is needed; missing files are skipped.\n");
    if matches!(template, Template::Api | Template::Fullstack) {
        readme.push_str(&format!(
            r#"
## Call the backend API

The starter in `api/src/lib.rs` implements GET `/hello`.
Pishoo provides the HTTP listener and mounts this route under `/{name}`.
After publishing, install the package on your running Pishoo service, then call it
with `genmeta curl` (replace the author and host identities as needed):

```sh
genmeta install alice.smith.dhttp.net/{name} --id alice.smith
genmeta curl --id alice.smith -f https://alice.smith.dhttp.net/{name}/hello
# {{"message":"Hello from Rust"}}
```
"#
        ));
    }
    if matches!(template, Template::Fullstack) {
        readme.push_str(&format!("\nThe frontend in `web/src/main.js` calls `/{name}/hello` and displays the JSON response's `message`. Open the installed package's `entry_url` to try it. Vite's dev server serves only the frontend; API requests require the Pishoo service.\n"));
    }
    fs::write(root.join("README.md"), readme)?;
    commit_directory(root, &target).map_err(|e| {
        Error::new(
            "E_OUTPUT_CONFLICT",
            format!("Cannot create project; use a new path: {e}"),
        )
    })?;
    Ok(json!({"path":target,"manifest":target.join("jade.toml"),"name":name}))
}

fn commit_directory(source: &std::path::Path, target: &std::path::Path) -> std::io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        rustix::fs::renameat_with(
            rustix::fs::CWD,
            source,
            rustix::fs::CWD,
            target,
            rustix::fs::RenameFlags::NOREPLACE,
        )?;
        Ok(())
    }
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::ffi::OsStrExt;
        let source = std::ffi::CString::new(source.as_os_str().as_bytes())?;
        let target = std::ffi::CString::new(target.as_os_str().as_bytes())?;
        // RENAME_EXCL keeps an existing directory intact, even if it is empty.
        if unsafe { libc::renamex_np(source.as_ptr(), target.as_ptr(), libc::RENAME_EXCL) } == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        std::fs::rename(source, target)
    }
}
