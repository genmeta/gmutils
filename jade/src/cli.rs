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
        after_help = "Examples:\n  jade create hello                             # Vite frontend + Rust API (default)\n  jade create website --template static         # Static HTML\n  jade create frontend --template web           # Vite frontend\n  jade create service --template api            # Rust HTTP API\n  jade create application --template fullstack  # Frontend calling a Rust API\n\nAPI and fullstack templates include GET /whoami."
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
    /// Build sources or declared artifacts into an unsigned package
    #[command(version)]
    Build {
        /// Project directory or Jade configuration file
        #[arg(default_value = ".")]
        path: PathBuf,
        /// Actual development identity, for example dev.alex.chen
        #[arg(short, long, value_name = "DEV_NAME")]
        id: Option<String>,
        /// Package output file (default build/NAME-VERSION.waz)
        #[arg(short, long, value_name = "FILE.waz")]
        output: Option<PathBuf>,
        /// Replace an existing explicit output file
        #[arg(long, requires = "output")]
        overwrite: bool,
    },
    /// Build and watch local projects on the selected development identity
    #[command(version)]
    Run {
        #[arg(default_value = ".")]
        path: PathBuf,
        /// Actual development identity (default: the default identity's dev child, or dev.zero.ai)
        #[arg(short, long, value_name = "DEV_NAME")]
        id: Option<String>,
        /// Archive previous test data and start with an empty directory
        #[arg(long)]
        fresh: bool,
    },
    /// Sign and publish a built package; never rebuild sources
    #[command(version)]
    Publish {
        /// Project directory, jade.toml, or a built FILE.waz
        #[arg(default_value = ".", value_name = "PATH")]
        file: PathBuf,
        /// Actual development identity; must match the built package author
        #[arg(short, long, value_name = "DEV_NAME")]
        id: Option<String>,
        /// Account email used only when developer setup is needed
        #[arg(long)]
        email: Option<String>,
        /// Developer certificate sequence for signing and upload
        #[arg(long)]
        signing_sequence: Option<u32>,
    },
}

impl Command {
    pub(super) fn name(&self) -> &'static str {
        match self {
            Self::Create { .. } => "create",
            Self::Build { .. } => "build",
            Self::Publish { .. } => "publish",
            Self::Run { .. } => "run",
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
        } => crate::pack::run(path, output, id, overwrite).await,
        Command::Run { path, id, fresh } => crate::run::run(path, id, fresh, machine).await,
        Command::Publish {
            file,
            id,
            email,
            signing_sequence,
        } => crate::upload::run(file, id, email, signing_sequence, machine).await,
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
                include_str!("../templates/web/index.html").replace("__JADE_NAME__", &name),
            )?;
            let api = if matches!(template, Template::Fullstack) {
                format!("\"/{name}/whoami\"")
            } else {
                "null".to_owned()
            };
            fs::write(
                root.join("web/src/main.js"),
                include_str!("../templates/web/src/main.js")
                    .replace("__JADE_NAME__", &name)
                    .replace("__JADE_API__", &api),
            )?;
            fs::write(
                root.join("web/src/style.css"),
                include_str!("../templates/web/src/style.css"),
            )?;
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
pishoo-sdk = {{ version = "=0.1.0-preview.2", git = "https://github.com/genmeta/pishoo.git", rev = "daa6cde34dcabd642136ce662945bdaebb830e0f" }}
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
        readme.push_str("Frontend: `web/index.html`, `web/src/main.js` and `web/src/style.css`. Requires Node.js and npm.\n\n");
    }
    if matches!(template, Template::Api | Template::Fullstack) {
        readme.push_str("API: `api/src/lib.rs`. Requires Rust with `wasm32-wasip2` installed. Keep `ROUTES` in sync with the handlers.\n\n");
    }
    readme.push_str("## Develop locally\n\nReplace `dev.alex.chen` with your actual development identity. Start Pishoo, then run:\n\n```sh\njade run --id dev.alex.chen\n```\n\nJade runs on `dev.alex.chen`, using ordinary identity credentials. Follow its setup hint if credentials are missing. No developer certificate or subscription is needed. Changes rebuild automatically; Ctrl+C removes local code and keeps data. Without `--id`, Jade selects the `dev` child of your DHTTP default identity, retaining an existing development child, or uses `dev.zero.ai` when no default is configured.\n\n");
    if matches!(
        template,
        Template::Static | Template::Web | Template::Fullstack
    ) {
        readme.push_str(&format!(
            "Open `/app/{name}/` on the development identity, using the URL printed by Jade.\n\n"
        ));
    }
    if matches!(template, Template::Api | Template::Fullstack) {
        readme.push_str(&format!("GET `/{name}/whoami` returns the verified visitor's name, or `anonymous`. The visitor can differ from the hosting identity.\n\n"));
    }
    readme.push_str(&format!("## Build and publish\n\nBuild and review the unsigned package, then publish it:\n\n```sh\njade build --id dev.alex.chen\n# Review build/{name}-0.1.0.waz, then upload it.\njade publish --id dev.alex.chen\n```\n\nBuild requires no developer certificate or subscription. Publish guides first-time developer setup, signs the existing build and uploads it without changing the local archive or rebuilding sources. Already signed packages are verified and uploaded unchanged.\n\nUse `--id dev.alex.chen` for all Jade commands. Jade uses the selected name directly for hosting and the package author; it never adds or removes `dev.`. Local hosting uses ordinary identity credentials; only publication needs developer credentials.\n\nBuild output and Cargo's cache go under `build/`. Root `README.md` and `CHANGELOG.md` are included when present.\n"));
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
