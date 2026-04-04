use std::{fs, io::Write, path::Path};

use serde::Serialize;
use snafu::{ResultExt, Whatever};
use tracing::info;
use xshell::{Shell, cmd};

use crate::{ScoopTarget, package_meta, sha256_file, target_dir};

const CARGO_NAME: &str = "genmeta";

/// Download URL prefix for Scoop archives.
const SCOOP_DL_URL: &str = "https://download.genmeta.net/scoop";

fn scoop_arch(triple: &str) -> Result<&'static str, Whatever> {
    match triple {
        "x86_64-pc-windows-msvc" => Ok("64bit"),
        "i686-pc-windows-msvc" => Ok("32bit"),
        _ => snafu::whatever!("unsupported scoop target triple: {triple}"),
    }
}

fn check_cargo_xwin(sh: &Shell) -> Result<(), Whatever> {
    cmd!(sh, "which cargo-xwin")
        .quiet()
        .run()
        .whatever_context("cargo-xwin not found in PATH")?;
    Ok(())
}

/// Create a zip archive from a staging directory.
fn create_zip(staging: &Path, output: &Path) -> Result<(), Whatever> {
    let file = fs::File::create(output)
        .whatever_context(format!("failed to create {}", output.display()))?;
    let mut zip = zip::ZipWriter::new(file);
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);

    for entry in fs::read_dir(staging).whatever_context("failed to read staging dir")? {
        let entry = entry.whatever_context("failed to read dir entry")?;
        let path = entry.path();
        if path.is_file() {
            let name = path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned();
            zip.start_file(&name, options)
                .whatever_context(format!("failed to start zip entry {name}"))?;
            let data =
                fs::read(&path).whatever_context(format!("failed to read {}", path.display()))?;
            zip.write_all(&data)
                .whatever_context(format!("failed to write zip entry {name}"))?;
        }
    }

    zip.finish()
        .whatever_context("failed to finalize zip archive")?;
    Ok(())
}

/// Scoop manifest JSON structure.
#[derive(Serialize)]
struct ScoopManifest {
    version: String,
    description: String,
    license: String,
    homepage: String,
    architecture: serde_json::Map<String, serde_json::Value>,
    bin: Vec<String>,
    checkver: CheckVer,
    autoupdate: serde_json::Map<String, serde_json::Value>,
}

#[derive(Serialize)]
struct CheckVer {
    url: String,
    re: String,
}

struct ArchiveInfo {
    arch_key: String,
    archive_name: String,
    sha256: String,
}

pub fn run(targets: &[ScoopTarget]) -> Result<(), Whatever> {
    let meta = package_meta(CARGO_NAME)?;
    let target_dir = target_dir()?;
    let workspace = std::env::current_dir().whatever_context("failed to get cwd")?;

    let archives: Vec<ArchiveInfo> = std::thread::scope(|s| {
        let handles: Vec<_> = targets
            .iter()
            .map(|&target| {
                let meta_version = &meta.version;
                let target_dir = &target_dir;
                let workspace = &workspace;
                let triple = target.triple();
                s.spawn(move || build_one(triple, meta_version, target_dir, workspace))
            })
            .collect();

        handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .collect::<Result<Vec<_>, _>>()
    })?;

    // Generate aggregated manifest
    let manifest_name = format!("{CARGO_NAME}.json");

    let mut architecture = serde_json::Map::new();
    let mut autoupdate = serde_json::Map::new();

    for info in &archives {
        let url = format!("{SCOOP_DL_URL}/{}", info.archive_name);
        architecture.insert(
            info.arch_key.clone(),
            serde_json::json!({
                "url": url,
                "hash": info.sha256,
            }),
        );
        autoupdate.insert(
            info.arch_key.clone(),
            serde_json::json!({
                "url": url,
            }),
        );
    }

    let manifest = ScoopManifest {
        version: meta.version,
        description: meta.description,
        license: meta.license,
        homepage: meta.homepage,
        architecture,
        bin: vec![format!("{CARGO_NAME}.exe"), "genmeta-ssh.bat".to_string()],
        checkver: CheckVer {
            url: format!("{SCOOP_DL_URL}/{manifest_name}"),
            re: r#""version"\s*:\s*"([^"]+)""#.to_string(),
        },
        autoupdate,
    };

    let manifest_dir = target_dir.join("common").join("scoop");
    fs::create_dir_all(&manifest_dir)
        .whatever_context(format!("failed to create {}", manifest_dir.display()))?;
    let manifest_path = manifest_dir.join(&manifest_name);
    let json = serde_json::to_string_pretty(&manifest)
        .whatever_context("failed to serialize scoop manifest")?;
    fs::write(&manifest_path, json + "\n")
        .whatever_context(format!("failed to write {}", manifest_path.display()))?;
    info!(path = %manifest_path.display(), "produced manifest");

    Ok(())
}

fn build_one(
    triple: &str,
    version: &str,
    target_dir: &std::path::Path,
    workspace: &std::path::Path,
) -> Result<ArchiveInfo, Whatever> {
    let _span = tracing::info_span!("scoop", triple).entered();
    let arch_key = scoop_arch(triple)?;

    let sh = Shell::new().whatever_context("failed to create shell")?;
    check_cargo_xwin(&sh)?;

    // Build
    cmd!(
        sh,
        "cargo xwin build --release --target {triple} --bin {CARGO_NAME}"
    )
    .run()
    .whatever_context(format!("cargo xwin build failed for {triple}"))?;

    // Stage
    let scoop_dir = target_dir.join(triple).join("release").join("scoop");
    let staging = scoop_dir.join("staging");
    let _ = fs::remove_dir_all(&staging);
    fs::create_dir_all(&staging)
        .whatever_context(format!("failed to create {}", staging.display()))?;

    // Copy artifacts
    let binary = target_dir
        .join(triple)
        .join("release")
        .join(format!("{CARGO_NAME}.exe"));
    fs::copy(&binary, staging.join(format!("{CARGO_NAME}.exe")))
        .whatever_context(format!("failed to copy {}", binary.display()))?;
    fs::copy(
        workspace.join("genmeta-ssh.bat"),
        staging.join("genmeta-ssh.bat"),
    )
    .whatever_context("failed to copy genmeta-ssh.bat")?;

    // Create zip
    let archive_name = format!("{CARGO_NAME}-{version}-{triple}.zip");
    let archive_path = scoop_dir.join(&archive_name);
    create_zip(&staging, &archive_path)?;

    // Cleanup staging
    let _ = fs::remove_dir_all(&staging);

    // Hash
    let sha = sha256_file(&archive_path)?;

    info!(path = %archive_path.display(), "produced archive");
    Ok(ArchiveInfo {
        arch_key: arch_key.to_string(),
        archive_name,
        sha256: sha,
    })
}
