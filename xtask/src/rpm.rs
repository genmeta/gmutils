#![allow(dead_code)]

//! RPM (.rpm) packaging via a Fedora 40 Docker container and cargo-zigbuild.
//!
//! Flow per target triple:
//! 1. Ensure an image `xtask-{triple}:{IMAGE_TAG_PREFIX}` exists
//!    (Fedora + rpm-build + rustup nightly + Zig + cargo-zigbuild).
//! 2. Spin up a container with the workspace bind-mounted at `/workspace`.
//! 3. Run `cargo zigbuild --target {triple}.{glibc}` as the host uid:gid.
//! 4. Generate a minimal `.spec` file in Rust (no template files), lay out a
//!    private `_topdir`, and run `rpmbuild -bb --target={rpm_arch}`.
//! 5. Move the produced `.rpm` next to the `.deb` outputs under
//!    `target/{triple}/release/rpm/`.

use std::path::{Path, PathBuf};

use bollard::{
    Docker,
    models::{ContainerConfig, ContainerCreateBody, HostConfig, Mount, MountType},
    query_parameters::{
        CommitContainerOptionsBuilder, CreateContainerOptionsBuilder, CreateImageOptionsBuilder,
    },
};
use futures_util::StreamExt;
use snafu::{ResultExt, Whatever};
use tracing::{Instrument, info, info_span};

use crate::{
    RpmTarget,
    container::{
        CARGO_HOME, RUSTUP_HOME, Sibling, ZIG_GLIBC_VERSION, cargo_cache_mounts,
        cargo_config_from_siblings, check_docker, dhttp_bootstrap_from_env, exec_in_container,
        force_remove_container, host_uid_gid, install_cargo_config, remove_container_if_exists,
        resolve_siblings, start_container,
    },
    package_version, target_dir,
};

const CARGO_NAME: &str = "genmeta";

/// Distribution package name (differs from the cargo crate name).
const PACKAGE_NAME: &str = "gmutils";

/// Base Docker image for rpm cross-compilation.
const BASE_IMAGE: &str = "fedora:40";

/// Image tag prefix for genmeta rpm builds.
const IMAGE_TAG_PREFIX: &str = "gmutils-rpm-v1";

/// Package metadata baked into the generated spec. Kept here (not in Cargo.toml)
/// so spec generation stays a single source of truth owned by xtask.
const RPM_SUMMARY: &str = "Genmeta binary utilities";
const RPM_LICENSE: &str = "Proprietary";
const RPM_URL: &str = "https://www.dhttp.net";
const RPM_VENDOR: &str = "Genmeta Tech Limited";
const RPM_DESCRIPTION: &str =
    "Genmeta command-line tools for DHTTP/3, SSH3, DNS, and identity management.";
const AARCH64_ZIGBUILD_RUSTFLAGS_WORKAROUND: &str =
    "-Z unstable-options -Clinker-flavor=gnu-lld-cc";
const AARCH64_ZIGBUILD_WORKAROUND_SCRIPT_PREFIX: &str = r#"# TODO: Remove this aarch64 cargo-zigbuild workaround after rustc/Zig/cargo-zigbuild
# agree on the Cortex-A53 843419 mitigation linker argument.
cat > /tmp/gmutils-aarch64-zig <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [ "${1:-}" = "cc" ] || [ "${1:-}" = "c++" ]; then
    zig_subcommand="$1"
    shift
    filtered_args=()
    for arg in "$@"; do
        case "$arg" in
            -Wl,--fix-cortex-a53-843419|--fix-cortex-a53-843419)
                continue
                ;;
        esac
        filtered_args+=("$arg")
    done
    exec /usr/local/zig/zig "$zig_subcommand" "${filtered_args[@]}"
fi
exec /usr/local/zig/zig "$@"
EOF
chmod +x /tmp/gmutils-aarch64-zig
export CARGO_ZIGBUILD_ZIG_PATH=/tmp/gmutils-aarch64-zig
"#;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpmArtifact {
    pub target: String,
    pub path: PathBuf,
}

#[derive(Debug, snafu::Snafu)]
#[snafu(module)]
enum FindRpmArtifactError {
    #[snafu(display("failed to read rpm artifact directory"))]
    ReadDir {
        source: std::io::Error,
        path: PathBuf,
    },
    #[snafu(display("failed to read rpm artifact directory entry"))]
    ReadEntry {
        source: std::io::Error,
        path: PathBuf,
    },
    #[snafu(display("rpm build produced no artifact"))]
    NoArtifact { path: PathBuf },
    #[snafu(display("rpm build produced multiple artifacts"))]
    MultipleArtifacts { path: PathBuf },
}

/// Map a Rust target triple to the rpm arch name.
fn rpm_arch(triple: &str) -> Result<&'static str, Whatever> {
    match triple {
        "x86_64-unknown-linux-gnu" => Ok("x86_64"),
        "aarch64-unknown-linux-gnu" => Ok("aarch64"),
        "armv7-unknown-linux-gnueabihf" => Ok("armv7hl"),
        "i686-unknown-linux-gnu" => Ok("i686"),
        _ => snafu::whatever!("unsupported rpm target triple: {triple}"),
    }
}

fn aarch64_zigbuild_workaround_script(triple: &str) -> String {
    if triple == "aarch64-unknown-linux-gnu" {
        format!(
            "{AARCH64_ZIGBUILD_WORKAROUND_SCRIPT_PREFIX}export RUSTFLAGS=\"$RUSTFLAGS {AARCH64_ZIGBUILD_RUSTFLAGS_WORKAROUND}\"\n"
        )
    } else {
        String::new()
    }
}

pub async fn run(
    targets: &[RpmTarget],
    siblings: &[std::path::PathBuf],
) -> Result<Vec<RpmArtifact>, Whatever> {
    info!(target_count = targets.len(), "starting rpm dist build");
    let docker = Docker::connect_with_local_defaults()
        .whatever_context("failed to connect to Docker/Podman")?;
    check_docker(&docker).await?;

    let siblings = resolve_siblings(siblings)?;
    let version = package_version(CARGO_NAME)?;
    let target_dir = target_dir()?;

    let mut tasks = tokio::task::JoinSet::new();
    for &target in targets {
        let docker = docker.clone();
        let version = version.clone();
        let target_dir = target_dir.clone();
        let siblings = siblings.clone();
        let triple = target.triple();
        info!(triple, "queued rpm target build");
        let span = info_span!("rpm", triple);
        tasks.spawn(
            async move { build_one(&docker, triple, &version, &target_dir, &siblings).await }
                .instrument(span),
        );
    }

    let mut artifacts = Vec::new();
    while let Some(result) = tasks.join_next().await {
        artifacts.push(result.whatever_context("rpm build task panicked")??);
    }
    artifacts.sort_by(|left, right| left.target.cmp(&right.target));

    info!("finished rpm dist build");
    Ok(artifacts)
}

/// Build the image if missing, then produce the rpm for this triple.
async fn ensure_image(docker: &Docker, triple: &str) -> Result<String, Whatever> {
    let tag = format!("xtask-{triple}:{IMAGE_TAG_PREFIX}");
    if docker.inspect_image(&tag).await.is_ok() {
        info!(tag, "image already exists");
        return Ok(tag);
    }
    info!(tag, "building image");

    let mut pull_stream = docker.create_image(
        Some(
            CreateImageOptionsBuilder::default()
                .from_image(BASE_IMAGE)
                .build(),
        ),
        None,
        None,
    );
    while let Some(result) = pull_stream.next().await {
        result.whatever_context(format!("failed to pull base image {BASE_IMAGE}"))?;
    }

    let container_name = format!("{CARGO_NAME}-xtask-rpm-setup-{triple}");
    remove_container_if_exists(docker, &container_name).await;
    let container = docker
        .create_container(
            Some(
                CreateContainerOptionsBuilder::default()
                    .name(&container_name)
                    .build(),
            ),
            ContainerCreateBody {
                image: Some(BASE_IMAGE.to_string()),
                cmd: Some(vec!["sleep".into(), "infinity".into()]),
                ..Default::default()
            },
        )
        .await
        .whatever_context("failed to create rpm setup container")?;
    let container_id = container.id.clone();

    let result = ensure_image_inner(docker, &container_id, triple).await;
    if result.is_err() {
        force_remove_container(docker, &container_id).await;
        result?;
        unreachable!();
    }

    let repo = tag.split(':').next().unwrap_or(&tag);
    let img_tag = tag.split(':').nth(1).unwrap_or(IMAGE_TAG_PREFIX);
    let commit_result = docker
        .commit_container(
            CommitContainerOptionsBuilder::default()
                .container(&container_id)
                .repo(repo)
                .tag(img_tag)
                .build(),
            ContainerConfig::default(),
        )
        .await
        .whatever_context("failed to commit image");
    force_remove_container(docker, &container_id).await;
    commit_result?;

    info!(tag, "image ready");
    Ok(tag)
}

async fn ensure_image_inner(
    docker: &Docker,
    container_id: &str,
    triple: &str,
) -> Result<(), Whatever> {
    start_container(docker, container_id).await?;

    // Install rpmbuild toolchain + Rust nightly + Zig + cargo-zigbuild.
    // Toolchain goes into /opt/cargo + /opt/rustup so any uid can use it.
    // gmutils links against no native libraries beyond libc, which zigbuild
    // bundles, so no cross sysroot is required.
    let setup_script = format!(
        r#"set -e
dnf install -y --setopt=install_weak_deps=False \
    rpm-build rpmdevtools systemd-rpm-macros \
    gcc make pkgconf-pkg-config \
    ca-certificates curl wget tar xz which util-linux \
    clang

export CARGO_HOME={CARGO_HOME}
export RUSTUP_HOME={RUSTUP_HOME}
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
    sh -s -- --default-toolchain nightly --profile minimal -y
export PATH="{CARGO_HOME}/bin:$PATH"
rustup target add {triple}

wget -q https://ziglang.org/download/0.14.0/zig-linux-x86_64-0.14.0.tar.xz
tar -xf zig-linux-x86_64-0.14.0.tar.xz
mv zig-linux-x86_64-0.14.0 /usr/local/zig
ln -s /usr/local/zig/zig /usr/local/bin/zig
rm zig-linux-x86_64-0.14.0.tar.xz

cargo install cargo-zigbuild

chmod -R a+rX {CARGO_HOME} {RUSTUP_HOME}
"#
    );
    exec_in_container(docker, container_id, &["bash", "-c", &setup_script], None).await?;
    Ok(())
}

async fn build_one(
    docker: &Docker,
    triple: &str,
    version: &str,
    target_dir: &Path,
    siblings: &[Sibling],
) -> Result<RpmArtifact, Whatever> {
    let arch = rpm_arch(triple)?;
    info!(triple, arch, "ensuring build image");
    let image = ensure_image(docker, triple).await?;

    let out_dir = target_dir.join(triple).join("release").join("rpm");
    tokio::fs::create_dir_all(&out_dir)
        .await
        .whatever_context(format!("failed to create {}", out_dir.display()))?;

    let workspace_dir =
        std::env::current_dir().whatever_context("failed to get current directory")?;

    let mut mounts = vec![Mount {
        target: Some("/workspace".into()),
        source: Some(workspace_dir.to_string_lossy().into_owned()),
        typ: Some(MountType::BIND),
        ..Default::default()
    }];
    for sibling in siblings {
        mounts.push(Mount {
            target: Some(format!("/{}", sibling.basename)),
            source: Some(sibling.host.to_string_lossy().into_owned()),
            typ: Some(MountType::BIND),
            ..Default::default()
        });
    }
    mounts.extend(cargo_cache_mounts());

    let bootstrap = dhttp_bootstrap_from_env()?;
    mounts.extend(bootstrap.mounts);
    let cargo_config = cargo_config_from_siblings(siblings);

    let container_name = format!("{CARGO_NAME}-xtask-rpm-{triple}");
    remove_container_if_exists(docker, &container_name).await;
    let container = docker
        .create_container(
            Some(
                CreateContainerOptionsBuilder::default()
                    .name(&container_name)
                    .build(),
            ),
            ContainerCreateBody {
                image: Some(image.clone()),
                cmd: Some(vec!["sleep".into(), "infinity".into()]),
                host_config: Some(HostConfig {
                    mounts: Some(mounts),
                    ..Default::default()
                }),
                ..Default::default()
            },
        )
        .await
        .whatever_context("failed to create rpm build container")?;
    let container_id = container.id.clone();

    let result = build_one_inner(
        docker,
        &container_id,
        triple,
        version,
        arch,
        &bootstrap.exports,
        cargo_config.as_deref(),
    )
    .await;
    force_remove_container(docker, &container_id).await;
    result?;

    info!(
        triple,
        out = %out_dir.display(),
        "produced rpm"
    );
    let path = find_rpm_artifact(&out_dir)
        .await
        .whatever_context("failed to find rpm artifact")?;
    Ok(RpmArtifact {
        target: triple.to_string(),
        path,
    })
}

async fn find_rpm_artifact(out_dir: &Path) -> Result<PathBuf, FindRpmArtifactError> {
    let mut entries =
        tokio::fs::read_dir(out_dir)
            .await
            .context(find_rpm_artifact_error::ReadDirSnafu {
                path: out_dir.to_path_buf(),
            })?;
    let mut artifact = None;
    while let Some(entry) =
        entries
            .next_entry()
            .await
            .context(find_rpm_artifact_error::ReadEntrySnafu {
                path: out_dir.to_path_buf(),
            })?
    {
        let path = entry.path();
        if path.extension().and_then(|extension| extension.to_str()) != Some("rpm") {
            continue;
        }
        if artifact.replace(path).is_some() {
            return Err(FindRpmArtifactError::MultipleArtifacts {
                path: out_dir.to_path_buf(),
            });
        }
    }
    artifact.ok_or_else(|| FindRpmArtifactError::NoArtifact {
        path: out_dir.to_path_buf(),
    })
}

async fn build_one_inner(
    docker: &Docker,
    container_id: &str,
    triple: &str,
    version: &str,
    arch: &str,
    dhttp_bootstrap_exports: &str,
    cargo_config: Option<&str>,
) -> Result<(), Whatever> {
    start_container(docker, container_id).await?;
    info!(triple, "build container started");

    install_cargo_config(docker, container_id, cargo_config).await?;

    let user = host_uid_gid()?;
    let spec = render_spec(version, arch);
    let aarch64_zigbuild_workaround = aarch64_zigbuild_workaround_script(triple);

    // All artifacts produced inside target/{triple}/release/rpm/ so they inherit
    // the bind-mount and host ownership. _topdir points into the workspace so
    // the final .rpm lands next to deb outputs automatically.
    let spec_escaped = shell_escape(&spec);
    let build_script = format!(
        r#"set -e
export HOME=/tmp
export PATH="{CARGO_HOME}/bin:/usr/local/zig:$PATH"
export RUSTUP_HOME={RUSTUP_HOME}
export CARGO_HOME={CARGO_HOME}
{dhttp_bootstrap_exports}
export RUSTFLAGS="${{RUSTFLAGS:-}}"
{aarch64_zigbuild_workaround}
cd /workspace
cargo zigbuild --release --target {triple}.{ZIG_GLIBC_VERSION} --bin genmeta

TOPDIR=/workspace/target/{triple}/release/rpm
rm -rf "$TOPDIR"/{{SPECS,BUILD,BUILDROOT,SOURCES,SRPMS,RPMS}}
mkdir -p "$TOPDIR"/{{SPECS,BUILD,BUILDROOT,SOURCES,SRPMS,RPMS}}

SPEC="$TOPDIR/SPECS/{PACKAGE_NAME}.spec"
printf '%s' {spec_escaped} > "$SPEC"

# stage prebuilt binary + script as SOURCES so rpmbuild's %install can pick them up
cp /workspace/target/{triple}/release/genmeta "$TOPDIR/SOURCES/genmeta"
cp /workspace/genmeta-ssh.sh "$TOPDIR/SOURCES/genmeta-ssh.sh"

rpmbuild -bb \
    --target={arch} \
    --define "_topdir $TOPDIR" \
    --define "_binary_payload w19.xzdio" \
    "$SPEC"

# Flatten: move the produced rpm up next to deb/scoop outputs.
find "$TOPDIR/RPMS" -name '*.rpm' -exec mv {{}} "$TOPDIR/" \;
"#
    );

    exec_in_container(
        docker,
        container_id,
        &["bash", "-c", &build_script],
        Some(&user),
    )
    .await?;
    info!(triple, "rpmbuild finished inside container");
    Ok(())
}

/// Single-quote a string for bash, escaping embedded single quotes.
fn shell_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for c in s.chars() {
        if c == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(c);
        }
    }
    out.push('\'');
    out
}

/// Generate the gmutils rpm spec.
///
/// The spec installs a pre-built binary staged in `SOURCES/`; no `%build`
/// compilation occurs during `rpmbuild` itself (cargo-zigbuild ran earlier).
/// `AutoReqProv: no` avoids rpm's dependency scanner pulling in glibc-specific
/// symbol versions from the zig-bundled libc shim; we list runtime deps
/// explicitly.
fn render_spec(version: &str, _arch: &str) -> String {
    format!(
        r#"Name:           {PACKAGE_NAME}
Version:        {version}
Release:        1%{{?dist}}
Summary:        {RPM_SUMMARY}
License:        {RPM_LICENSE}
URL:            {RPM_URL}
Vendor:         {RPM_VENDOR}
Source0:        genmeta
Source1:        genmeta-ssh.sh
AutoReqProv:    no
Requires:       glibc

%description
{RPM_DESCRIPTION}

%prep
# nothing to do: binary already built by cargo-zigbuild

%build
# nothing to do: binary already built by cargo-zigbuild

%install
rm -rf %{{buildroot}}
install -D -m 0755 %{{SOURCE0}} %{{buildroot}}/usr/bin/genmeta
install -D -m 0755 %{{SOURCE1}} %{{buildroot}}/usr/bin/genmeta-ssh.sh

%files
/usr/bin/genmeta
/usr/bin/genmeta-ssh.sh

%changelog
* %(date '+%a %b %d %Y') {RPM_VENDOR} <developer@genmeta.net> - {version}-1
- release {version}
"#
    )
}

#[cfg(test)]
mod tests {
    use super::{AARCH64_ZIGBUILD_RUSTFLAGS_WORKAROUND, aarch64_zigbuild_workaround_script};

    #[test]
    fn aarch64_linker_workaround_enables_unstable_flavor_option() {
        assert!(AARCH64_ZIGBUILD_RUSTFLAGS_WORKAROUND.contains("-Z unstable-options"));
        assert!(AARCH64_ZIGBUILD_RUSTFLAGS_WORKAROUND.contains("-Clinker-flavor=gnu-lld-cc"));
    }

    #[test]
    fn aarch64_zigbuild_workaround_filters_unsupported_cortex_linker_arg() {
        let script = aarch64_zigbuild_workaround_script("aarch64-unknown-linux-gnu");

        assert!(script.contains("CARGO_ZIGBUILD_ZIG_PATH"));
        assert!(script.contains("-Wl,--fix-cortex-a53-843419|--fix-cortex-a53-843419"));
        assert!(script.contains("/usr/local/zig/zig"));
    }
}
