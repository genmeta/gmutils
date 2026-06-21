#![allow(dead_code)]

use bollard::{
    Docker,
    models::{ContainerConfig, ContainerCreateBody, HostConfig},
    query_parameters::{
        CommitContainerOptionsBuilder, CreateContainerOptionsBuilder, CreateImageOptionsBuilder,
    },
};
use futures_util::StreamExt;
use snafu::{Report, ResultExt, Whatever};
use tracing::{Instrument, info, info_span};

use crate::{
    BuildProfile, DebTarget,
    container::{
        CARGO_HOME, ContainerSourceLayout, RUSTUP_HOME, ZIG_GLIBC_VERSION, cargo_cache_mounts,
        cargo_config_from_siblings, check_docker, dhttp_bootstrap_from_env, exec_in_container,
        force_remove_container, host_uid_gid, install_cargo_config, remove_container_if_exists,
        source_layout, source_mounts, start_container,
    },
    package_version, target_dir,
};

const CARGO_NAME: &str = "genmeta";

/// Distribution package name (differs from the cargo crate name).
const PACKAGE_NAME: &str = "gmutils";

/// Base Docker image for cross-compilation.
const BASE_IMAGE: &str = "debian:bookworm";

/// Image tag prefix for genmeta deb builds.
const IMAGE_TAG_PREFIX: &str = "gmutils-deb-v2";
const BUILD_ATTEMPTS: usize = 2;

/// Relative path from workspace root to the debian packaging source files.
const DEBIAN_PKG_DIR: &str = "xtask/deb";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DebArtifact {
    pub target: String,
    pub path: std::path::PathBuf,
}

fn deb_arch(triple: &str) -> Result<&'static str, Whatever> {
    match triple {
        "x86_64-unknown-linux-gnu" => Ok("amd64"),
        "aarch64-unknown-linux-gnu" => Ok("arm64"),
        "armv7-unknown-linux-gnueabihf" => Ok("armhf"),
        "i686-unknown-linux-gnu" => Ok("i386"),
        _ => snafu::whatever!("unsupported deb target triple: {triple}"),
    }
}

/// GNU architecture prefix used for cross-compilation lib paths.
fn gnu_arch(triple: &str) -> Result<&'static str, Whatever> {
    match triple {
        "x86_64-unknown-linux-gnu" => Ok("x86_64-linux-gnu"),
        "aarch64-unknown-linux-gnu" => Ok("aarch64-linux-gnu"),
        "armv7-unknown-linux-gnueabihf" => Ok("arm-linux-gnueabihf"),
        "i686-unknown-linux-gnu" => Ok("i386-linux-gnu"),
        _ => snafu::whatever!("unsupported gnu arch for triple: {triple}"),
    }
}

// (shared docker/container helpers live in crate::container)

/// Ensure the Debian base image is available locally.
///
/// Docker's pull API contacts the registry even when the tag already exists
/// locally. Packaging should only depend on the registry when the local image is
/// missing; otherwise a transient registry timeout can fail an otherwise
/// reproducible local build.
async fn ensure_base_image(docker: &Docker) -> Result<(), Whatever> {
    if docker.inspect_image(BASE_IMAGE).await.is_ok() {
        info!(image = BASE_IMAGE, "base image already exists");
        return Ok(());
    }

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

    Ok(())
}

/// Ensure the build image exists for the given target triple.
/// If not, pull the base image, create a container, install toolchain, and commit.
async fn ensure_image(docker: &Docker, triple: &str) -> Result<String, Whatever> {
    let deb = deb_arch(triple)?;
    let tag = format!("xtask-{triple}:{IMAGE_TAG_PREFIX}");

    // Check if image already exists
    if docker.inspect_image(&tag).await.is_ok() {
        info!(tag, "image already exists");
        return Ok(tag);
    }

    info!(tag, "building image");

    ensure_base_image(docker).await?;

    // Create temp container from base
    let container_name = format!("{CARGO_NAME}-xtask-setup-{triple}");
    // Remove a leaked container left by a previous failed run so we can retry.
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
        .whatever_context("failed to create setup container")?;
    let container_id = container.id.clone();

    // Any failure past this point must still remove the container, otherwise
    // the name collides on retry. We wrap the fallible work in an inner fn.
    let result = ensure_image_inner(docker, &container_id, triple, deb).await;

    if result.is_err() {
        // Do not commit; just clean up and propagate.
        force_remove_container(docker, &container_id).await;
        result?;
        unreachable!();
    }

    // Commit the container as a new image
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

    // Always remove the setup container before returning, success or not.
    force_remove_container(docker, &container_id).await;
    commit_result?;

    info!(tag, "image ready");
    Ok(tag)
}

/// Run the toolchain-installation steps inside an already-created container.
async fn ensure_image_inner(
    docker: &Docker,
    container_id: &str,
    triple: &str,
    deb: &str,
) -> Result<(), Whatever> {
    start_container(docker, container_id).await?;

    // Install Rust toolchain, Zig, cargo-zigbuild, and cross-compilation libs.
    // Toolchain is installed to /opt/cargo + /opt/rustup so any uid can use it.
    let setup_script = format!(
        r#"set -e
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install --assume-yes -qq \
    ca-certificates curl build-essential pkg-config libclang-dev wget

# install rust into globally readable paths
export CARGO_HOME={CARGO_HOME}
export RUSTUP_HOME={RUSTUP_HOME}
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
    sh -s -- --default-toolchain nightly --profile minimal -y
export PATH="{CARGO_HOME}/bin:$PATH"
rustup target add {triple}

# install zig
wget -q https://ziglang.org/download/0.14.0/zig-linux-x86_64-0.14.0.tar.xz
tar -xf zig-linux-x86_64-0.14.0.tar.xz
mv zig-linux-x86_64-0.14.0 /usr/local/zig
ln -s /usr/local/zig/zig /usr/local/bin/zig
rm zig-linux-x86_64-0.14.0.tar.xz

cargo install cargo-zigbuild

# cross-compilation libraries
dpkg --add-architecture {deb}
apt-get update -qq
apt-get install --assume-yes -qq libc-dev:{deb} dpkg-dev debhelper fakeroot

# make toolchain readable by any user
chmod -R a+rX {CARGO_HOME} {RUSTUP_HOME}
"#
    );
    exec_in_container(docker, container_id, &["bash", "-c", &setup_script], None).await?;
    Ok(())
}

pub async fn run(
    targets: &[DebTarget],
    profile: BuildProfile,
    siblings: &[std::path::PathBuf],
) -> Result<Vec<DebArtifact>, Whatever> {
    info!(
        target_count = targets.len(),
        profile = profile.target_dir_name(),
        "starting deb dist build"
    );
    let docker = Docker::connect_with_local_defaults()
        .whatever_context("failed to connect to Docker/Podman")?;
    check_docker(&docker).await?;

    // Resolve sibling paths up front so every target build sees the same set
    // and path errors surface before we spin up containers.
    let layout = source_layout("gmutils", siblings)?;

    let version = package_version(CARGO_NAME)?;
    let target_dir = target_dir()?;

    let mut tasks = tokio::task::JoinSet::new();

    for &target in targets {
        let docker = docker.clone();
        let version = version.clone();
        let target_dir = target_dir.clone();
        let layout = layout.clone();
        let triple = target.triple();
        info!(
            triple,
            profile = profile.target_dir_name(),
            "queued deb target build"
        );
        let span = info_span!("deb", triple);
        tasks.spawn(
            async move {
                build_one_with_retry(&docker, triple, &version, &target_dir, profile, &layout).await
            }
            .instrument(span),
        );
    }

    info!("waiting for deb target builds to finish");
    let mut artifacts = Vec::new();
    while let Some(result) = tasks.join_next().await {
        artifacts.push(result.whatever_context("deb build task panicked")??);
    }
    artifacts.sort_by(|left, right| left.target.cmp(&right.target));

    info!("finished deb dist build");

    Ok(artifacts)
}

async fn build_one_with_retry(
    docker: &Docker,
    triple: &str,
    version: &str,
    target_dir: &std::path::Path,
    profile: BuildProfile,
    layout: &ContainerSourceLayout,
) -> Result<DebArtifact, Whatever> {
    for attempt in 1..=BUILD_ATTEMPTS {
        match build_one(docker, triple, version, target_dir, profile, layout).await {
            Ok(artifact) => return Ok(artifact),
            Err(error) if attempt < BUILD_ATTEMPTS => {
                let report = Report::from_error(&error);
                tracing::warn!(
                    %triple,
                    attempt,
                    error = %report,
                    "deb target build failed, retrying"
                );
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
            Err(error) => return Err(error),
        }
    }
    unreachable!("build attempts loop must return")
}

async fn build_one(
    docker: &Docker,
    triple: &str,
    version: &str,
    target_dir: &std::path::Path,
    profile: BuildProfile,
    layout: &ContainerSourceLayout,
) -> Result<DebArtifact, Whatever> {
    let arch = deb_arch(triple)?;
    let gnu = gnu_arch(triple)?;
    info!(triple, "ensuring build image");
    let image = ensure_image(docker, triple).await?;

    let deb_name = format!("{PACKAGE_NAME}_{version}-1_{arch}.deb");
    let profile_dir = profile.target_dir_name();
    let out_dir = target_dir.join(triple).join(profile_dir).join("deb");
    tokio::fs::create_dir_all(&out_dir)
        .await
        .whatever_context(format!("failed to create {}", out_dir.display()))?;

    let mut mounts = source_mounts(layout);
    mounts.extend(cargo_cache_mounts());

    let bootstrap = dhttp_bootstrap_from_env()?;
    mounts.extend(bootstrap.mounts);
    let cargo_config = cargo_config_from_siblings(&layout.overrides);

    let container_name = format!("{CARGO_NAME}-xtask-deb-{triple}");
    info!(triple, container = %container_name, "creating build container");
    // Clean up any leftover container from a previous failed run.
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
        .whatever_context("failed to create build container")?;
    let container_id = container.id.clone();

    // Run the actual build; always clean up the container regardless of outcome.
    let result = build_one_inner(
        docker,
        &container_id,
        triple,
        version,
        arch,
        gnu,
        profile,
        &layout.primary.container,
        &bootstrap.exports,
        cargo_config.as_deref(),
    )
    .await;
    force_remove_container(docker, &container_id).await;
    result?;

    info!(deb_name, "produced");
    Ok(DebArtifact {
        target: triple.to_string(),
        path: out_dir.join(deb_name),
    })
}

#[allow(clippy::too_many_arguments)]
async fn build_one_inner(
    docker: &Docker,
    container_id: &str,
    triple: &str,
    version: &str,
    arch: &str,
    gnu: &str,
    profile: BuildProfile,
    primary_source: &str,
    dhttp_bootstrap_exports: &str,
    cargo_config: Option<&str>,
) -> Result<(), Whatever> {
    start_container(docker, container_id).await?;
    info!(triple, "build container started");

    // Install cross-compilation binutils (needs root).
    let install_binutils = format!("apt-get install -y -qq binutils-{gnu} 2>/dev/null || true");
    exec_in_container(
        docker,
        container_id,
        &["bash", "-c", &install_binutils],
        None,
    )
    .await?;
    install_cargo_config(docker, container_id, cargo_config).await?;

    // dpkg-buildpackage -B builds only Architecture: any packages.
    // -a{arch} sets the host architecture for cross-compilation.
    // Prepare debian source tree under target/{triple}/{profile}/deb/src/ so that
    // all temp files and products stay inside target/ (bind-mounted, gitignored).
    // Runs as host uid:gid so files in target/ are owned by the host user.
    let user = host_uid_gid()?;
    let profile_dir = profile.target_dir_name();
    let cargo_profile_args = profile.cargo_profile_args().join(" ");
    let build_script = format!(
        r#"set -e
export HOME=/tmp
export PATH="{CARGO_HOME}/bin:/usr/local/zig:$PATH"
export RUSTUP_HOME={RUSTUP_HOME}
export CARGO_HOME={CARGO_HOME}
export TRIPLE={triple}
export ZIG_TARGET={triple}.{ZIG_GLIBC_VERSION}
export BUILD_PROFILE={profile_dir}
export CARGO_PROFILE_ARGS="{cargo_profile_args}"
export DEB_HOST_MULTIARCH={gnu}
{dhttp_bootstrap_exports}
SRC={primary_source}/target/{triple}/{profile_dir}/deb/src
mkdir -p "$SRC/debian"
cp -r {primary_source}/{DEBIAN_PKG_DIR}/. "$SRC/debian/"
printf '{PACKAGE_NAME} ({version}-1) unstable; urgency=low\n\n  * release {version}\n\n -- Genmeta Tech Limited <developer@genmeta.net>  %s\n' \
    "$(date -R)" > "$SRC/debian/changelog"
cd "$SRC"
dpkg-buildpackage -B -uc -us -d -a{arch}
"#
    );

    info!(triple, "starting dpkg-buildpackage inside container");
    exec_in_container(
        docker,
        container_id,
        &["bash", "-c", &build_script],
        Some(&user),
    )
    .await?;
    info!(triple, "dpkg-buildpackage finished inside container");
    Ok(())
}
