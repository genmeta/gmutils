//! Single-package publication; the trusted store validates uploaded releases.
use std::{
    path::{Path, PathBuf},
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use dhttp_home::{DhttpHome, HomeScope, certificate::OwnerHash};
use dhttp_identity::name::DhttpName;
use http::{HeaderValue, StatusCode, Uri, header};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use snafu::{FromString, OptionExt, ResultExt, Whatever, whatever};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

const STORE_NAME: &str = "store.dhttp.net";
const STORE_OWNER: &str = "ffc3e50e1dfb7baca1cc07a7cbfcf8cb34a9bf5a9c25024fcf9a9786bb230746";
const PACKAGE_LIMIT: usize = 64 * 1024 * 1024;
const JSON_LIMIT: usize = 1024 * 1024;
const UPLOAD_TIMEOUT: Duration = Duration::from_secs(180);
const METADATA_TIMEOUT: Duration = Duration::from_secs(30);

pub(super) async fn run(file: PathBuf, id: Option<String>) -> Result<(), Whatever> {
    let bytes = read_snapshot(&file).await?;
    let metadata = inspect_package(&bytes).await?;
    let publisher = text(&metadata, "publisher")?;
    let selected: DhttpName<'static> = id
        .unwrap_or_else(|| publisher.to_owned())
        .parse()
        .whatever_context("invalid publisher identity")?;
    if selected.as_full() != publisher {
        whatever!("--id must match the signed package publisher {publisher}");
    }
    let home = DhttpHome::load(HomeScope::User).whatever_context("failed to locate DHTTP home")?;
    let profile = home
        .resolve_identity_profile(selected.as_full())
        .await
        .whatever_context(format!(
            "missing local credentials for publisher {publisher}"
        ))?;
    let endpoint = tokio::time::timeout(
        METADATA_TIMEOUT,
        dhttp::Endpoint::load_from_with_ocsp(profile.path()),
    )
    .await
    .whatever_context("publisher credential loading timed out")?
    .whatever_context("failed to load the publisher's authenticated DHTTP endpoint")?;
    let authority = endpoint
        .local_authority()
        .whatever_context("failed to load outgoing signing authority")?;
    let certificates = package_certificates(&bytes)?;
    verify_publisher(&metadata, &certificates, &authority)?;
    let owner = owner_hash(&certificates)?;
    tokio::time::timeout(METADATA_TIMEOUT, init_network())
        .await
        .whatever_context("DHTTP network initialization timed out")??;
    let output = publish(&endpoint, &bytes, &metadata, &owner).await?;
    println!(
        "{}",
        serde_json::to_string(&output).whatever_context("failed to encode upload result")?
    );
    Ok(())
}

async fn read_snapshot(path: &Path) -> Result<Vec<u8>, Whatever> {
    // O_NONBLOCK prevents a replacement FIFO from blocking before fstat; use the
    // opened handle's metadata and never reopen the user's pathname afterwards.
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW);
    }
    let file = options
        .open(path)
        .whatever_context(format!("cannot open upload file {}", path.display()))?;
    let metadata = file
        .metadata()
        .whatever_context("cannot inspect upload file")?;
    if !metadata.is_file() {
        whatever!("upload requires one local regular file");
    }
    if metadata.len() > PACKAGE_LIMIT as u64 {
        whatever!("upload file exceeds 64 MiB");
    }
    bounded_read(
        tokio::fs::File::from_std(file),
        PACKAGE_LIMIT,
        "upload file",
    )
    .await
}

async fn bounded_read(
    reader: impl AsyncRead + Unpin,
    limit: usize,
    label: &str,
) -> Result<Vec<u8>, Whatever> {
    let mut bytes = Vec::new();
    reader
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .await
        .whatever_context(format!("failed to read {label}"))?;
    if bytes.len() > limit {
        whatever!("{label} exceeds its size limit ({limit} bytes)");
    }
    Ok(bytes)
}

fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str, Whatever> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .whatever_context(format!("missing or invalid {key}"))
}

// Read only the bounded raw manifest for identity and request paths. The store
// verifies the uploaded release before registering or returning it.
fn manifest_identity(bytes: &[u8]) -> Result<Value, Whatever> {
    if bytes.get(..8) != Some(b"\0webc003") || bytes.get(8) != Some(&2) {
        whatever!("expected a signed WEBC v3 package; run genmeta build first");
    }
    let length = |offset: usize| -> Result<usize, Whatever> {
        let raw: [u8; 8] = bytes
            .get(offset..offset + 8)
            .whatever_context("truncated WEBC section length")?
            .try_into()
            .unwrap();
        usize::try_from(u64::from_le_bytes(raw)).whatever_context("WEBC section length overflow")
    };
    let mut offset = 17usize
        .checked_add(length(9)?)
        .filter(|end| *end <= bytes.len())
        .whatever_context("truncated WEBC index")?;
    if offset > JSON_LIMIT {
        whatever!("WEBC index exceeds 1 MiB");
    }
    while offset < bytes.len() {
        let header_end = offset
            .checked_add(41)
            .filter(|end| *end <= bytes.len())
            .whatever_context("truncated WEBC section")?;
        let end = header_end
            .checked_add(length(offset + 33)?)
            .filter(|end| *end <= bytes.len())
            .whatever_context("truncated WEBC section body")?;
        if bytes[offset] == 1 {
            if end - offset > JSON_LIMIT {
                whatever!("WEBC manifest exceeds 1 MiB");
            }
            let section = webc::v3::read::Section::parse(
                1,
                Some(bytes[offset + 1..offset + 33].try_into().unwrap()),
                bytes[header_end..end].to_vec().into(),
            )
            .whatever_context("invalid WEBC manifest section")?;
            let manifest = section
                .as_manifest()
                .whatever_context("missing WEBC manifest")?
                .manifest()
                .whatever_context("invalid WEBC manifest")?;
            let document = serde_json::to_value(manifest)
                .whatever_context("invalid WEBC manifest annotations")?;
            let wapm = &document["package"]["wapm"];
            let annotation = &document["package"]["pishoo"];
            let id = text(wapm, "name")?;
            let (publisher, name) = id
                .split_once('/')
                .whatever_context("manifest name must be publisher/name")?;
            let version = text(wapm, "version")?;
            let kind = text(annotation, "kind")?;
            if !matches!(kind, "app" | "lib") {
                whatever!("manifest kind must be app or lib");
            }
            let mut result =
                json!({"id":id,"publisher":publisher,"name":name,"version":version,"kind":kind});
            if let Some(repository) = wapm.get("repository") {
                // Preserve it for comparison; the host validates its URL format.
                result["repository"] = repository.clone();
            }
            return Ok(result);
        }
        offset = end;
    }
    whatever!("missing WEBC manifest");
}

async fn inspect_package(bytes: &[u8]) -> Result<Value, Whatever> {
    let mut metadata = manifest_identity(bytes)?;
    let package = webc::Container::from_bytes_and_version(bytes.to_vec().into(), webc::Version::V3)
        .whatever_context("cannot parse package container")?;
    package
        .validate()
        .whatever_context("invalid package content digest or mapping")?;
    signature_envelope(bytes)?;
    let document =
        serde_json::to_value(package.manifest()).whatever_context("invalid package manifest")?;
    for key in ["title", "dependencies", "changelog", "entry", "host"] {
        if let Some(value) = document["package"]["pishoo"].get(key) {
            metadata[key] = value.clone();
        }
    }
    for key in ["description", "license", "repository"] {
        if let Some(value) = document["package"]["wapm"].get(key) {
            metadata[key] = value.clone();
        }
    }
    version_path(&metadata)?;
    Ok(metadata)
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

// Extract the existing protocol digest after the host has validated these spans.
fn payload_digest(bytes: &[u8]) -> Result<String, Whatever> {
    let reader =
        webc::v3::read::OwnedReader::parse(bytes.to_vec()).whatever_context("cannot parse WEBC")?;
    let index = reader.index();
    let mut hasher = Sha256::new();
    hasher.update(b"\0webc003");
    for entry in std::iter::once(&index.manifest)
        .chain(std::iter::once(&index.atoms))
        .chain(
            index
                .volumes
                .iter()
                .filter(|(name, _)| name.as_str() != "pishoo-signature")
                .map(|(_, entry)| entry),
        )
    {
        let end = entry
            .span
            .start
            .checked_add(entry.span.len)
            .whatever_context("WEBC span overflow")?;
        hasher.update(
            bytes
                .get(entry.span.start..end)
                .whatever_context("WEBC span exceeds package")?,
        );
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn signature_envelope(bytes: &[u8]) -> Result<Value, Whatever> {
    let package = webc::Container::from_bytes_and_version(bytes.to_vec().into(), webc::Version::V3)
        .whatever_context("cannot parse package")?;
    let volume = package
        .get_volume("pishoo-signature")
        .whatever_context("missing package signature")?;
    let (data, _) = volume
        .read_file("/signature.json")
        .whatever_context("missing signature envelope")?;
    if data.len() > 64 * 1024 {
        whatever!("signature envelope exceeds 64 KiB");
    }
    serde_json::from_slice(&data).whatever_context("invalid signature envelope JSON")
}

fn package_certificates(
    bytes: &[u8],
) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>, Whatever> {
    signature_envelope(bytes)?["certificates"]
        .as_array()
        .filter(|v| !v.is_empty())
        .whatever_context("missing package signer certificates")?
        .iter()
        .map(|value| {
            STANDARD
                .decode(
                    value
                        .as_str()
                        .whatever_context("invalid signer certificate")?,
                )
                .map(rustls::pki_types::CertificateDer::from)
                .whatever_context("invalid signer certificate encoding")
        })
        .collect()
}

fn owner_hash(certificates: &[rustls::pki_types::CertificateDer<'_>]) -> Result<String, Whatever> {
    Ok(
        dhttp_home::certificate::extract_dhttp_subject_key_identifier(certificates)
            .whatever_context("invalid identity owner_hash")?
            .owner_hash()
            .as_str()
            .to_owned(),
    )
}

fn verify_publisher(
    metadata: &Value,
    certificates: &[rustls::pki_types::CertificateDer<'_>],
    authority: &dhttp::LocalAuthority,
) -> Result<(), Whatever> {
    if authority.name() != text(metadata, "publisher")?
        || certificates != authority.certificates()
        || owner_hash(certificates)? != owner_hash(authority.certificates())?
    {
        whatever!(
            "package signer differs from current publisher credentials; run genmeta build again with the current credentials"
        );
    }
    Ok(())
}

fn version_path(metadata: &Value) -> Result<String, Whatever> {
    let publisher = text(metadata, "publisher")?;
    let normalized: DhttpName<'static> = publisher
        .parse()
        .whatever_context("invalid package publisher")?;
    let name = text(metadata, "name")?;
    let version = text(metadata, "version")?;
    let valid_version = version.split('.').count() == 3
        && version.split('.').all(|part| {
            !part.is_empty()
                && (part == "0" || !part.starts_with('0'))
                && part.bytes().all(|c| c.is_ascii_digit())
                && part.parse::<u64>().is_ok()
        });
    if normalized.as_full() != publisher
        || name.len() > 63
        || !name.as_bytes()[0].is_ascii_lowercase()
        || !name
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
        || !valid_version
    {
        whatever!("invalid normalized package identity or exact version");
    }
    let collection = match text(metadata, "kind")? {
        "app" => "apps",
        "lib" => "libs",
        _ => whatever!("invalid package kind"),
    };
    Ok(format!(
        "/store/v1/{collection}/{publisher}/{name}/versions/{version}"
    ))
}

fn store_uri(path: &str) -> Result<Uri, Whatever> {
    format!("https://{STORE_NAME}{path}")
        .parse()
        .whatever_context("invalid fixed store URI")
}

async fn init_network() -> Result<(), Whatever> {
    let mdns = ddns::install_resolvers(&[ddns::DnsScheme::Mdns, ddns::DnsScheme::H3])
        .whatever_context("failed to initialize DHTTP DNS")?;
    let network = dhttp::DhttpNetwork::init()
        .await
        .whatever_context("failed to initialize DHTTP network")?;
    if let Some(mdns) = mdns {
        mdns.maintain(Duration::from_secs(1), move || {
            Ok(network
                .active_bindings()
                .map_err(std::io::Error::other)?
                .into_iter()
                .filter(|binding| {
                    dhttp::resolve::EndpointAddr::direct(binding.address).scope()
                        == Some(dhttp::Scope::Internal)
                })
                .map(|binding| ddns::mdns::MdnsBinding::new(binding.device, binding.address.ip()))
                .collect())
        })
        .await
        .whatever_context("failed to initialize mDNS interfaces")?;
    }
    Ok(())
}

fn verify_store(response: &http::Response<dhttp::Body>) -> Result<(), Whatever> {
    let remote = response
        .extensions()
        .get::<dhttp::RemoteAuthority>()
        .whatever_context("store response lacks authenticated RemoteAuthority")?;
    if remote.name() != STORE_NAME || owner_hash(remote.certificates())? != STORE_OWNER {
        whatever!("store response identity does not match the pinned store owner");
    }
    Ok(())
}

async fn read_response(
    response: http::Response<dhttp::Body>,
    limit: usize,
    content_type: &str,
) -> Result<http::Response<Vec<u8>>, Whatever> {
    verify_store(&response)?;
    let (parts, mut body) = response.into_parts();
    if matches!(parts.status, StatusCode::OK | StatusCode::CREATED)
        && !parts
            .headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(';').next())
            .is_some_and(|v| v.trim().eq_ignore_ascii_case(content_type))
    {
        whatever!("unexpected store response Content-Type");
    }
    if let Some(length) = parts.headers.get(header::CONTENT_LENGTH) {
        let length = length
            .to_str()
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .whatever_context("invalid response Content-Length")?;
        if length > limit as u64 {
            whatever!("store response exceeds its size limit");
        }
    }
    let mut bytes = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame
            .map_err(|e| std::io::Error::other(e.to_string()))
            .whatever_context("failed to read store response")?;
        let data = frame
            .into_data()
            .map_err(|_| std::io::Error::other("unsupported response trailers"))
            .whatever_context("store response trailers are unsupported")?;
        if data.len() > limit.saturating_sub(bytes.len()) {
            whatever!("store response exceeds its size limit");
        }
        bytes.extend_from_slice(&data);
    }
    if let Some(length) = parts.headers.get(header::CONTENT_LENGTH)
        && length.to_str().ok().and_then(|v| v.parse::<usize>().ok()) != Some(bytes.len())
    {
        whatever!("store response length differs from Content-Length");
    }
    Ok(http::Response::from_parts(parts, bytes))
}

async fn put(
    endpoint: &dhttp::Endpoint,
    path: &str,
    bytes: &[u8],
) -> Result<http::Response<Vec<u8>>, Whatever> {
    tokio::time::timeout(UPLOAD_TIMEOUT, async {
        let (mut writer, receive) = endpoint
            .put(store_uri(path)?)
            .expect_remote_owner_hash(
                OwnerHash::try_from(STORE_OWNER).whatever_context("invalid store trust anchor")?,
            )
            .header(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/webc"),
            )
            .header(header::ACCEPT, HeaderValue::from_static("application/json"))
            .header(
                header::CONTENT_LENGTH,
                HeaderValue::from_str(&bytes.len().to_string())
                    .whatever_context("invalid package size header")?,
            )
            .await
            .whatever_context("failed to open store upload")?;
        let send = async {
            writer
                .write_all(bytes)
                .await
                .whatever_context("failed to send package snapshot")?;
            writer
                .shutdown()
                .await
                .whatever_context("failed to finish package upload")
        };
        let receive = async {
            let response = receive
                .await
                .whatever_context("failed to receive store upload response")?;
            read_response(response, JSON_LIMIT, "application/json").await
        };
        // Read concurrently, so early daccess rejection cancels an unfinished body.
        tokio::pin!(send, receive);
        tokio::select! {
            result = &mut send => {
                match result {
                    Ok(()) => receive.await,
                    Err(error) => match receive.await {
                        Ok(response) if !response.status().is_success() => Ok(response),
                        _ => Err(error),
                    },
                }
            },
            result = &mut receive => {
                let response = result?;
                if response.status().is_success() { send.await?; }
                Ok(response)
            }
        }
    })
    .await
    .whatever_context("store upload timed out after 180 seconds")?
}

async fn get(
    endpoint: &dhttp::Endpoint,
    path: &str,
    package: bool,
) -> Result<http::Response<Vec<u8>>, Whatever> {
    let deadline = if package {
        UPLOAD_TIMEOUT
    } else {
        METADATA_TIMEOUT
    };
    tokio::time::timeout(deadline, async {
        let mime = if package {
            "application/webc"
        } else {
            "application/json"
        };
        let response = endpoint
            .get(store_uri(path)?)
            .expect_remote_owner_hash(
                OwnerHash::try_from(STORE_OWNER).whatever_context("invalid store trust anchor")?,
            )
            .header(header::ACCEPT, HeaderValue::from_static(mime))
            .await
            .whatever_context("store verification GET failed")?;
        read_response(
            response,
            if package { PACKAGE_LIMIT } else { JSON_LIMIT },
            mime,
        )
        .await
    })
    .await
    .whatever_context("store verification GET timed out")?
}

fn http_failure(response: &http::Response<Vec<u8>>) -> Whatever {
    let hint = match response.status() {
        StatusCode::CONFLICT => {
            " Increase the package version; existing versions cannot be overwritten."
        }
        StatusCode::UNPROCESSABLE_ENTITY | StatusCode::BAD_REQUEST => {
            " Publish any missing exact Lib dependencies first."
        }
        StatusCode::GONE => " This version remains withdrawn; retrying does not restore it.",
        _ => "",
    };
    // Retain the real daccess/store diagnostic, including any exact dependency ID.
    Whatever::without_source(format!(
        "store returned HTTP {}: {}{}",
        response.status(),
        String::from_utf8_lossy(response.body()).trim(),
        hint
    ))
}

fn release_metadata(
    response: &http::Response<Vec<u8>>,
    metadata: &Value,
    owner: &str,
) -> Result<Value, Whatever> {
    let release: Value =
        serde_json::from_slice(response.body()).whatever_context("invalid store release JSON")?;
    for key in ["id", "publisher", "name", "kind", "version"] {
        if release[key] != metadata[key] {
            whatever!("store release {key} differs from signed package");
        }
    }
    if release["publisher_owner_hash"] != owner {
        whatever!("store release publisher owner_hash mismatch");
    }
    let path = format!(
        "{}/{}.webc",
        version_path(metadata)?,
        text(metadata, "kind")?
    );
    if release["download_path"] != path {
        whatever!("store returned an unexpected download path");
    }
    let hash = text(&release, "package_sha256")?;
    if hash.len() != 64
        || !hash
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        || release["size"]
            .as_u64()
            .is_none_or(|n| n == 0 || n > PACKAGE_LIMIT as u64)
    {
        whatever!("store release has invalid package digest or size");
    }
    match text(&release, "status")? {
        "published" => {}
        "yanked" => {
            whatever!("this version remains withdrawn (yanked); retrying does not restore it")
        }
        _ => whatever!("invalid store release status"),
    }
    Ok(release)
}

async fn confirm_release(
    endpoint: &dhttp::Endpoint,
    release: &Value,
    bytes: &[u8],
    metadata: &Value,
    owner: &str,
    first: bool,
) -> Result<(), Whatever> {
    if release["package_sha256"] == digest(bytes) {
        if release["size"].as_u64() != Some(bytes.len() as u64) {
            whatever!("saved package size mismatch");
        }
        return Ok(());
    }
    if first {
        whatever!("first publication response package digest differs from uploaded snapshot");
    }
    let response = get(endpoint, text(release, "download_path")?, true).await?;
    if response.status() != StatusCode::OK {
        return Err(http_failure(&response));
    }
    let saved = response.body();
    if digest(saved) != release["package_sha256"]
        || release["size"].as_u64() != Some(saved.len() as u64)
    {
        whatever!("downloaded saved package digest or size differs from trusted store metadata");
    }
    let saved_metadata = inspect_package(saved).await?;
    for key in ["id", "publisher", "name", "kind", "version"] {
        if saved_metadata[key] != metadata[key] {
            whatever!("saved package identity differs from upload");
        }
    }
    if signature_envelope(saved)?["certificates"] != release["signer_certificates"]
        || owner_hash(&package_certificates(saved)?)? != owner
    {
        whatever!("saved signer differs from trusted store proof or publisher owner_hash");
    }
    if payload_digest(saved)? != payload_digest(bytes)? {
        whatever!("this version already has different content; increase the package version");
    }
    Ok(())
}

fn success(release: &Value, result: &str) -> Result<Value, Whatever> {
    Ok(
        json!({"result":result,"id":release["id"],"kind":release["kind"],"version":release["version"],
        "status":release["status"],"package_sha256":release["package_sha256"],
        "detail_url":store_uri(&version_path(release)?)?.to_string()}),
    )
}

async fn reconcile(
    endpoint: &dhttp::Endpoint,
    bytes: &[u8],
    metadata: &Value,
    owner: &str,
) -> Result<Value, Whatever> {
    let response = get(endpoint, &version_path(metadata)?, false).await?;
    if response.status() != StatusCode::OK {
        return Err(http_failure(&response));
    }
    let release = release_metadata(&response, metadata, owner)?;
    confirm_release(endpoint, &release, bytes, metadata, owner, false).await?;
    success(&release, "published")
}

async fn publish(
    endpoint: &dhttp::Endpoint,
    bytes: &[u8],
    metadata: &Value,
    owner: &str,
) -> Result<Value, Whatever> {
    let response = put(endpoint, &version_path(metadata)?, bytes).await;
    match response {
        Ok(response) if matches!(response.status(), StatusCode::OK | StatusCode::CREATED) => {
            let release = release_metadata(&response, metadata, owner)?;
            confirm_release(
                endpoint,
                &release,
                bytes,
                metadata,
                owner,
                response.status() == StatusCode::CREATED,
            )
            .await?;
            success(
                &release,
                if response.status() == StatusCode::CREATED {
                    "published"
                } else {
                    "already-published"
                },
            )
        }
        Ok(response) if !response.status().is_server_error() => Err(http_failure(&response)),
        unknown => {
            let cause = match unknown {
                Ok(response) => http_failure(&response),
                Err(error) => error,
            };
            eprintln!("upload result uncertain ({cause}); checking the exact saved version once");
            reconcile(endpoint, bytes, metadata, owner).await.whatever_context(
                "发布结果未知，可稍后重新执行同一命令 (publication result unknown; retry the same command later); read-only verification did not prove publication")
        }
    }
}

#[cfg(test)]
#[path = "upload_tests.rs"]
mod tests;
