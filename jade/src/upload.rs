//! Single-package publication; the trusted store validates uploaded releases.
use std::{path::PathBuf, time::Duration};

use dhttp_home::certificate::OwnerHash;
use http::{HeaderValue, StatusCode, Uri, header};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use snafu::{FromString, OptionExt, ResultExt, Whatever, whatever};
use tokio::io::AsyncWriteExt;

use crate::package::{
    PACKAGE_LIMIT, digest, inspect_package, owner_hash, package_certificates, payload_digest,
    read_snapshot, signature_envelope, text, version_path,
};

const STORE_NAME: &str = "store.dhttp.net";
const STORE_OWNER: &str = "ffc3e50e1dfb7baca1cc07a7cbfcf8cb34a9bf5a9c25024fcf9a9786bb230746";
const JSON_LIMIT: usize = 1024 * 1024;
const UPLOAD_TIMEOUT: Duration = Duration::from_secs(180);
const METADATA_TIMEOUT: Duration = Duration::from_secs(30);

pub(super) async fn run(file: PathBuf) -> crate::error::Result<Value> {
    use crate::error::Error;
    let bytes = read_snapshot(&file)
        .await
        .map_err(|e| Error::new("E_PACKAGE_INVALID", e))?;
    let metadata = inspect_package(&bytes).await?;
    let author = text(&metadata, "author").map_err(|e| Error::new("E_PACKAGE_INVALID", e))?;
    let home = crate::identity::home()?;
    let (local_certificates, _) = crate::identity::credentials(&home, author).await?;
    let certificates =
        package_certificates(&bytes).map_err(|e| Error::new("E_SIGNATURE_INVALID", e))?;
    if local_certificates != certificates {
        return Err(Error::new(
            "E_IDENTITY_MISMATCH",
            "Package signer differs from current author credentials",
        )
        .hint("Run jade build again with the current credentials"));
    }
    let owner = owner_hash(&certificates).map_err(|e| Error::new("E_SIGNATURE_INVALID", e))?;
    let profile = home
        .resolve_identity_profile(author)
        .await
        .map_err(|e| Error::new("E_IDENTITY_UNAVAILABLE", e))?;
    let endpoint = tokio::time::timeout(
        METADATA_TIMEOUT,
        dhttp::Endpoint::load_from_with_ocsp(profile.path()),
    )
    .await
    .map_err(|e| Error::new("E_IDENTITY_UNAVAILABLE", e))?
    .map_err(|e| Error::new("E_IDENTITY_UNAVAILABLE", e))?;
    let authority = endpoint
        .local_authority()
        .map_err(|e| Error::new("E_IDENTITY_UNAVAILABLE", e))?;
    verify_author(&metadata, &certificates, &authority)
        .map_err(|e| Error::new("E_IDENTITY_MISMATCH", e))?;
    tokio::time::timeout(METADATA_TIMEOUT, init_network())
        .await
        .map_err(|e| Error::new("E_PUBLISH_REJECTED", e))?
        .map_err(|e| Error::new("E_PUBLISH_REJECTED", e))?;
    publish(&endpoint, &bytes, &metadata, &owner).await
}

fn verify_author(
    metadata: &Value,
    certificates: &[rustls::pki_types::CertificateDer<'_>],
    authority: &dhttp::LocalAuthority,
) -> Result<(), Whatever> {
    if authority.name() != text(metadata, "author")?
        || certificates != authority.certificates()
        || owner_hash(certificates)? != owner_hash(authority.certificates())?
    {
        whatever!(
            "package signer differs from current author credentials; run jade build again with the current credentials"
        );
    }
    Ok(())
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
    if release.get("kind").is_some() {
        whatever!("store must return unified Pkg metadata");
    }
    for key in ["id", "author", "name", "version"] {
        if release[key] != metadata[key] {
            whatever!("store release {key} differs from signed package");
        }
    }
    if release["author_owner_hash"] != owner {
        whatever!("store release author owner_hash mismatch");
    }
    let path = format!("{}/package.waz", version_path(metadata)?);
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
    let saved_metadata = inspect_package(saved)
        .await
        .map_err(|e| Whatever::without_source(e.to_string()))?;
    for key in ["id", "author", "name", "version"] {
        if saved_metadata[key] != metadata[key] {
            whatever!("saved package identity differs from upload");
        }
    }
    if signature_envelope(saved)?["certificates"] != release["signer_certificates"]
        || owner_hash(&package_certificates(saved)?)? != owner
    {
        whatever!("saved signer differs from trusted store proof or author owner_hash");
    }
    if payload_digest(saved)? != payload_digest(bytes)? {
        whatever!("this version already has different content; increase the package version");
    }
    Ok(())
}

fn success(release: &Value, outcome: &str, payload: &str) -> Value {
    json!({"outcome":outcome,"id":release["id"],"version":release["version"],
        "package_sha256":release["package_sha256"],"payload_sha256":payload})
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
    Ok(success(&release, "published", &payload_digest(bytes)?))
}

async fn publish(
    endpoint: &dhttp::Endpoint,
    bytes: &[u8],
    metadata: &Value,
    owner: &str,
) -> crate::error::Result<Value> {
    use crate::error::Error;
    let catalogue = get(endpoint, "/store/v1/packages?page_size=1", false)
        .await
        .map_err(|e| Error::new("E_PUBLISH_REJECTED", e))?;
    check_catalogue(&catalogue).map_err(|e| {
        Error::new("E_PUBLISH_REJECTED", e)
            .hint("Update the store to the author/.waz protocol before publishing")
    })?;
    let response = put(
        endpoint,
        &version_path(metadata).map_err(|e| Error::new("E_PACKAGE_INVALID", e))?,
        bytes,
    )
    .await;
    let uncertain = match response {
        Ok(response) if matches!(response.status(), StatusCode::OK | StatusCode::CREATED) => {
            let confirmed = async {
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
                Ok::<_, Whatever>(success(
                    &release,
                    if response.status() == StatusCode::CREATED {
                        "published"
                    } else {
                        "already-published"
                    },
                    &payload_digest(bytes)?,
                ))
            }
            .await;
            match confirmed {
                Ok(value) => return Ok(value),
                Err(error) => error,
            }
        }
        Ok(response) if !response.status().is_server_error() => {
            let code = if response.status() == StatusCode::CONFLICT {
                "E_VERSION_CONFLICT"
            } else {
                "E_PUBLISH_REJECTED"
            };
            return Err(Error::new(code, http_failure(&response)));
        }
        Ok(response) => http_failure(&response),
        Err(error) => error,
    };
    eprintln!("Upload result uncertain ({uncertain}); checking the exact saved version once");
    reconcile(endpoint, bytes, metadata, owner)
        .await
        .map_err(|e| {
            Error::new(
                "E_PUBLISH_OUTCOME_UNKNOWN",
                format!("Read-only verification did not confirm publication: {e}"),
            )
            .hint("Retry publishing the same package file later")
        })
}

fn check_catalogue(response: &http::Response<Vec<u8>>) -> Result<(), Whatever> {
    if response.status() != StatusCode::OK {
        return Err(http_failure(response));
    }
    let value: Value =
        serde_json::from_slice(response.body()).whatever_context("invalid store catalogue JSON")?;
    let packages = value["packages"]
        .as_array()
        .whatever_context("missing store catalogue packages")?;
    if value["total"].as_u64().is_none()
        || (value["total"].as_u64().unwrap_or(0) > 0 && packages.is_empty())
    {
        whatever!("invalid store catalogue pagination");
    }
    for package in packages {
        if package.get("publisher").is_some()
            || package.get("publisher_owner_hash").is_some()
            || package["author"].as_str().is_none_or(str::is_empty)
            || package["author_owner_hash"]
                .as_str()
                .is_none_or(str::is_empty)
            || !package["download_path"]
                .as_str()
                .is_some_and(|p| p.ends_with("/package.waz"))
        {
            whatever!("store still uses an incompatible package protocol; no upload was sent");
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "upload_tests.rs"]
mod tests;
