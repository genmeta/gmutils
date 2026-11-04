//! Single-package publication; the trusted store validates uploaded releases.
use std::{collections::BTreeMap, path::PathBuf, time::Duration};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use dhttp_home::certificate::OwnerHash;
use http::{HeaderValue, StatusCode, Uri, header};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use snafu::{FromString, OptionExt, ResultExt, Whatever, whatever};
use tokio::io::AsyncWriteExt;
use tracing_indicatif::span_ext::IndicatifSpanExt;

use crate::package::{
    PACKAGE_LIMIT, digest, inspect_package, owner_hash, package_certificates, payload_digest,
    read_snapshot, signature_envelope, text, version_path,
};

const STORE_NAME: &str = match option_env!("PISHOO_REGISTRY_NAME") {
    Some(value) => value,
    None => "store.dhttp.net",
};
const STORE_OWNER: &str = match option_env!("PISHOO_REGISTRY_OWNER_HASH") {
    Some(value) => value,
    None => "ffc3e50e1dfb7baca1cc07a7cbfcf8cb34a9bf5a9c25024fcf9a9786bb230746",
};
// A detailed release may carry a base64-encoded 4 MiB issuer CRL.
const JSON_LIMIT: usize = 8 * 1024 * 1024;
const UPLOAD_TIMEOUT: Duration = Duration::from_secs(180);
const METADATA_TIMEOUT: Duration = Duration::from_secs(30);

pub(super) async fn run(
    file: PathBuf,
    id: Option<String>,
    email: Option<String>,
    signing_sequence: Option<u32>,
    machine: bool,
) -> crate::error::Result<Value> {
    use crate::error::Error;
    let id = id
        .as_deref()
        .map(crate::identity::developer_name)
        .transpose()?;
    let project = file.is_dir() || file.file_name().is_some_and(|name| name == "jade.toml");
    let interactive = !machine && std::io::IsTerminal::is_terminal(&std::io::stdin());
    let (bytes, metadata) = match read_input(&file).await {
        Ok(value) => value,
        Err(error) if error.code == "E_BUILD_REQUIRED" && project => {
            if interactive {
                let author = prepare_project_identity(
                    &file,
                    id.as_deref(),
                    email.as_deref(),
                    None,
                    signing_sequence,
                    true,
                )
                .await?;
                let name = author
                    .strip_suffix(dhttp_home::DHTTP_SUFFIX)
                    .unwrap_or(&author);
                return Err(error.hint(format!("Developer credentials are ready. Run jade build --id {name}, review the package, then run jade publish --id {name} again.")));
            }
            return Err(error.hint("For first-time developer setup, run jade publish --id NAME interactively. Then run jade build --id NAME, review the package, and run jade publish again. For a custom output, use jade publish FILE.waz."));
        }
        Err(error) => return Err(error),
    };
    let author = text(&metadata, "author").map_err(|e| Error::new("E_PACKAGE_INVALID", e))?;
    let home = crate::identity::home()?;
    if let Some(id) = &id
        && author != crate::identity::developer_name(id)?
    {
        return Err(Error::new(
            "E_IDENTITY_MISMATCH",
            "The package author differs from the selected development identity",
        ));
    }
    let profile = home.resolve_identity_profile_exactly(author).await;
    let credentials = profile
        .as_ref()
        .ok()
        .and_then(|profile| genmeta_identity::code_signing::load(profile, signing_sequence).ok());
    let credentials = match credentials {
        Some(credentials) => credentials,
        None if interactive => {
            prepare_project_identity(
                &file,
                id.as_deref(),
                email.as_deref(),
                Some(author),
                signing_sequence,
                true,
            )
            .await?;
            let profile = home
                .resolve_identity_profile_exactly(author)
                .await
                .map_err(|e| Error::new("E_IDENTITY_UNAVAILABLE", e))?;
            genmeta_identity::code_signing::load(&profile, signing_sequence)
                .map_err(|e| Error::new("E_DEVELOPER_CERTIFICATE_REQUIRED", e))?
        }
        None => return Err(Error::new(
            "E_DEVELOPER_CERTIFICATE_REQUIRED",
            "No usable developer upload credentials for this package author",
        )
        .hint(
            "Run jade publish interactively with this project or package to set up matching developer credentials, then retry publication.",
        )),
    };
    let local_certificates = credentials
        .chain()
        .map_err(|e| Error::new("E_IDENTITY_UNAVAILABLE", e))?;
    let files = crate::archive::waz_read(&bytes).map_err(|e| Error::new("E_PACKAGE_INVALID", e))?;
    let bytes = if files.contains_key("signature.json") {
        bytes
    } else {
        let key = credentials
            .key()
            .map_err(|e| Error::new("E_IDENTITY_UNAVAILABLE", e))?;
        let signing_key = qtls::default_provider()
            .key_provider
            .load_private_key(key)
            .map_err(|e| Error::new("E_IDENTITY_UNAVAILABLE", e))?;
        if !machine {
            eprintln!("{:>12} {}", "Signing", crate::display::identity(author));
        }
        let signed = sign_package(files, &local_certificates, &signing_key)
            .map_err(|e| Error::new("E_SIGNATURE_INVALID", e))?;
        inspect_package(&signed).await?;
        persist_signed_snapshot(&file, &bytes, &signed)?;
        signed
    };
    let certificates =
        package_certificates(&bytes).map_err(|e| Error::new("E_SIGNATURE_INVALID", e))?;
    if owner_hash(&local_certificates).map_err(|e| Error::new("E_IDENTITY_MISMATCH", e))?
        != owner_hash(&certificates).map_err(|e| Error::new("E_IDENTITY_MISMATCH", e))?
    {
        return Err(Error::new(
            "E_IDENTITY_MISMATCH",
            "Package signer owner differs from TLS uploader owner",
        )
        .hint("Use TLS upload credentials with the same author domain and owner_hash as the developer signer"));
    }
    let owner = owner_hash(&certificates).map_err(|e| Error::new("E_SIGNATURE_INVALID", e))?;
    let profile = home
        .resolve_identity_profile(author)
        .await
        .map_err(|e| Error::new("E_IDENTITY_UNAVAILABLE", e))?;
    genmeta_identity::code_signing::check_local_revocations(
        &certificates,
        &profile.path().join("trust/code-signing"),
    )
    .map_err(|e| Error::new("E_PUBLISH_REJECTED", e))?;
    let name = text(&metadata, "name").map_err(|e| Error::new("E_PACKAGE_INVALID", e))?;
    let version = text(&metadata, "version").map_err(|e| Error::new("E_PACKAGE_INVALID", e))?;
    let id = format!("{author}/{name}");
    if !machine {
        eprintln!(
            "{:>12} {} v{version} to {STORE_NAME}",
            "Uploading",
            crate::display::package_id(&id)
        );
    }
    let progress = tracing::info_span!("cli_progress", indicatif.pb_show = tracing::field::Empty);
    progress.pb_set_message(&format!(
        "Publishing {} v{version}...",
        crate::display::package_id(&id),
    ));
    progress.pb_start();
    tokio::time::timeout(METADATA_TIMEOUT, init_network())
        .await
        .map_err(|e| Error::new("E_PUBLISH_REJECTED", e))?
        .map_err(|e| Error::new("E_PUBLISH_REJECTED", e))?;
    // Signing and upload share the selected identity's normal SSL credentials and OCSP cache.
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
    // Certificate purpose, validity and WAZ signature were verified locally by inspect_package.
    // Paid entitlement is enforced only when the developer certificate is issued or renewed.
    let result = publish(&endpoint, &bytes, &metadata, &owner).await;
    drop(progress);
    result
}

async fn prepare_project_identity(
    input: &std::path::Path,
    requested_identity: Option<&str>,
    email: Option<&str>,
    signed_author: Option<&str>,
    sequence: Option<u32>,
    interactive: bool,
) -> crate::error::Result<String> {
    use crate::error::Error;
    let configured = if input.is_dir() || input.file_name().is_some_and(|name| name == "jade.toml")
    {
        let (_, config) = crate::project::read_manifest(input)?;
        config
            .package
            .author
            .as_deref()
            .map(crate::identity::normalize)
            .transpose()?
    } else {
        None
    };
    let author = signed_author.or(configured.as_deref());
    let target = match requested_identity.or(author) {
        Some(name) => crate::identity::developer_name(name)?,
        None => crate::identity::select(None, None).await?,
    };
    if author.is_some_and(|author| author != target) {
        return Err(Error::new("E_IDENTITY_MISMATCH", "The project author differs from the selected developer name")
            .hint(format!("Review the author migration and set package.author to {target} before building a new release.")));
    }
    let home = crate::identity::home()?;
    if let Ok(profile) = home.resolve_identity_profile_exactly(&target).await
        && genmeta_identity::code_signing::load(&profile, sequence)
            .and_then(|credentials| credentials.validate_transport(&target))
            .is_ok()
    {
        return Ok(target);
    }
    if sequence.is_some() {
        return Err(Error::new("E_DEVELOPER_CERTIFICATE_REQUIRED", "The explicitly selected developer sequence is unavailable")
            .hint("Renew or install that sequence in ssl, or omit --signing-sequence to provision a new credential."));
    }
    if !interactive {
        return Err(Error::new(
            "E_DEVELOPER_CERTIFICATE_REQUIRED",
            "Developer credentials must be prepared before noninteractive publication",
        )
        .hint(
            "Run jade publish --id NAME interactively for developer setup, then follow its build and publication hints.",
        ));
    }
    eprintln!(
        "A developer certificate is required for {}. We'll guide you through the application.",
        crate::display::identity(&target)
    );
    let server = genmeta_identity::cert_server::CertServer::new(genmeta_identity::DHTTP_CA_SERVICE)
        .map_err(|e| Error::new("E_DEVELOPER_SETUP", e))?;
    let result = genmeta_identity::cli::prepare_for_publish(&home, &server, &target, email, true)
        .await
        .map_err(|e| Error::new("E_DEVELOPER_SETUP", e))?;
    if result["domain"] != target {
        return Err(Error::new(
            "E_IDENTITY_MISMATCH",
            "The provisioned developer name differs from the requested author",
        ));
    }
    eprintln!(
        "{:>12} developer credentials for {}",
        "Ready",
        crate::display::identity(&target)
    );
    Ok(target)
}

fn sign_package(
    mut files: BTreeMap<String, Vec<u8>>,
    certificates: &[qtls::CertificateDer<'_>],
    signing_key: &std::sync::Arc<dyn rustls::sign::SigningKey>,
) -> std::result::Result<Vec<u8>, Box<dyn std::error::Error>> {
    let digest = crate::archive::waz_payload(&files);
    let mut input = b"pishoo-waz-signature-v1\0".to_vec();
    for offset in (0..digest.len()).step_by(2) {
        input.push(u8::from_str_radix(&digest[offset..offset + 2], 16)?);
    }
    let mut signature = None;
    for scheme in [
        qtls::SignatureScheme::RSA_PSS_SHA512,
        qtls::SignatureScheme::ECDSA_NISTP256_SHA256,
        qtls::SignatureScheme::ECDSA_NISTP384_SHA384,
        qtls::SignatureScheme::ED25519,
    ] {
        if let Some(signer) = signing_key.choose_scheme(&[scheme]) {
            signature = Some(signer.sign(&input)?);
            break;
        }
    }
    let envelope = json!({"version":1,
        "certificates":certificates.iter().map(|c|STANDARD.encode(c.as_ref())).collect::<Vec<_>>(),
        "signature":STANDARD.encode(signature.ok_or("unsupported signing key")?)});
    files.insert(
        "signature.json".into(),
        serde_json::to_vec_pretty(&envelope)?,
    );
    let bytes = crate::archive::waz_write(&files)
        .map_err(|error| -> Box<dyn std::error::Error> { error })?;
    if crate::package::payload_digest(&bytes)? != digest {
        return Err("final package content differs from signed payload".into());
    }
    Ok(bytes)
}

/// Resolve a project to its exact prebuilt release; source discovery and build
/// commands intentionally do not participate in publication.
async fn read_input(input: &std::path::Path) -> crate::error::Result<(Vec<u8>, Value)> {
    use crate::error::Error;
    crate::pack::reject_url(input.as_os_str()).map_err(|e| Error::new("E_CONFIG_INVALID", e))?;
    let project = if input.is_dir() || input.file_name().is_some_and(|name| name == "jade.toml") {
        let (root, config) = crate::project::read_manifest(input)?;
        let author = config
            .package
            .author
            .as_deref()
            .map(crate::identity::normalize)
            .transpose()?;
        let (metadata, annotation) =
            config.metadata(author.as_deref().unwrap_or("jade-validation.dhttp.net"))?;
        crate::pack::validate_metadata(&metadata, &annotation, false)
            .map_err(|e| Error::new("E_CONFIG_INVALID", e))?;
        let file = root.join(crate::project::BUILD_DIR).join(format!(
            "{}-{}.waz",
            config.package.name, config.package.version
        ));
        if !file.try_exists()? {
            return Err(Error::new("E_BUILD_REQUIRED", "The configured package version has not been built")
                .hint("Run jade build first, review the package, then run jade publish again. For a custom output, use jade publish FILE.waz.")
                .context(json!({"file":file,"name":config.package.name,"version":config.package.version})));
        }
        Some((file, config, author))
    } else {
        None
    };
    let file = project
        .as_ref()
        .map_or(input, |(file, _, _)| file.as_path());
    let bytes = read_snapshot(file)
        .await
        .map_err(|e| Error::new("E_PACKAGE_INVALID", e))?;
    let files = crate::archive::waz_read(&bytes).map_err(|e| Error::new("E_PACKAGE_INVALID", e))?;
    // A present signature must verify; never repair or re-sign a damaged release.
    let metadata = if files.contains_key("signature.json") {
        inspect_package(&bytes).await?
    } else {
        crate::package::inspect_contents(&bytes).await?
    };
    if let Some((_, config, author)) = project
        && (metadata["name"] != config.package.name
            || metadata["version"] != config.package.version
            || author.is_some_and(|author| metadata["author"] != author))
    {
        return Err(Error::new(
            "E_PACKAGE_MISMATCH",
            "The built package does not match jade.toml",
        )
        .hint("Run jade build for this project, or explicitly select the intended FILE.waz."));
    }
    Ok((bytes, metadata))
}

fn verify_author(
    metadata: &Value,
    certificates: &[rustls::pki_types::CertificateDer<'_>],
    authority: &dhttp::LocalAuthority,
) -> Result<(), Whatever> {
    if authority.name() != text(metadata, "author")?
        || owner_hash(certificates)? != owner_hash(authority.certificates())?
    {
        whatever!(
            "TLS uploader and developer signer must have the same canonical domain and owner_hash"
        );
    }
    Ok(())
}

fn store_uri(path: &str) -> Result<Uri, Whatever> {
    format!("https://{STORE_NAME}{path}")
        .parse()
        .whatever_context("invalid fixed store URI")
}

pub(crate) async fn init_network() -> Result<(), Whatever> {
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
                HeaderValue::from_static("application/zip"),
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
            "application/zip"
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
#[path = "../tests/unit/upload.rs"]
mod tests;

/// Commit signed bytes before any network publication. Retry the exact same WAZ.
fn persist_signed_snapshot(
    input: &std::path::Path,
    original: &[u8],
    bytes: &[u8],
) -> crate::error::Result<()> {
    let path = if input.is_dir() || input.file_name().is_some_and(|name| name == "jade.toml") {
        let (root, config) = crate::project::read_manifest(input)?;
        root.join(crate::project::BUILD_DIR).join(format!(
            "{}-{}.waz",
            config.package.name, config.package.version
        ))
    } else {
        input.to_path_buf()
    };
    if std::fs::read(&path)? != original {
        return Err(crate::error::Error::new(
            "E_PACKAGE_MISMATCH",
            "Package snapshot changed during signing; preserve both artifacts before retrying",
        ));
    }
    persist_signed_file(&path, bytes)
}

fn persist_signed_file(path: &std::path::Path, bytes: &[u8]) -> crate::error::Result<()> {
    use std::io::Write;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    if !path.symlink_metadata()?.file_type().is_file() {
        return Err(crate::error::Error::new(
            "E_PACKAGE_INVALID",
            "Package snapshot must be a regular file",
        ));
    }
    let mut staged = tempfile::NamedTempFile::new_in(parent)?;
    staged.write_all(bytes)?;
    staged.as_file().sync_all()?;
    staged
        .persist(path)
        .map_err(|e| crate::error::Error::new("E_PACKAGE_INVALID", e))?;
    #[cfg(unix)]
    std::fs::File::open(parent)?.sync_all()?;
    Ok(())
}
