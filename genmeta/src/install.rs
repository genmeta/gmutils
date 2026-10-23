//! Resolve a release from the pinned store; the running Pishoo owns installation.
use std::{collections::BTreeSet, future::Future, time::Duration};

use dhttp_home::{DhttpHome, HomeScope, certificate::OwnerHash, identity::IdentityProfile};
use http::{Response, StatusCode, Uri, header};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use snafu::{ResultExt, Whatever, ensure_whatever, whatever};
use tokio::io::AsyncWriteExt;

use crate::display;

const STORE: &str = "store.dhttp.net";
const STORE_OWNER: &str = "ffc3e50e1dfb7baca1cc07a7cbfcf8cb34a9bf5a9c25024fcf9a9786bb230746";
const JSON_LIMIT: usize = 2 * 1024 * 1024;
const RESOLUTION_BYTES: usize = 20 * 1024 * 1024;
const CANDIDATE_LIMIT: u64 = 10_000;
const PAGE_SIZE: u64 = 100;
const RESOLUTION_TIMEOUT: Duration = Duration::from_secs(120);
const INSTALL_TIMEOUT: Duration = Duration::from_secs(15 * 60);
const UNKNOWN: &str = "Installation outcome is unknown; the server may still be installing. Check the catalog and server logs before explicitly retrying. The request will not be retried automatically.";
const PARTIAL: &str = "Dependencies already installed successfully are retained; installation is not a transaction across packages.";
const SERVICE: &str = "Start or enable the correct Pishoo service for the selected identity, and check the installation route and access permissions.";

fn valid_name(name: &str) -> bool {
    name.len() <= 63
        && name.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn valid_target(target: &str) -> bool {
    match target.split_once('/') {
        Some((publisher, name)) => {
            dhttp_home::normalize_name(publisher).as_deref() == Some(publisher) && valid_name(name)
        }
        None => valid_name(target),
    }
}

fn normalize_target(target: &str, standard_bare: bool) -> String {
    if let Some((publisher, name)) = target.split_once('/') {
        if let Some(publisher) = dhttp_home::normalize_name(publisher) {
            return format!("{publisher}/{name}");
        }
    } else if standard_bare && valid_name(target) {
        return format!("std.dhttp.net/{target}");
    }
    target.to_owned()
}

fn valid_version(version: &str) -> bool {
    let parts: Vec<_> = version.split('.').collect();
    parts.len() == 3
        && parts.iter().all(|part| {
            !part.is_empty()
                && (part.len() == 1 || !part.starts_with('0'))
                && part.bytes().all(|b| b.is_ascii_digit())
                && part.parse::<u64>().is_ok()
        })
}

fn valid_hash(value: &Value) -> bool {
    value.as_str().is_some_and(|s| {
        s.len() == 64
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

fn validate_input(target: &str, version: Option<&str>) -> Result<(), Whatever> {
    ensure_whatever!(
        valid_target(target),
        "TARGET must be a valid short name or canonical publisher/name; local paths, .pkg files, URLs, and name@version are not supported"
    );
    ensure_whatever!(
        version.is_none_or(valid_version),
        "Version must be MAJOR.MINOR.PATCH without leading zeros"
    );
    Ok(())
}

fn validate_release(
    value: &Value,
    expected: Option<&str>,
    version: Option<&str>,
) -> Result<(), Whatever> {
    let id = value["id"].as_str().unwrap_or("");
    let publisher = value["publisher"].as_str().unwrap_or("");
    let name = value["name"].as_str().unwrap_or("");
    let release = value["version"].as_str().unwrap_or("");
    let collection = "packages";
    ensure_whatever!(
        value.get("kind").is_none()
            && id.contains('/')
            && valid_target(id)
            && id == format!("{publisher}/{name}")
            && expected.is_none_or(|expected| id == expected)
            && valid_version(release)
            && version.is_none_or(|version| release == version),
        "Store package identity or version does not match; the store may not support the current package protocol"
    );
    ensure_whatever!(
        value["status"] == "published",
        "Store release has been withdrawn or is not published: {} {release}",
        display::package_id(id)
    );
    ensure_whatever!(
        value["size"]
            .as_u64()
            .is_some_and(|s| s > 0 && s <= 64 * 1024 * 1024)
            && valid_hash(&value["package_sha256"])
            && valid_hash(&value["publisher_owner_hash"])
            && value["download_path"]
                == format!("/store/v1/{collection}/{id}/versions/{release}/package.pkg"),
        "Invalid store package size, digest, publisher owner hash, or download path"
    );
    Ok(())
}

fn validate_detail(value: &Value) -> Result<(), Whatever> {
    ensure_whatever!(
        ["kind", "openapi", "host", "entry", "has_lib", "has_app"]
            .iter()
            .all(|key| value.get(*key).is_none()),
        "Store details must contain package metadata only"
    );
    // No fallback to the old OpenAPI package metadata contract.
    ensure_whatever!(
        ["title", "description", "changelog"]
            .iter()
            .all(|key| value[*key]
                .as_str()
                .is_some_and(|text| !text.trim().is_empty()))
            && value["dependencies"]
                .as_array()
                .is_some_and(|items| items.len() <= 100),
        "Store details do not support the current manifest metadata protocol"
    );
    Ok(())
}

async fn resolve<F, Fut>(target: &str, version: Option<&str>, mut get: F) -> Result<Value, Whatever>
where
    F: FnMut(String) -> Fut,
    Fut: Future<Output = Result<Vec<u8>, Whatever>>,
{
    validate_input(target, version)?;
    let collection = "packages";
    let mut remaining = RESOLUTION_BYTES;
    let id = if target.contains('/') {
        target.to_owned()
    } else {
        let mut matches = BTreeSet::new();
        let mut seen = BTreeSet::new();
        let mut expected_total = None;
        let mut page = 1;
        loop {
            let bytes = get(format!(
                "/store/v1/{collection}?q={target}&page={page}&page_size={PAGE_SIZE}"
            ))
            .await
            .whatever_context("Store resolution incomplete: catalog page request failed")?;
            let value = decode_resolution(&bytes, &mut remaining)?;
            let total = value["total"].as_u64();
            ensure_whatever!(
                value["page"].as_u64() == Some(page)
                    && value["page_size"].as_u64() == Some(PAGE_SIZE)
                    && total.is_some(),
                "Store resolution incomplete: invalid pagination"
            );
            let total = total.unwrap();
            ensure_whatever!(
                total <= CANDIDATE_LIMIT,
                "Store resolution incomplete: candidate budget exceeded"
            );
            ensure_whatever!(
                expected_total.is_none_or(|previous| previous == total),
                "Store resolution incomplete: catalog total changed during the query"
            );
            expected_total = Some(total);
            let Some(items) = value[collection].as_array() else {
                whatever!("Store resolution incomplete: missing catalog entries");
            };
            let offset = (page - 1) * PAGE_SIZE;
            ensure_whatever!(
                offset <= total && items.len() as u64 == (total - offset).min(PAGE_SIZE),
                "Store resolution incomplete: inconsistent page length"
            );
            for item in items {
                validate_release(item, None, None)
                    .whatever_context("Store resolution incomplete: invalid catalog entry")?;
                let id = item["id"].as_str().unwrap();
                // The real catalog returns one latest release per full ID. An overlap
                // means a moving catalog may have skipped unseen entries.
                ensure_whatever!(
                    seen.insert(id.to_owned()),
                    "Store resolution incomplete: overlapping catalog entries indicate inconsistent pagination"
                );
                if item["name"] == target {
                    matches.insert(id.to_owned());
                }
            }
            if offset + items.len() as u64 == total {
                break;
            }
            page += 1;
        }
        ensure_whatever!(
            !matches.is_empty(),
            "No published package named {target} was found in the store"
        );
        ensure_whatever!(
            matches.len() == 1,
            "Ambiguous package name; specify one of these full IDs: {}",
            matches
                .iter()
                .map(|id| display::package_id(id))
                .collect::<Vec<_>>()
                .join(", ")
        );
        matches.into_iter().next().unwrap()
    };
    let path = format!(
        "/store/v1/{collection}/{id}{}",
        version
            .map(|v| format!("/versions/{v}"))
            .unwrap_or_default()
    );
    let bytes = get(path).await?;
    let value = decode_resolution(&bytes, &mut remaining)?;
    validate_release(&value, Some(&id), version)?;
    validate_detail(&value)?;
    Ok(value)
}

async fn resolve_with_deadline<F, Fut>(
    target: &str,
    version: Option<&str>,
    get: F,
) -> Result<Value, Whatever>
where
    F: FnMut(String) -> Fut,
    Fut: Future<Output = Result<Vec<u8>, Whatever>>,
{
    tokio::time::timeout(RESOLUTION_TIMEOUT, resolve(target, version, get))
        .await
        .whatever_context("Store resolution incomplete: the 120-second deadline was exceeded")?
}

fn decode_resolution(bytes: &[u8], remaining: &mut usize) -> Result<Value, Whatever> {
    ensure_whatever!(
        bytes.len() <= JSON_LIMIT && bytes.len() <= *remaining,
        "Store resolution incomplete: response byte budget exceeded"
    );
    *remaining -= bytes.len();
    serde_json::from_slice(bytes).whatever_context("Store resolution incomplete: invalid JSON")
}

fn uri(name: &str, path: &str) -> Result<Uri, Whatever> {
    Uri::builder()
        .scheme("https")
        .authority(name)
        .path_and_query(path)
        .build()
        .whatever_context("Failed to construct request URI")
}

fn verify_remote(
    response: &Response<dhttp::Body>,
    name: &str,
    owner: &OwnerHash,
) -> Result<(), Whatever> {
    let Some(remote) = response.extensions().get::<dhttp::RemoteAuthority>() else {
        whatever!("Response has no authenticated remote authority");
    };
    verify_peer(remote.name(), remote.certificates(), name, owner)
}

fn verify_peer(
    remote_name: &str,
    certificates: &[dhttp::CertificateDer<'static>],
    name: &str,
    owner: &OwnerHash,
) -> Result<(), Whatever> {
    let ski = dhttp_home::certificate::extract_dhttp_subject_key_identifier(certificates)
        .whatever_context("Failed to read the remote owner hash")?;
    ensure_whatever!(
        remote_name == name && ski.owner_hash() == owner,
        "Remote service name or owner hash does not match the expected identity"
    );
    Ok(())
}

fn require_json(response: &Response<dhttp::Body>) -> Result<(), Whatever> {
    ensure_whatever!(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(';').next())
            .is_some_and(|v| v.trim().eq_ignore_ascii_case("application/json")),
        "Response content type must be application/json"
    );
    Ok(())
}

async fn read_body(response: Response<dhttp::Body>) -> Result<Vec<u8>, Whatever> {
    let mut body = response.into_body();
    let mut bytes = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.whatever_context("Response body was interrupted")?;
        if let Ok(data) = frame.into_data() {
            ensure_whatever!(
                data.len() <= JSON_LIMIT.saturating_sub(bytes.len()),
                "Response exceeds the 2 MiB limit"
            );
            bytes.extend_from_slice(&data);
        } else {
            whatever!("Response trailers are not supported");
        }
    }
    Ok(bytes)
}

async fn store_get(endpoint: &dhttp::Endpoint, path: &str) -> Result<Vec<u8>, Whatever> {
    let owner =
        OwnerHash::try_from(STORE_OWNER).whatever_context("Invalid pinned store owner hash")?;
    let response = endpoint
        .get(uri(STORE, path)?)
        .expect_remote_owner_hash(owner.clone())
        .header(
            header::ACCEPT,
            http::HeaderValue::from_static("application/json"),
        )
        .await
        .whatever_context("Failed to connect to the trusted store")?;
    verify_remote(&response, STORE, &owner)?;
    match response.status() {
        StatusCode::OK => {
            require_json(&response)?;
            read_body(response).await
        }
        StatusCode::NOT_FOUND => whatever!(
            "Store package or version was not found, or no published release is available"
        ),
        StatusCode::GONE => whatever!("The requested store version has been withdrawn"),
        status => whatever!("Store request failed (HTTP {status}); redirects are not followed"),
    }
}

async fn identity(home: &DhttpHome, id: Option<String>) -> Result<IdentityProfile, Whatever> {
    match id {
        Some(name) => {
            let name: dhttp_identity::name::DhttpName<'static> = name.parse()
                .whatever_context("Invalid identity name; configure an identity or use --id")?;
            home.resolve_identity_profile(name.as_full()).await
                .whatever_context("Selected identity does not exist; configure an identity or use --id")
        }
        None => home.resolve_default_identity_profile().await
            .whatever_context("No default identity is available; configure one with genmeta identity default <name>, or use --id"),
    }
}

async fn init_network() -> Result<(), Whatever> {
    let mdns = ddns::install_resolvers(&[ddns::DnsScheme::Mdns, ddns::DnsScheme::H3])
        .whatever_context("Failed to initialize DNS resolvers")?;
    let network = dhttp::DhttpNetwork::init()
        .await
        .whatever_context("Failed to initialize the DHTTP network")?;
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
        .whatever_context("Failed to initialize local identity resolution")?;
    }
    Ok(())
}

fn install_body(release: &Value) -> Value {
    json!({"author":release["publisher"],"name":release["name"],"version":release["version"]})
}

fn success(result: &Value, release: &Value, identity: &str) -> Result<Value, Whatever> {
    ensure_whatever!(
        ["id", "version"]
            .iter()
            .all(|key| result[*key] == release[*key]),
        "Installation response id/version does not match the selected package. {UNKNOWN}"
    );
    let mut output =
        json!({"id": result["id"], "version": result["version"], "identity": identity});
    if result["has_app"] == true {
        ensure_whatever!(
            result["entry"] == "/",
            "App installation response has no valid saved entry. {UNKNOWN}"
        );
        output["entry_url"] = json!(format!(
            "https://{identity}/app/{}/",
            release["name"].as_str().unwrap()
        ));
    }
    Ok(output)
}

fn install_status(status: StatusCode, bytes: &[u8]) -> Result<(), Whatever> {
    match status {
        StatusCode::OK => Ok(()),
        StatusCode::ACCEPTED => whatever!(
            "Service returned an approval response; installation has not completed (HTTP 202): {}",
            String::from_utf8_lossy(bytes)
        ),
        StatusCode::NOT_FOUND | StatusCode::SERVICE_UNAVAILABLE => whatever!(
            "Installation service unavailable (HTTP {status}): {}. {SERVICE}",
            String::from_utf8_lossy(bytes)
        ),
        StatusCode::REQUEST_TIMEOUT | StatusCode::GATEWAY_TIMEOUT => whatever!(
            "Service returned HTTP {status}: {}. {UNKNOWN} {PARTIAL}",
            String::from_utf8_lossy(bytes)
        ),
        _ => whatever!(
            "Installation failed (HTTP {status}): {}. {PARTIAL}",
            String::from_utf8_lossy(bytes)
        ),
    }
}

async fn install(
    endpoint: &dhttp::Endpoint,
    owner: &OwnerHash,
    release: &Value,
) -> Result<Value, Whatever> {
    let bytes = serde_json::to_vec(&install_body(release))
        .whatever_context("Failed to encode installation JSON")?;
    let (mut writer, receive) = endpoint
        .post(uri(endpoint.name(), "/std/sys/pkg/install")?)
        .expect_remote_owner_hash(owner.clone())
        .header(
            header::ACCEPT,
            http::HeaderValue::from_static("application/json"),
        )
        .header(
            header::CONTENT_TYPE,
            http::HeaderValue::from_static("application/json"),
        )
        .await
        .whatever_context(format!(
            "Failed to connect to the selected identity service. {SERVICE}"
        ))?;
    let upload = async {
        writer.write_all(&bytes).await.map_err(dhttp::Error::from)?;
        writer.shutdown().await.map_err(dhttp::Error::from)
    };
    let (_, response) =
        tokio::try_join!(upload, receive).whatever_context(format!("{UNKNOWN} {PARTIAL}"))?;
    verify_remote(&response, endpoint.name(), owner).whatever_context(UNKNOWN)?;
    let status = response.status();
    if status == StatusCode::OK {
        require_json(&response).whatever_context(UNKNOWN)?;
    }
    let bytes = read_body(response)
        .await
        .whatever_context(format!("{UNKNOWN} {PARTIAL}"))?;
    install_status(status, &bytes)?;
    let value = serde_json::from_slice(&bytes).whatever_context(UNKNOWN)?;
    success(&value, release, endpoint.name())
}

async fn wait_for_install(
    request: impl Future<Output = Result<Value, Whatever>>,
) -> Result<Value, Whatever> {
    tokio::select! {
        result = tokio::time::timeout(INSTALL_TIMEOUT, request) =>
            result.whatever_context(format!("{UNKNOWN} {PARTIAL} The 15-minute deadline was exceeded; timing out does not guarantee cancellation on the server. {SERVICE}"))?,
        signal = tokio::signal::ctrl_c() => {
            signal.whatever_context("Failed to listen for interruption")?;
            whatever!("Installation interrupted. {UNKNOWN} {PARTIAL}");
        }
    }
}

// Catalog and mutation requests always authenticate the selected identity service.
async fn catalog(
    endpoint: &dhttp::Endpoint,
    owner: &OwnerHash,
    target: Option<&str>,
    require_removal_support: bool,
) -> Result<Option<Value>, Whatever> {
    let path = match target {
        Some(target) => format!("/std/sys/pkg?name={}", target.rsplit('/').next().unwrap()),
        None => "/std/sys/pkg/list".to_owned(),
    };
    tokio::time::timeout(RESOLUTION_TIMEOUT, async {
        let response = endpoint.get(uri(endpoint.name(), &path)?)
            .expect_remote_owner_hash(owner.clone())
            .header(header::ACCEPT, http::HeaderValue::from_static("application/json"))
            .await.whatever_context(format!("Cannot query the selected identity service. {SERVICE}"))?;
        verify_remote(&response, endpoint.name(), owner)?;
        let status = response.status();
        let package_id = response.headers().get("package-id").cloned();
        if status == StatusCode::NOT_FOUND && target.is_some() {
            return Ok(None);
        }
        ensure_whatever!(status == StatusCode::OK,
            "Package query failed (HTTP {status}); no package was changed");
        require_json(&response)?;
        let bytes = read_body(response).await?;
        let value: Value = serde_json::from_slice(&bytes)
            .whatever_context("Invalid installed package catalog")?;
        if let Some(target) = target {
            validate_installed(&value, Some(target))?;
            if require_removal_support {
                ensure_whatever!(package_id.as_ref().and_then(|header| header.to_str().ok()) == value["id"].as_str(),
                    "The service does not support identity-checked removal; update Pishoo before removing this package");
            }
        } else {
            let Some(items) = value.as_array() else {
                whatever!("Installed package catalog must be an array");
            };
            for item in items {
                validate_installed(item, None)?;
            }
        }
        Ok(Some(value))
    }).await.whatever_context("Package query timed out; no package was changed")?
}

fn validate_installed(value: &Value, target: Option<&str>) -> Result<(), Whatever> {
    let id = value["id"].as_str().unwrap_or("");
    ensure_whatever!(
        valid_target(id) && value["version"].as_str().is_some_and(valid_version),
        "Invalid installed package identity, type or version"
    );
    if let Some(target) = target {
        ensure_whatever!(
            if target.contains('/') {
                id == target
            } else {
                id.rsplit('/').next() == Some(target)
            },
            "Installed package is {}, not {}; specify its full ID explicitly",
            display::package_id(id),
            display::package_id(target)
        );
    }
    Ok(())
}

async fn remove(
    endpoint: &dhttp::Endpoint,
    owner: &OwnerHash,
    package: &Value,
) -> Result<Value, Whatever> {
    let id = package["id"].as_str().unwrap();
    let path = format!("/std/sys/pkg?name={}", id.rsplit('/').next().unwrap());
    // The host checks the full identity again; a replacement publisher must
    // never be deleted just because it occupies the same short name.
    let condition =
        http::HeaderValue::from_str(id).whatever_context("Invalid package removal precondition")?;
    let response = endpoint
        .delete(uri(endpoint.name(), &path)?)
        .expect_remote_owner_hash(owner.clone())
        .header("expected-package-id".parse().unwrap(), condition)
        .await
        .whatever_context(
            "Removal outcome is unknown; query the installed catalog before retrying",
        )?;
    verify_remote(&response, endpoint.name(), owner)?;
    let status = response.status();
    let bytes = read_body(response).await?;
    ensure_whatever!(
        status == StatusCode::NO_CONTENT,
        "Package removal failed (HTTP {status}): {}",
        String::from_utf8_lossy(&bytes)
    );
    Ok(json!({"id":id,"identity":endpoint.name(),"removed":true,"data_retained":true}))
}

fn choose_release_target<'a>(
    operation: &str,
    target: &'a str,
    current: Option<&'a Value>,
) -> Result<&'a str, Whatever> {
    if operation == "update" {
        let Some(current) = current else {
            whatever!(
                "Package {} is not installed; use genmeta install",
                display::package_id(target)
            );
        };
        let id = current["id"].as_str().unwrap();
        ensure_whatever!(
            id.contains('/'),
            "Legacy package {} has no publisher; remove it explicitly before installing a published package",
            display::package_id(id)
        );
        Ok(id)
    } else {
        Ok(target)
    }
}

fn check_install_version(
    operation: &str,
    current: Option<&Value>,
    release: &Value,
) -> Result<bool, Whatever> {
    let Some(current) = current else {
        return Ok(false);
    };
    ensure_whatever!(
        current["id"] == release["id"],
        "Name is already installed as {}; remove it explicitly before installing {}",
        display::package_id(current["id"].as_str().unwrap()),
        display::package_id(release["id"].as_str().unwrap())
    );
    if current["version"] == release["version"] {
        return Ok(true);
    }
    ensure_whatever!(
        operation == "update",
        "Package {} is already installed at {}; use genmeta update to change its version",
        display::package_id(current["id"].as_str().unwrap()),
        current["version"]
    );
    Ok(false)
}

pub(super) async fn run(
    operation: &str,
    target: Option<String>,
    id: Option<String>,
    version: Option<String>,
) -> Result<(), Whatever> {
    let target = target.map(|target| normalize_target(&target, operation == "install"));
    if let Some(target) = &target {
        validate_input(target, version.as_deref())?;
    }
    let home = DhttpHome::load(HomeScope::User)
        .whatever_context("Failed to load the identity home; configure an identity or use --id")?;
    let profile = identity(&home, id).await?;
    init_network().await?;
    let endpoint = dhttp::Endpoint::load_from_with_ocsp(profile.path()).await
        .whatever_context("Selected identity credentials are incomplete or invalid; configure an identity or use --id")?;
    let authority = endpoint
        .local_authority()
        .whatever_context("Failed to read local identity credentials")?;
    let ski =
        dhttp_home::certificate::extract_dhttp_subject_key_identifier(authority.certificates())
            .whatever_context("Local credentials have no valid owner hash")?;
    let owner = ski.owner_hash().clone();
    if operation == "list" {
        let packages =
            display::package_output(catalog(&endpoint, &owner, None, false).await?.unwrap());
        println!(
            "{}",
            serde_json::to_string_pretty(&packages).whatever_context("Cannot encode catalog")?
        );
        return Ok(());
    }
    let target = target.as_deref().unwrap();
    let current = catalog(&endpoint, &owner, Some(target), operation == "remove").await?;
    if matches!(operation, "info" | "remove") {
        let Some(current) = current else {
            whatever!("Package {} is not installed", display::package_id(target))
        };
        let output = if operation == "remove" {
            tokio::time::timeout(RESOLUTION_TIMEOUT, remove(&endpoint, &owner, &current))
                .await
                .whatever_context("Removal timed out; query the catalog before retrying")??
        } else {
            current
        };
        println!(
            "{}",
            serde_json::to_string_pretty(&display::package_output(output))
                .whatever_context("Cannot encode package result")?
        );
        return Ok(());
    }
    let selected = choose_release_target(operation, target, current.as_ref())?;
    eprintln!(
        "Resolving package {} from the store for identity {}",
        display::package_id(selected),
        display::identity(endpoint.name())
    );
    let release = resolve_with_deadline(selected, version.as_deref(), |path| {
        let endpoint = &endpoint;
        async move { store_get(endpoint, &path).await }
    })
    .await?;
    let output = if check_install_version(operation, current.as_ref(), &release)? {
        let mut output = success(current.as_ref().unwrap(), &release, endpoint.name())?;
        output["unchanged"] = true.into();
        output
    } else {
        eprintln!(
            "{} package {} {} for identity {}",
            if operation == "update" {
                "Updating"
            } else {
                "Installing"
            },
            display::package_id(release["id"].as_str().unwrap()),
            release["version"].as_str().unwrap(),
            display::identity(endpoint.name())
        );
        wait_for_install(install(&endpoint, &owner, &release)).await?
    };
    println!(
        "{}",
        serde_json::to_string(&display::package_output(output))
            .whatever_context("Failed to encode success output")?
    );
    Ok(())
}

// These commands use the host's existing authorization and validation boundaries.
pub(super) async fn host_request(
    id: Option<String>,
    method: http::Method,
    path: &str,
    body: Vec<u8>,
    content_type: &'static str,
) -> Result<Value, Whatever> {
    let home = DhttpHome::load(HomeScope::User).whatever_context("Cannot load identity home")?;
    let profile = identity(&home, id).await?;
    init_network().await?;
    let endpoint = dhttp::Endpoint::load_from_with_ocsp(profile.path())
        .await
        .whatever_context("Cannot load selected identity credentials")?;
    let authority = endpoint
        .local_authority()
        .whatever_context("Cannot read identity")?;
    let ski =
        dhttp_home::certificate::extract_dhttp_subject_key_identifier(authority.certificates())
            .whatever_context("Cannot read identity owner")?;
    let owner = ski.owner_hash().clone();
    host_exchange(&endpoint, &owner, method, path, body, content_type).await
}

async fn host_exchange(
    endpoint: &dhttp::Endpoint,
    owner: &OwnerHash,
    method: http::Method,
    path: &str,
    body: Vec<u8>,
    content_type: &'static str,
) -> Result<Value, Whatever> {
    tokio::time::timeout(INSTALL_TIMEOUT, async {
        let request = http::Request::builder()
            .method(method)
            .uri(uri(endpoint.name(), path)?)
            .header(header::CONTENT_TYPE, content_type)
            .header(header::ACCEPT, "application/json")
            .body(dhttp::WndBuf::new(64 * 1024))
            .whatever_context("Invalid host request")?;
        let (mut writer, response) = endpoint
            .from_request(request)
            .expect_remote_owner_hash(owner.clone())
            .await
            .whatever_context(format!(
                "Cannot connect to selected Pishoo service. {SERVICE}"
            ))?;
        let upload = async {
            writer.write_all(&body).await.map_err(dhttp::Error::from)?;
            writer.shutdown().await.map_err(dhttp::Error::from)
        };
        let (_, response) = tokio::try_join!(upload, response).whatever_context(
            "Request failed; a write outcome may be unknown. Inspect the service before retrying",
        )?;
        verify_remote(&response, endpoint.name(), owner)?;
        let status = response.status();
        let bytes = read_body(response).await?;
        ensure_whatever!(
            matches!(
                status,
                StatusCode::OK | StatusCode::CREATED | StatusCode::NO_CONTENT
            ),
            "Pishoo returned HTTP {status}: {}",
            String::from_utf8_lossy(&bytes)
        );
        if bytes.is_empty() {
            Ok(Value::Null)
        } else {
            serde_json::from_slice(&bytes).whatever_context("Invalid Pishoo JSON response")
        }
    })
    .await
    .whatever_context(
        "Request timed out; a write may still complete. Inspect the service before retrying",
    )?
}

#[cfg(test)]
#[path = "install/tests.rs"]
mod tests;
