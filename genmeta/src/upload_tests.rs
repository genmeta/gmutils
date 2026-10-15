use std::{collections::BTreeMap, sync::Arc};

use webc::v3::{
    SignatureAlgorithm, Timestamps,
    write::{Directory, FileEntry, Writer},
};

use super::*;

#[path = "../tests/support/upload_credentials.rs"]
mod credentials;

#[test]
fn upload_cli_accepts_only_the_designed_arguments() {
    use clap::Parser;
    for args in [
        vec!["genmeta", "package", "publish", "package.webc"],
        vec![
            "genmeta",
            "package",
            "publish",
            "package.webc",
            "-i",
            "alice",
        ],
        vec![
            "genmeta",
            "package",
            "publish",
            "package.webc",
            "--id",
            "alice.dhttp.net",
        ],
    ] {
        assert!(matches!(
            crate::Options::try_parse_from(args).unwrap(),
            crate::Options::Package {
                command: crate::PackageCommand::Publish { .. }
            }
        ));
    }
    assert!(crate::Options::try_parse_from(["genmeta", "package", "publish"]).is_err());
    for flag in [
        "--kind",
        "--name",
        "--version",
        "--store",
        "--source",
        "--force",
        "--home",
    ] {
        assert!(
            crate::Options::try_parse_from([
                "genmeta",
                "package",
                "publish",
                "package.webc",
                flag,
                "override"
            ])
            .is_err(),
            "{flag}"
        );
    }
    for (flag, kind) in [
        ("--help", clap::error::ErrorKind::DisplayHelp),
        ("--version", clap::error::ErrorKind::DisplayVersion),
    ] {
        assert_eq!(
            crate::Options::try_parse_from(["genmeta", "package", "publish", flag])
                .unwrap_err()
                .kind(),
            kind
        );
    }
}

fn metadata(kind: &str, name: &str, dependencies: Value) -> Value {
    let mut value = json!({"id":format!("alice.dhttp.net/{name}"),"publisher":"alice.dhttp.net","name":name,
        "version":"1.0.0","kind":kind,"title":"Upload test","description":"Test package","license":"MIT",
        "changelog":"Initial release; compatible data","dependencies":dependencies});
    if kind == "app" {
        value["entry"] = "/".into();
    } else {
        value["host"] = json!({});
    }
    value
}

fn build(metadata: &Value, authority: Option<&dhttp::LocalAuthority>, content: &str) -> Vec<u8> {
    let kind = metadata["kind"].as_str().unwrap();
    let mut annotation = metadata.clone();
    for key in [
        "id",
        "publisher",
        "name",
        "version",
        "description",
        "license",
        "repository",
    ] {
        annotation.as_object_mut().unwrap().remove(key);
    }
    let mut wapm = json!({"name":metadata["id"],"version":metadata["version"],"description":metadata["description"],"license":"MIT"});
    if let Some(repository) = metadata.get("repository") {
        wapm["repository"] = repository.clone();
    }
    let mut manifest: webc::metadata::Manifest = serde_json::from_value(json!({"package":{
        "wapm":wapm,
        "pishoo":annotation,"fs":[{"volume_name":if kind == "app" {"public"} else {"metadata"},
            "mount_path":if kind == "app" {"/public"} else {"/metadata"}}]}}))
    .unwrap();
    let (volume, filename, data) = if kind == "app" {
        ("public", "index.html", content.as_bytes().to_vec())
    } else {
        let backend = include_bytes!("../tests/fixtures/upload-handler.wasm");
        manifest.atoms =
            serde_json::from_value(json!({"backend":{"kind":"https://webc.org/kind/wasm",
            "signature":format!("sha256:{}",STANDARD.encode(Sha256::digest(backend)))}}))
            .unwrap();
        (
            "metadata",
            "openapi.json",
            serde_json::to_vec(&json!({"openapi":"3.1.0","info":{
            "title":"Upload API","description":content,"version":"1.0.0","license":{"name":"MIT"}},
            "x-pishoo":{"access-groups":{"read":{"title":"Read","operations":["readPage"]}}},
            "paths":{"/page":{"get":{"operationId":"readPage","summary":"Read page",
                "x-pishoo":{"access-group":"read"},"responses":{"200":{"description":"OK"}}}}}}))
            .unwrap(),
        )
    };
    let make = || {
        Writer::default()
            .write_manifest(&manifest)
            .unwrap()
            .write_atoms(if kind == "lib" {
                BTreeMap::from([(
                    "backend".parse().unwrap(),
                    FileEntry::borrowed(
                        include_bytes!("../tests/fixtures/upload-handler.wasm"),
                        Timestamps::default(),
                    ),
                )])
            } else {
                BTreeMap::new()
            })
            .unwrap()
            .with_volume(
                volume,
                Directory::new(
                    BTreeMap::from([(filename.parse().unwrap(), data.clone().into())]),
                    Timestamps::default(),
                ),
            )
            .unwrap()
    };
    let unsigned = make().finish(SignatureAlgorithm::None).unwrap().to_vec();
    let Some(authority) = authority else {
        return unsigned;
    };
    let payload = payload_digest(&unsigned).unwrap();
    let mut input = b"pishoo-webc-signature-v1\0".to_vec();
    for offset in (0..64).step_by(2) {
        input.push(u8::from_str_radix(&payload[offset..offset + 2], 16).unwrap());
    }
    let signature = authority
        .sign(qtls::SignatureScheme::ECDSA_NISTP256_SHA256, &input)
        .unwrap();
    let envelope = json!({"version":1,"certificates":authority.certificates().iter().map(|c|STANDARD.encode(c.as_ref())).collect::<Vec<_>>(),
        "signature":STANDARD.encode(signature)});
    let bytes = make()
        .with_volume(
            "pishoo-signature",
            Directory::new(
                BTreeMap::from([(
                    "signature.json".parse().unwrap(),
                    serde_json::to_vec(&envelope).unwrap().into(),
                )]),
                Timestamps::default(),
            ),
        )
        .unwrap()
        .finish(SignatureAlgorithm::None)
        .unwrap()
        .to_vec();
    assert_eq!(payload_digest(&bytes).unwrap(), payload);
    bytes
}

fn local(name: &str, owner: &str) -> dhttp::LocalAuthority {
    let mut params = rcgen::CertificateParams::new(vec![name.to_owned()]).unwrap();
    let ski = format!("0:0:{owner}");
    let mut der = vec![4, ski.len() as u8];
    der.extend_from_slice(ski.as_bytes());
    params
        .custom_extensions
        .push(rcgen::CustomExtension::from_oid_content(
            &[2, 5, 29, 14],
            der,
        ));
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    dhttp::LocalAuthority::new(
        &qtls::default_provider(),
        Arc::from(name),
        vec![cert.der().clone()],
        qtls::PrivateKeyDer::try_from(key.serialize_der()).unwrap(),
        vec![1],
    )
    .unwrap()
}

fn release(metadata: &Value, bytes: &[u8], owner: &str) -> Value {
    let mut value = metadata.clone();
    value["publisher_owner_hash"] = owner.into();
    value["package_sha256"] = digest(bytes).into();
    value["size"] = bytes.len().into();
    value["download_path"] = format!(
        "{}/{}.webc",
        version_path(metadata).unwrap(),
        metadata["kind"].as_str().unwrap()
    )
    .into();
    value["status"] = "published".into();
    if let Ok(envelope) = signature_envelope(bytes) {
        value["signer_certificates"] = envelope["certificates"].clone();
    }
    value
}

#[test]
fn paths_and_protocol_proofs_are_exact() {
    for kind in ["app", "lib"] {
        let metadata = metadata(kind, "note", json!([]));
        let bytes = build(&metadata, None, "test");
        let path = version_path(&metadata).unwrap();
        assert_eq!(
            path,
            format!("/store/v1/{kind}s/alice.dhttp.net/note/versions/1.0.0")
        );
        let proof = release(&metadata, &bytes, &"a".repeat(64));
        let response = http::Response::new(serde_json::to_vec(&proof).unwrap());
        assert!(release_metadata(&response, &metadata, &"a".repeat(64)).is_ok());
        for (key, invalid) in [
            ("id", json!("alice.dhttp.net/other")),
            ("kind", json!("bogus")),
            ("publisher", json!("bob.dhttp.net")),
            ("version", json!("2.0.0")),
            ("status", json!("pending")),
            ("status", json!("yanked")),
            ("size", json!(0)),
            ("size", json!(PACKAGE_LIMIT + 1)),
            ("package_sha256", json!("xyz")),
            ("publisher_owner_hash", json!("b".repeat(64))),
            ("download_path", json!("https://evil.example/package.webc")),
            ("download_path", json!(format!("{path}/../app.webc"))),
        ] {
            let mut bad = proof.clone();
            bad[key] = invalid;
            assert!(
                release_metadata(
                    &http::Response::new(serde_json::to_vec(&bad).unwrap()),
                    &metadata,
                    &"a".repeat(64)
                )
                .is_err(),
                "{key}"
            );
        }
    }
    for name in ["../bad", "a/b", "Bad", "a%2fb", "", "name?x", "name#x"] {
        assert!(version_path(&metadata("app", name, json!([]))).is_err());
    }
    for version in [
        "latest",
        "01.0.0",
        "1.0",
        "1.0.0-rc",
        "1.0.0+meta",
        "1.0.0/evil",
    ] {
        let mut value = metadata("app", "note", json!([]));
        value["version"] = version.into();
        assert!(version_path(&value).is_err());
    }
}

#[test]
fn parses_manifest_without_treating_it_as_verified_and_preserves_payload_identity() {
    let owner = "a".repeat(64);
    let alice = local("alice.dhttp.net", &owner);
    let rotated = local("alice.dhttp.net", &owner);
    for kind in ["app", "lib"] {
        let metadata = metadata(kind, "note", json!([]));
        let original = build(&metadata, Some(&alice), "test");
        let resigned = build(&metadata, Some(&rotated), "test");
        assert_eq!(manifest_identity(&original).unwrap()["id"], metadata["id"]);
        assert_ne!(digest(&original), digest(&resigned));
        assert_eq!(
            payload_digest(&original).unwrap(),
            payload_digest(&resigned).unwrap()
        );
        assert_ne!(
            payload_digest(&original).unwrap(),
            payload_digest(&build(&metadata, Some(&alice), "different")).unwrap()
        );
        let chain = package_certificates(&original).unwrap();
        assert!(verify_publisher(&metadata, &chain, &alice).is_ok());
        assert!(verify_publisher(&metadata, &chain, &rotated).is_err());
        let mut wrong = metadata.clone();
        wrong["publisher"] = "bob.dhttp.net".into();
        assert!(verify_publisher(&wrong, &chain, &alice).is_err());
    }
    for bytes in [vec![], b"not webc".to_vec(), b"\0webc003\x02".to_vec()] {
        assert!(manifest_identity(&bytes).is_err());
    }
}

#[tokio::test]
async fn snapshot_is_bounded_and_survives_original_replacement() {
    let directory = tempfile::tempdir().unwrap();
    assert!(read_snapshot(directory.path()).await.is_err());
    let path = directory.path().join("input.webc");
    std::fs::write(&path, b"original").unwrap();
    let snapshot = read_snapshot(&path).await.unwrap();
    std::fs::write(&path, b"changed").unwrap();
    assert_eq!(snapshot, b"original");
    let file = std::fs::File::create(&path).unwrap();
    file.set_len(PACKAGE_LIMIT as u64 + 1).unwrap();
    assert!(read_snapshot(&path).await.is_err());
    assert!(bounded_read(b"12345".as_slice(), 4, "test").await.is_err());
    #[cfg(unix)]
    {
        let link = directory.path().join("symlink");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(read_snapshot(&link).await.is_err());
        let fifo = directory.path().join("fifo");
        let output = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .output()
            .unwrap();
        assert!(output.status.success());
        assert!(
            tokio::time::timeout(Duration::from_secs(1), read_snapshot(&fifo))
                .await
                .unwrap()
                .is_err()
        );
    }
}

#[derive(Debug)]
struct PeerResolver(dhttp::resolve::EndpointAddr);
impl std::fmt::Display for PeerResolver {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("upload loopback test peer")
    }
}
impl dhttp::resolve::Resolve for PeerResolver {
    fn lookup<'a>(
        &'a self,
        name: &'a str,
        _: &'a str,
        _: Option<dhttp::resolve::Family>,
    ) -> dhttp::resolve::ResolveFuture<'a> {
        use futures::{FutureExt, StreamExt};
        async move {
            assert_eq!(name, STORE_NAME);
            Ok(futures::stream::iter([(dhttp::resolve::Source::System, self.0)]).boxed())
        }
        .boxed()
    }
}

async fn endpoint(root: &Path, directory: &str, name: &str) -> dhttp::Endpoint {
    let profile = dhttp_home::identity::IdentityProfile::try_from(root.join(directory)).unwrap();
    dhttp::Endpoint::new(
        qbase::endpoint::Endpoint::new(
            name,
            profile.load_certs().await.unwrap(),
            profile.load_key().await.unwrap(),
            profile.load_ocsp().await.unwrap(),
        )
        .unwrap(),
    )
}

fn body(bytes: Vec<u8>) -> dhttp::Body {
    http_body_util::Full::new(bytes::Bytes::from(bytes))
        .map_err(|never| match never {})
        .boxed_unsync()
}

fn response(status: StatusCode, value: Value) -> http::Response<dhttp::Body> {
    http::Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(body(serde_json::to_vec(&value).unwrap()))
        .unwrap()
}

#[tokio::test]
#[ignore = "requires a publisher Pishoo validation API, OpenSSL and local UDP socket permission"]
async fn real_http3_publish_retry_dependencies_and_read_only_recovery() {
    use std::sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    };

    use qprotocol::{Dock, UdpSocket};
    let root = tempfile::tempdir().unwrap();
    let owner = "a".repeat(64);
    credentials::generate(
        root.path(),
        &[
            ("store", STORE_NAME, STORE_OWNER),
            ("alice", "alice.dhttp.net", &owner),
            ("rotated", "alice.dhttp.net", &owner),
            ("wrong", "wrong.dhttp.net", &"b".repeat(64)),
        ],
    );
    let ca = std::fs::read(root.path().join("ca.crt")).unwrap();
    let peer = Arc::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
    Dock::global().add(peer.clone()).unwrap().unwrap();
    dhttp::DhttpNetwork::init().await.unwrap();
    qtls::RootCerts::set(
        rustls_pemfile::certs(&mut ca.as_slice())
            .collect::<Result<Vec<_>, _>>()
            .unwrap(),
    )
    .unwrap();
    dhttp::resolve::Resolver::add(Arc::new(PeerResolver(
        dhttp::resolve::EndpointAddr::direct(peer.local_addr().unwrap()),
    )));
    let store = endpoint(root.path(), "store", STORE_NAME).await;
    let client = endpoint(root.path(), "alice", "alice.dhttp.net").await;
    let rotated = endpoint(root.path(), "rotated", "alice.dhttp.net").await;
    let authority = client.local_authority().unwrap();
    let rotated_authority = rotated.local_authority().unwrap();
    let packages = Arc::new(Mutex::new(BTreeMap::<String, (Vec<u8>, Value)>::new()));
    let puts = Arc::new(AtomicUsize::new(0));
    let gets = Arc::new(AtomicUsize::new(0));
    let listening = store.listen(dhttp::Scope::Loopback.into(), tower::service_fn({
        let packages = packages.clone(); let puts = puts.clone(); let gets = gets.clone();
        let owner = owner.clone();
        move |request: http::Request<dhttp::Body>| {
            let packages = packages.clone(); let puts = puts.clone(); let gets = gets.clone(); let owner = owner.clone();
            async move {
                let path = request.uri().path().to_owned();
                let method = request.method().clone();
                let remote = request.extensions().get::<dhttp::HandshakeSummary>().unwrap().remote.clone().unwrap();
                assert_eq!(remote.name(), "alice.dhttp.net");
                if method == http::Method::GET {
                    gets.fetch_add(1, Ordering::SeqCst);
                    let download = path.ends_with(".webc");
                    let key = if download { path.rsplit_once('/').unwrap().0 } else { path.as_str() };
                    let saved = packages.lock().unwrap().get(key).cloned();
                    return Ok::<_, dhttp::BoxError>(match saved {
                        None => response(StatusCode::NOT_FOUND, json!({"error":"not_found"})),
                        Some((_, metadata)) if download && metadata["status"] == "yanked" => response(StatusCode::GONE, json!({"error":"yanked"})),
                        Some((bytes, _)) if download => http::Response::builder().header(header::CONTENT_TYPE, "application/webc").body(body(bytes)).unwrap(),
                        Some((_, metadata)) => response(StatusCode::OK, metadata),
                    });
                }
                assert_eq!(method, http::Method::PUT);
                puts.fetch_add(1, Ordering::SeqCst);
                assert_eq!(request.headers()[header::CONTENT_TYPE], "application/webc");
                let bytes = request.into_body().collect().await?.to_bytes().to_vec();
                let metadata = checked_package(&bytes).await?;
                assert_eq!(version_path(&metadata).unwrap(), path);
                assert_eq!(package_certificates(&bytes).unwrap(), remote.certificates());
                let payload = payload_digest(&bytes).unwrap();
                let proof = release(&metadata, &bytes, &owner);
                let mut saved = packages.lock().unwrap();
                if let Some((existing, proof)) = saved.get(&path) {
                    return Ok(if payload_digest(existing).unwrap() == payload {
                        response(StatusCode::OK, proof.clone())
                    } else { response(StatusCode::CONFLICT, json!({"error":"version_conflict","message":"different content"})) });
                }
                for dependency in metadata["dependencies"].as_array().unwrap() {
                    let key = format!("/store/v1/libs/{}/{}/versions/{}", dependency["publisher"].as_str().unwrap(),
                        dependency["name"].as_str().unwrap(), dependency["version"].as_str().unwrap());
                    if saved.get(&key).is_none_or(|(_, release)| release["status"] != "published") {
                        return Ok(response(StatusCode::UNPROCESSABLE_ENTITY, json!({"error":"dependency_unavailable",
                            "message":format!("Lib {}/{}@{} is missing or withdrawn", dependency["publisher"].as_str().unwrap(),
                                dependency["name"].as_str().unwrap(), dependency["version"].as_str().unwrap())})));
                    }
                }
                if metadata["name"] != "unsaved" { saved.insert(path.clone(), (bytes, proof.clone())); }
                if metadata["name"] == "lost" || metadata["name"] == "unsaved" {
                    return Ok(response(StatusCode::INTERNAL_SERVER_ERROR, json!({"error":"response_lost"})));
                }
                if metadata["name"] == "redirect" {
                    return Ok(http::Response::builder().status(StatusCode::TEMPORARY_REDIRECT)
                        .header(header::LOCATION, "https://evil.invalid/package").body(body(vec![])).unwrap());
                }
                if metadata["name"] == "trailer" {
                    let mut trailers = http::HeaderMap::new();
                    trailers.insert("x-upload-test", HeaderValue::from_static("trailer"));
                    let frames = futures::stream::iter([Ok::<_, dhttp::BoxError>(http_body::Frame::data(bytes::Bytes::from(serde_json::to_vec(&proof).unwrap()))),
                        Ok(http_body::Frame::trailers(trailers))]);
                    return Ok(http::Response::builder().status(StatusCode::CREATED).header(header::CONTENT_TYPE,"application/json")
                        .body(http_body_util::StreamBody::new(frames).boxed_unsync()).unwrap());
                }
                Ok(response(StatusCode::CREATED, proof))
            }
        }
    })).await.unwrap();
    let listening = tokio::spawn(listening);
    for kind in ["app", "lib"] {
        let metadata = metadata(kind, "note", json!([]));
        let bytes = build(&metadata, Some(&authority), "test");
        let checked = checked_package(&bytes).await.unwrap();
        verify_publisher(&checked, &package_certificates(&bytes).unwrap(), &authority).unwrap();
        assert_eq!(
            publish(&client, &bytes, &checked, &owner).await.unwrap()["result"],
            "published"
        );
        assert_eq!(
            publish(&client, &bytes, &checked, &owner).await.unwrap()["result"],
            "already-published"
        );
        let rotated_package = build(&metadata, Some(&rotated_authority), "test");
        assert!(
            verify_publisher(
                &checked,
                &package_certificates(&rotated_package).unwrap(),
                &authority
            )
            .is_err()
        );
        // A CLI run loads one publisher endpoint. Same-name endpoints share a
        // connection pool, so test resigning with its retained real credentials.
        let resigned = build(&metadata, Some(&authority), "test");
        assert_ne!(digest(&bytes), digest(&resigned));
        let before = gets.load(Ordering::SeqCst);
        assert_eq!(
            publish(&client, &resigned, &checked, &owner).await.unwrap()["result"],
            "already-published"
        );
        assert_eq!(
            gets.load(Ordering::SeqCst),
            before + 1,
            "resigning must download the retained original"
        );
        assert!(
            publish(
                &client,
                &build(&metadata, Some(&authority), "changed"),
                &checked,
                &owner
            )
            .await
            .unwrap_err()
            .to_string()
            .contains("409")
        );
        let unsigned = build(&metadata, None, "test");
        assert!(checked_package(&unsigned).await.is_err());
        let mut tampered = bytes.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(checked_package(&tampered).await.is_err());
    }
    let dependency = json!([{"publisher":"alice.dhttp.net","name":"backend","version":"1.0.0"}]);
    for kind in ["app", "lib"] {
        let metadata = metadata(kind, "parent", dependency.clone());
        let bytes = build(&metadata, Some(&authority), "parent");
        let error = publish(&client, &bytes, &metadata, &owner)
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("alice.dhttp.net/backend@1.0.0"), "{error}");
    }
    // A same-name App cannot satisfy a Lib dependency.
    let app = metadata("app", "backend", json!([]));
    publish(
        &client,
        &build(&app, Some(&authority), "frontend"),
        &app,
        &owner,
    )
    .await
    .unwrap();
    let parent = metadata("app", "parent", dependency.clone());
    assert!(
        publish(
            &client,
            &build(&parent, Some(&authority), "parent"),
            &parent,
            &owner
        )
        .await
        .is_err()
    );
    let lib = metadata("lib", "backend", json!([]));
    publish(
        &client,
        &build(&lib, Some(&authority), "backend"),
        &lib,
        &owner,
    )
    .await
    .unwrap();
    for kind in ["app", "lib"] {
        let parent = metadata(kind, "parent", dependency.clone());
        assert_eq!(
            publish(
                &client,
                &build(&parent, Some(&authority), "parent"),
                &parent,
                &owner
            )
            .await
            .unwrap()["result"],
            "published"
        );
    }
    packages
        .lock()
        .unwrap()
        .get_mut(&version_path(&lib).unwrap())
        .unwrap()
        .1["status"] = "yanked".into();
    let blocked = metadata("app", "blocked", dependency);
    assert!(
        publish(
            &client,
            &build(&blocked, Some(&authority), "parent"),
            &blocked,
            &owner
        )
        .await
        .is_err()
    );
    assert!(
        publish(
            &client,
            &build(&lib, Some(&authority), "backend"),
            &lib,
            &owner
        )
        .await
        .unwrap_err()
        .to_string()
        .contains("withdrawn")
    );
    for name in ["lost", "unsaved", "redirect", "trailer"] {
        let metadata = metadata("app", name, json!([]));
        let before = puts.load(Ordering::SeqCst);
        let get_before = gets.load(Ordering::SeqCst);
        let result = publish(
            &client,
            &build(&metadata, Some(&authority), "test"),
            &metadata,
            &owner,
        )
        .await;
        assert_eq!(
            puts.load(Ordering::SeqCst),
            before + 1,
            "never repeat PUT automatically"
        );
        if name == "lost" || name == "trailer" {
            assert_eq!(result.unwrap()["result"], "published");
        } else if name == "unsaved" {
            assert!(result.unwrap_err().to_string().contains("发布结果未知"));
        } else {
            assert!(result.unwrap_err().to_string().contains("307"));
        }
        assert_eq!(
            gets.load(Ordering::SeqCst),
            get_before + usize::from(name != "redirect")
        );
    }
    let mut snapshot_metadata = metadata("app", "snapshot", json!([]));
    snapshot_metadata["repository"] = "https://github.com/genmeta/upload-test".into();
    let snapshot_bytes = build(&snapshot_metadata, Some(&authority), "original");
    let input = root.path().join("snapshot.webc");
    std::fs::write(&input, &snapshot_bytes).unwrap();
    let snapshot = read_snapshot(&input).await.unwrap();
    let checked = checked_package(&snapshot).await.unwrap();
    assert_eq!(checked["repository"], snapshot_metadata["repository"]);
    std::fs::write(
        &input,
        build(&snapshot_metadata, Some(&authority), "changed"),
    )
    .unwrap();
    publish(&client, &snapshot, &checked, &owner).await.unwrap();
    let proof = get(&client, &version_path(&checked).unwrap(), false)
        .await
        .unwrap();
    let proof: Value = serde_json::from_slice(proof.body()).unwrap();
    assert_eq!(proof["repository"], checked["repository"]);
    assert_eq!(proof["package_sha256"], digest(&snapshot_bytes));
    assert_ne!(
        proof["package_sha256"],
        digest(&std::fs::read(&input).unwrap())
    );
    // A trusted version match with another digest cannot prove the same content.
    let lost = metadata("app", "lost", json!([]));
    let different = build(&lost, Some(&authority), "other content");
    assert!(reconcile(&client, &different, &lost, &owner).await.is_err());
    // Before-stream pinning prevents package bytes reaching a different owner.
    let count = puts.load(Ordering::SeqCst);
    let error = client
        .put(store_uri(&version_path(&lost).unwrap()).unwrap())
        .expect_remote_owner_hash(OwnerHash::try_from("b".repeat(64).as_str()).unwrap())
        .await;
    assert!(error.is_err());
    assert_eq!(puts.load(Ordering::SeqCst), count);
    listening.abort();
    Dock::global().remove(&peer);
}
