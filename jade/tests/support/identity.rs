#[allow(dead_code)]
#[path = "upload_credentials.rs"]
mod signing;
use std::path::Path;

pub fn create(home: &Path) {
    create_named(home, "alice.dhttp.net");
}

pub fn create_named(home: &Path, name: &str) {
    let mut params = rcgen::CertificateParams::new(vec![name.into()]).unwrap();
    let ski = format!("1:0:{}", "a".repeat(64));
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
    let ssl = home
        .join(name.strip_suffix(".dhttp.net").unwrap())
        .join("ssl");
    std::fs::create_dir_all(&ssl).unwrap();
    std::fs::write(ssl.join("fullchain.crt"), cert.pem()).unwrap();
    std::fs::write(ssl.join("privkey.pem"), key.serialize_pem()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            ssl.join("privkey.pem"),
            std::fs::Permissions::from_mode(0o400),
        )
        .unwrap();
    }
    // Signing credentials are independent from the legacy TLS fixture above.
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    fn pem(label: &str, der: &[u8]) -> String {
        let base = STANDARD.encode(der);
        let lines = base
            .as_bytes()
            .chunks(64)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect::<Vec<_>>()
            .join("\n");
        format!("-----BEGIN {label}-----\n{lines}\n-----END {label}-----\n")
    }
    let (chain, key) = signing::developer(name, &"a".repeat(64));
    let cert_pem = chain
        .iter()
        .map(|c| pem("CERTIFICATE", c.as_ref()))
        .collect::<String>();
    let key_pem = pem("PRIVATE KEY", key.secret_der());
    let signing = ssl.parent().unwrap().join("code-signing/1");
    std::fs::create_dir_all(&signing).unwrap();
    let credentials = signing.join("credentials.json");
    std::fs::write(
        &credentials,
        serde_json::to_vec(&serde_json::json!({"cert_pem":cert_pem,"key_pem":key_pem})).unwrap(),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(credentials, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
}
