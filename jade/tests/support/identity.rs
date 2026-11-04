#[allow(dead_code)]
#[path = "upload_credentials.rs"]
mod signing;
use std::path::Path;

pub fn create(home: &Path) {
    create_named(home, "alice.dhttp.net");
}

pub fn create_named(home: &Path, name: &str) {
    let ssl = home
        .join(name.strip_suffix(".dhttp.net").unwrap())
        .join("ssl");
    std::fs::create_dir_all(&ssl).unwrap();
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
    std::fs::write(ssl.join("fullchain.crt"), cert_pem).unwrap();
    std::fs::write(ssl.join("privkey.pem"), key_pem).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            ssl.join("privkey.pem"),
            std::fs::Permissions::from_mode(0o400),
        )
        .unwrap();
    }
}
