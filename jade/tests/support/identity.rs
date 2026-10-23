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
    // Offline package signing needs certificate + private key, not transport OCSP.
}
