use std::{fs, path::Path, process::Command};

fn openssl(root: &Path, args: &[&str]) {
    let executable = std::env::var_os("DHTTP_TEST_OPENSSL").unwrap_or_else(|| "openssl".into());
    let output = Command::new(executable)
        .args(args)
        .current_dir(root)
        .output()
        .expect("this integration test requires OpenSSL");
    assert!(
        output.status.success(),
        "openssl {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

// Generate fresh certificates and signed OCSP responses. Production verification stays enabled.
pub fn generate(root: &Path, names: &[(&str, &str, &str)]) {
    fs::create_dir_all(root).unwrap();
    openssl(
        root,
        &[
            "req",
            "-x509",
            "-sha256",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:prime256v1",
            "-pkeyopt",
            "ec_param_enc:named_curve",
            "-nodes",
            "-keyout",
            "ca.key",
            "-out",
            "ca.crt",
            "-days",
            "2",
            "-subj",
            "/CN=DHTTP test CA",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign,digitalSignature",
        ],
    );
    for (index, &(name, hostname, owner)) in names.iter().enumerate() {
        let serial = format!("{:02X}", index + 1);
        let directory = format!("{name}/ssl");
        fs::create_dir_all(root.join(&directory)).unwrap();
        let key = format!("{directory}/privkey.pem");
        let cert = format!("{directory}/fullchain.crt");
        let subject = format!("/CN={hostname}");
        openssl(
            root,
            &[
                "req",
                "-new",
                "-sha256",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:prime256v1",
                "-pkeyopt",
                "ec_param_enc:named_curve",
                "-nodes",
                "-keyout",
                &key,
                "-out",
                "leaf.csr",
                "-subj",
                &subject,
            ],
        );
        fs::write(root.join("leaf.ext"), format!(
            "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth,clientAuth\nsubjectAltName=DNS:{hostname}\nsubjectKeyIdentifier={}\n",
            format!("0:0:{owner}").bytes().map(|byte| format!("{byte:02x}")).collect::<Vec<_>>().join(":")
        )).unwrap();
        openssl(
            root,
            &[
                "x509",
                "-req",
                "-sha256",
                "-in",
                "leaf.csr",
                "-CA",
                "ca.crt",
                "-CAkey",
                "ca.key",
                "-set_serial",
                &serial,
                "-out",
                &cert,
                "-days",
                "1",
                "-extfile",
                "leaf.ext",
            ],
        );
        // Validate actual credentials before starting QUIC. These are public
        // key files; private key bytes never appear in test output.
        openssl(root, &["pkey", "-in", &key, "-check", "-noout"]);
        openssl(
            root,
            &["pkey", "-in", &key, "-pubout", "-out", "leaf-key.pub"],
        );
        openssl(
            root,
            &[
                "x509",
                "-in",
                &cert,
                "-pubkey",
                "-noout",
                "-out",
                "leaf-cert.pub",
            ],
        );
        assert_eq!(
            fs::read(root.join("leaf-key.pub")).unwrap(),
            fs::read(root.join("leaf-cert.pub")).unwrap(),
            "certificate and private key must match for {hostname}"
        );
        openssl(
            root,
            &[
                "verify",
                "-CAfile",
                "ca.crt",
                "-verify_hostname",
                hostname,
                &cert,
            ],
        );
        fs::write(
            root.join("index.txt"),
            format!("V\t491231235959Z\t\t{serial}\tunknown\t{subject}\n"),
        )
        .unwrap();
        openssl(
            root,
            &[
                "ocsp",
                "-rmd",
                "sha256",
                "-index",
                "index.txt",
                "-rsigner",
                "ca.crt",
                "-rkey",
                "ca.key",
                "-CA",
                "ca.crt",
                "-issuer",
                "ca.crt",
                "-cert",
                &cert,
                "-respout",
                &format!("{directory}/{}", dhttp_home::identity::ssl::OCSP_FILE_NAME),
                "-ndays",
                "1",
            ],
        );
        openssl(
            root,
            &[
                "ocsp",
                "-respin",
                &format!("{directory}/{}", dhttp_home::identity::ssl::OCSP_FILE_NAME),
                "-issuer",
                "ca.crt",
                "-cert",
                &cert,
                "-CAfile",
                "ca.crt",
                "-no_nonce",
            ],
        );
        // Credential loaders validate the OCSP issuer from the complete chain.
        let mut chain = fs::read(root.join(&cert)).unwrap();
        chain.extend(fs::read(root.join("ca.crt")).unwrap());
        fs::write(root.join(&cert), chain).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(root.join(key), fs::Permissions::from_mode(0o400)).unwrap();
        }
    }
}

/// Disposable codeSigning leaf under the shared isolated Root. Never a production identity.
pub fn developer(
    name: &str,
    owner: &str,
) -> (
    Vec<qtls::CertificateDer<'static>>,
    qtls::PrivateKeyDer<'static>,
) {
    use rcgen::{
        BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose,
        IsCa, Issuer, KeyIdMethod, KeyPair, KeyUsagePurpose,
    };
    use rustls::pki_types::pem::PemObject;
    let ca_pem =
        include_str!("../../../genmeta-identity/tests/fixtures/code-signing/code-issuer.cert.pem");
    let ca = qtls::CertificateDer::from_pem_slice(ca_pem.as_bytes()).unwrap();
    let ca_key = KeyPair::from_pem(include_str!(
        "../../../genmeta-identity/tests/fixtures/code-signing/code-issuer.key.pem"
    ))
    .unwrap();
    let (_, parsed) = x509_parser::parse_x509_certificate(ca.as_ref()).unwrap();
    let mut issuer_params = CertificateParams::default();
    issuer_params.distinguished_name = DistinguishedName::new();
    issuer_params
        .distinguished_name
        .push(DnType::CommonName, "TEST ONLY code-issuer");
    issuer_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    let ski = parsed
        .extensions()
        .iter()
        .find_map(|e| {
            if let x509_parser::extensions::ParsedExtension::SubjectKeyIdentifier(id) =
                e.parsed_extension()
            {
                Some(id.0.to_vec())
            } else {
                None
            }
        })
        .unwrap();
    issuer_params.key_identifier_method = KeyIdMethod::PreSpecified(ski);
    let issuer = Issuer::new(issuer_params, ca_key);
    let mut params = CertificateParams::new(vec![name.into()]).unwrap();
    params.distinguished_name = DistinguishedName::new();
    params.distinguished_name.push(DnType::CommonName, name);
    params.is_ca = IsCa::ExplicitNoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::CodeSigning];
    let ski = format!("1:0:{owner}");
    params.key_identifier_method = KeyIdMethod::PreSpecified(ski.as_bytes().to_vec());
    let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
    let cert = params.signed_by(&key, &issuer).unwrap();
    (
        vec![cert.der().clone(), ca],
        qtls::PrivateKeyDer::try_from(key.serialize_der()).unwrap(),
    )
}
