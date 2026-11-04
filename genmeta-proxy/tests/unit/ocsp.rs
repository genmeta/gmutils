use der::asn1::{BitString, GeneralizedTime, OctetString};
use x509_ocsp::{
    BasicOcspResponse, CertId, CertStatus, OcspResponse, ResponseData, SingleResponse,
};

use super::*;

fn staple(deadlines: &[Option<u64>]) -> Vec<u8> {
    let time = |seconds| {
        x509_ocsp::OcspGeneralizedTime(
            GeneralizedTime::from_unix_duration(Duration::from_secs(seconds)).unwrap(),
        )
    };
    let algorithm = x509_cert::spki::AlgorithmIdentifierOwned {
        oid: der::oid::db::rfc5912::ID_SHA_1,
        parameters: Some(der::asn1::Any::null()),
    };
    let response = BasicOcspResponse {
        tbs_response_data: ResponseData {
            version: Default::default(),
            responder_id: x509_ocsp::ResponderId::ByKey(OctetString::new(vec![0; 20]).unwrap()),
            produced_at: time(0),
            responses: deadlines
                .iter()
                .map(|deadline| SingleResponse {
                    cert_id: CertId {
                        hash_algorithm: algorithm.clone(),
                        issuer_name_hash: OctetString::new(vec![0; 20]).unwrap(),
                        issuer_key_hash: OctetString::new(vec![0; 20]).unwrap(),
                        serial_number: 1u8.into(),
                    },
                    cert_status: CertStatus::good(),
                    this_update: time(0),
                    next_update: deadline.map(time),
                    single_extensions: None,
                })
                .collect(),
            response_extensions: None,
        },
        signature_algorithm: algorithm,
        signature: BitString::from_bytes(&[0]).unwrap(),
        certs: None,
    };
    OcspResponse::successful(response)
        .unwrap()
        .to_der()
        .unwrap()
}

#[test]
fn renewal_uses_remaining_lifetime_and_earliest_deadline() {
    let response = staple(&[Some(10_000), Some(2_000)]);
    assert_eq!(refresh_delay(&response, 1_000), Duration::from_secs(500));
    assert_eq!(refresh_delay(&response, 1_998), Duration::from_secs(1));
    assert_eq!(refresh_delay(&response, 2_001), Duration::from_secs(1));
}

#[test]
fn long_lived_and_undated_staples_are_renewed_daily() {
    assert_eq!(
        refresh_delay(&staple(&[Some(1_000_000)]), 0),
        MAX_REFRESH_DELAY
    );
    assert_eq!(refresh_delay(&staple(&[None]), 0), MAX_REFRESH_DELAY);
}

#[test]
fn malformed_staples_are_checked_again_soon() {
    assert_eq!(refresh_delay(b"invalid OCSP", 0), RETRY_DELAY);
    assert_eq!(
        refresh_delay(&OcspResponse::try_later().to_der().unwrap(), 0),
        RETRY_DELAY,
    );
}

#[tokio::test]
#[ignore = "requires GENMETA_PROXY_OCSP_PROFILE and access to its real OCSP responder"]
async fn live_ocsp_renewal_updates_cache_and_endpoint() -> Result<(), dhttp::BoxError> {
    let source_path = std::env::var_os("GENMETA_PROXY_OCSP_PROFILE")
        .ok_or_else(|| std::io::Error::other("GENMETA_PROXY_OCSP_PROFILE is required"))?;
    let source = IdentityProfile::try_from(std::path::Path::new(&source_path))?;
    let original_cache = tokio::fs::read(source.ocsp_path()).await.ok();
    let directory = tempfile::tempdir()?;
    let profile = IdentityProfile::try_from(
        directory
            .path()
            .join(source.path().file_name().unwrap())
            .as_path(),
    )?;
    tokio::fs::create_dir_all(profile.ssl_dir()).await?;
    tokio::fs::copy(source.cert_path(), profile.cert_path()).await?;
    tokio::fs::copy(source.key_path(), profile.key_path()).await?;

    // This unsigned, expired sentinel only triggers the renewal timer. The fetched
    // replacement must pass production signature, issuer, status and time checks.
    let expired = staple(&[Some(0)]);
    tokio::fs::write(profile.ocsp_path(), &expired).await?;
    let endpoint = dhttp::Endpoint::load_from(profile.path()).await?;
    let original = endpoint.local_authority()?;
    assert_eq!(endpoint_refresh_delay(&endpoint), Duration::from_secs(1));
    dhttp::DhttpNetwork::init().await?;

    let (updates, mut current) = watch::channel(Some(endpoint));
    let maintenance = maintain(Some(profile.clone()), updates);
    tokio::pin!(maintenance);
    tokio::select! {
        result = tokio::time::timeout(Duration::from_secs(30), current.changed()) => result??,
        () = &mut maintenance => panic!("OCSP maintenance stopped unexpectedly"),
    }

    let replacement = current.borrow().as_ref().unwrap().local_authority()?;
    let cached = profile.load_ocsp().await?;
    qtls::validate_ocsp(&cached, replacement.certificates(), qtls::UnixTime::now())?;
    assert_eq!(replacement.ocsp(), cached);
    assert_ne!(replacement.ocsp(), expired);
    assert_eq!(replacement.certificates(), original.certificates());
    assert_eq!(replacement.public_key(), original.public_key());
    assert_eq!(original.ocsp(), expired);
    assert!(tokio::fs::read(source.ocsp_path()).await.ok() == original_cache);

    let response = OcspResponse::from_der(&cached)?.response_bytes.unwrap();
    let basic = BasicOcspResponse::from_der(response.response.as_bytes())?;
    for response in basic.tbs_response_data.responses {
        println!(
            "live OCSP: status={:?}, thisUpdate={}, nextUpdate={:?}",
            response.cert_status,
            response.this_update.0.to_date_time(),
            response.next_update.map(|time| time.0.to_date_time()),
        );
    }
    println!(
        "live OCSP: verified {} bytes; cache and endpoint updated; next refresh in {} seconds; source cache unchanged",
        cached.len(),
        refresh_delay(&cached, qtls::UnixTime::now().as_secs()).as_secs(),
    );
    Ok(())
}
