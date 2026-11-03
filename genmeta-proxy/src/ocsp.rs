//! Renew the running proxy's OCSP staple without interrupting active requests.
use std::time::Duration;

use der::{Decode, Encode};
use dhttp_home::identity::IdentityProfile;
use sha1::{Digest, Sha1};
use tokio::sync::watch;
use x509_parser::prelude::FromDer;

const MAX_REFRESH_DELAY: Duration = Duration::from_secs(24 * 60 * 60);
const RETRY_DELAY: Duration = Duration::from_secs(60);

pub(super) async fn maintain(
    profile: Option<IdentityProfile>,
    updates: watch::Sender<Option<dhttp::Endpoint>>,
) {
    let endpoint = updates.borrow().clone();
    let (Some(profile), Some(mut endpoint)) = (profile, endpoint) else {
        return std::future::pending().await;
    };
    let mut delay = endpoint_refresh_delay(&endpoint);
    loop {
        tokio::time::sleep(delay).await;
        match renew(&profile, &endpoint).await {
            Ok(replacement) => {
                delay = endpoint_refresh_delay(&replacement);
                endpoint = replacement;
                updates.send_replace(Some(endpoint.clone()));
                tracing::info!(identity = %profile.name(), "proxy OCSP refreshed");
            }
            Err(error) => {
                delay = RETRY_DELAY;
                tracing::warn!(identity = %profile.name(), %error, "proxy OCSP refresh failed, retrying");
            }
        }
    }
}

fn endpoint_refresh_delay(endpoint: &dhttp::Endpoint) -> Duration {
    match endpoint.local_authority() {
        Ok(authority) => refresh_delay(authority.ocsp(), qtls::UnixTime::now().as_secs()),
        Err(_) => RETRY_DELAY,
    }
}

fn refresh_delay(staple: &[u8], now: u64) -> Duration {
    let Ok(response) = x509_ocsp::OcspResponse::from_der(staple) else {
        return RETRY_DELAY;
    };
    let Some(bytes) = response.response_bytes else {
        return RETRY_DELAY;
    };
    let Ok(response) = x509_ocsp::BasicOcspResponse::from_der(bytes.response.as_bytes()) else {
        return RETRY_DELAY;
    };
    // Renew halfway through the remaining lifetime, including an old startup cache.
    // Responses without nextUpdate are renewed daily.
    response
        .tbs_response_data
        .responses
        .iter()
        .filter_map(|response| response.next_update)
        .map(|time| time.0.to_unix_duration().as_secs())
        .min()
        .map(|deadline| {
            Duration::from_secs(deadline.saturating_sub(now) / 2)
                .clamp(Duration::from_secs(1), MAX_REFRESH_DELAY)
        })
        .unwrap_or(MAX_REFRESH_DELAY)
}

async fn renew(
    profile: &IdentityProfile,
    endpoint: &dhttp::Endpoint,
) -> std::io::Result<dhttp::Endpoint> {
    let authority = endpoint.local_authority().map_err(std::io::Error::other)?;
    let response = fetch(authority.certificates()).await?;
    let mut cache = tempfile::NamedTempFile::new_in(profile.ssl_dir())?;
    use std::io::Write;
    cache.write_all(&response)?;
    cache.as_file().sync_all()?;
    cache
        .persist(profile.ocsp_path())
        .map_err(|error| error.error)?;
    endpoint
        .reload_from(profile.path())
        .await
        .map_err(std::io::Error::other)
}

async fn fetch(certificates: &[dhttp::CertificateDer<'_>]) -> std::io::Result<Vec<u8>> {
    // dhttp-home's load_or_refresh reuses valid caches; renewal must fetch a new staple.
    let error = |error: String| std::io::Error::other(format!("OCSP: {error}"));
    let leaf = certificates
        .first()
        .ok_or_else(|| error("missing certificate".into()))?;
    let issuer = certificates
        .get(1)
        .ok_or_else(|| error("missing issuer certificate".into()))?;
    let (_, parsed) = x509_parser::certificate::X509Certificate::from_der(leaf.as_ref())
        .map_err(|e| error(e.to_string()))?;
    if !parsed.validity().is_valid() {
        return Err(error("certificate is outside its validity period".into()));
    }
    let url = parsed
        .extensions()
        .iter()
        .find_map(|extension| {
            let x509_parser::extensions::ParsedExtension::AuthorityInfoAccess(aia) =
                extension.parsed_extension()
            else {
                return None;
            };
            aia.accessdescs.iter().find_map(|access| {
                if access.access_method.to_id_string() != "1.3.6.1.5.5.7.48.1" {
                    return None;
                }
                match &access.access_location {
                    x509_parser::extensions::GeneralName::URI(uri) => Some((*uri).to_owned()),
                    _ => None,
                }
            })
        })
        .ok_or_else(|| error("certificate has no OCSP responder URI".into()))?;
    let leaf = x509_cert::Certificate::from_der(leaf.as_ref()).map_err(|e| error(e.to_string()))?;
    let issuer =
        x509_cert::Certificate::from_der(issuer.as_ref()).map_err(|e| error(e.to_string()))?;
    let request = x509_ocsp::OcspRequest {
        tbs_request: x509_ocsp::TbsRequest {
            request_list: vec![x509_ocsp::Request {
                req_cert: x509_ocsp::CertId {
                    hash_algorithm: x509_cert::spki::AlgorithmIdentifierOwned {
                        oid: der::oid::db::rfc5912::ID_SHA_1,
                        parameters: Some(der::asn1::Any::null()),
                    },
                    issuer_name_hash: der::asn1::OctetString::new(
                        Sha1::digest(
                            issuer
                                .tbs_certificate
                                .subject
                                .to_der()
                                .map_err(|e| error(e.to_string()))?,
                        )
                        .to_vec(),
                    )
                    .map_err(|e| error(e.to_string()))?,
                    issuer_key_hash: der::asn1::OctetString::new(
                        Sha1::digest(
                            issuer
                                .tbs_certificate
                                .subject_public_key_info
                                .subject_public_key
                                .raw_bytes(),
                        )
                        .to_vec(),
                    )
                    .map_err(|e| error(e.to_string()))?,
                    serial_number: leaf.tbs_certificate.serial_number,
                },
                single_request_extensions: None,
            }],
            ..Default::default()
        },
        optional_signature: None,
    }
    .to_der()
    .map_err(|e| error(e.to_string()))?;
    tokio::time::timeout(Duration::from_secs(15), async {
        let root = reqwest::Certificate::from_der(dhttp::trust::DHTTP_ROOT_CA_DER)
            .map_err(|e| error(e.to_string()))?;
        let client = reqwest::Client::builder()
            .tls_certs_merge([root])
            .redirect(reqwest::redirect::Policy::none())
            .https_only(false)
            .build()
            .map_err(|e| error(e.to_string()))?;
        let uri = reqwest::Url::parse(&url).map_err(|e| error(e.to_string()))?;
        if !matches!(uri.scheme(), "http" | "https") {
            return Err(error("unsupported responder scheme".into()));
        }
        let mut response = client
            .post(uri)
            .header("Content-Type", "application/ocsp-request")
            .header("Accept", "application/ocsp-response")
            .body(request)
            .send()
            .await
            .map_err(|e| error(e.to_string()))?;
        if !response.status().is_success() {
            return Err(error(format!("responder returned {}", response.status())));
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|e| error(e.to_string()))? {
            if body.len().saturating_add(chunk.len()) > 64 * 1024 {
                return Err(error("response exceeds 64KiB".into()));
            }
            body.extend_from_slice(&chunk);
        }
        qtls::validate_ocsp(&body, certificates, qtls::UnixTime::now())
            .map_err(|e| error(e.to_string()))?;
        Ok(body)
    })
    .await
    .map_err(|_| error("responder timed out after 15 seconds".into()))?
}

#[cfg(test)]
mod tests {
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
}
