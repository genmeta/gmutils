use std::collections::HashMap;

use dhttp::{
    certificate::CertificateSequence, ddns::resolvers::endpoint_candidates::EndpointCandidates,
};
use snafu::prelude::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SshPrimaryCandidate {
    pub(crate) sequence: CertificateSequence,
    pub(crate) online: bool,
    pub(crate) endpoint_count: usize,
    pub(crate) device_name: Option<String>,
    pub(crate) cert_status: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CertPrimaryMetadata {
    pub(crate) sequence: CertificateSequence,
    pub(crate) device_name: Option<String>,
    pub(crate) status: Option<String>,
}

pub(crate) fn merge_candidates(
    ddns: EndpointCandidates,
    certs: impl IntoIterator<Item = CertPrimaryMetadata>,
) -> Vec<SshPrimaryCandidate> {
    let mut rows = Vec::<SshPrimaryCandidate>::new();
    let mut sequence_indexes = HashMap::<u32, usize>::new();

    for group in ddns.groups {
        if group.chain.usage().kind_flag() != "0" {
            continue;
        }
        let sequence = group.chain.sequence().get();
        if let Some(index) = sequence_indexes.get(&sequence).copied() {
            rows[index].endpoint_count += group.endpoints.len();
        } else {
            sequence_indexes.insert(sequence, rows.len());
            rows.push(SshPrimaryCandidate {
                sequence: group.chain.sequence(),
                online: true,
                endpoint_count: group.endpoints.len(),
                device_name: None,
                cert_status: None,
            });
        }
    }

    for cert in certs {
        if let Some(index) = sequence_indexes.get(&cert.sequence.get()).copied() {
            let row = &mut rows[index];
            if row.device_name.is_none() {
                row.device_name.clone_from(&cert.device_name);
            }
            if row.cert_status.is_none() {
                row.cert_status.clone_from(&cert.status);
            }
        } else {
            sequence_indexes.insert(cert.sequence.get(), rows.len());
            rows.push(SshPrimaryCandidate {
                sequence: cert.sequence,
                online: false,
                endpoint_count: 0,
                device_name: cert.device_name,
                cert_status: cert.status,
            });
        }
    }

    rows
}

#[derive(Debug, Snafu)]
#[snafu(module(sequence_error))]
pub enum Error {
    #[snafu(display(
        "No primary sequences were found for {target}.\n\nThe device may not have published DNS endpoints yet, and no certificate metadata was available"
    ))]
    NoCandidates { target: String },
}

pub(crate) fn choose_server_ranked(
    target: &str,
    candidates: &[SshPrimaryCandidate],
) -> Result<CertificateSequence, Error> {
    candidates
        .iter()
        .find(|candidate| candidate.online)
        .map(|candidate| candidate.sequence)
        .ok_or_else(|| Error::NoCandidates {
            target: target.to_string(),
        })
}

pub(crate) fn cert_metadata_from_parts(
    kind: &str,
    sequence: u32,
    device_name: Option<&str>,
    status: &str,
) -> Option<CertPrimaryMetadata> {
    if kind != "primary" {
        return None;
    }
    Some(CertPrimaryMetadata {
        sequence: CertificateSequence::try_from(sequence).ok()?,
        device_name: device_name.map(str::to_owned),
        status: Some(status.to_owned()),
    })
}

pub(crate) async fn fetch_cert_metadata(
    target_domain: &str,
    local_identity: Option<&dhttp::home::identity::IdentityProfile>,
) -> Vec<CertPrimaryMetadata> {
    let Some(identity) = local_identity else {
        tracing::warn!(
            target = target_domain,
            "primary sequence device metadata unavailable without a local target identity"
        );
        return Vec::new();
    };
    if identity.name().as_full() != target_domain {
        tracing::warn!(
            target = target_domain,
            local_identity = %identity.name(),
            "primary sequence device metadata requires the same local identity"
        );
        return Vec::new();
    }

    let cert_server = match genmeta_identity::cert_server::CertServer::new(
        genmeta_identity::CERT_SERVER_BASE_URL,
    ) {
        Ok(client) => client,
        Err(error) => {
            tracing::warn!(error = %snafu::Report::from_error(&error), "failed to create certserver client for primary sequence metadata");
            return Vec::new();
        }
    };

    let page = match cert_server
        .list_certs_with_identity(
            identity.name().as_full(),
            target_domain,
            Some("primary"),
            None,
        )
        .await
    {
        Ok(page) => page,
        Err(error) => {
            tracing::warn!(error = %snafu::Report::from_error(&error), "failed to fetch primary sequence metadata from certserver");
            return Vec::new();
        }
    };

    page.list
        .iter()
        .filter_map(|item| {
            cert_metadata_from_parts(
                &item.kind,
                item.sequence,
                item.device_name.as_deref(),
                &item.status,
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use dhttp::{
        certificate::{CertificateChainKey, CertificateSequence, CertificateUsage},
        ddns::resolvers::endpoint_candidates::{EndpointCandidateGroup, EndpointCandidates},
        dquic::qresolve::Source,
    };

    use super::*;

    fn group(sequence: u8, endpoints: usize) -> EndpointCandidateGroup {
        EndpointCandidateGroup {
            chain: CertificateChainKey::new(
                CertificateSequence::from(sequence),
                CertificateUsage::ClientOnly,
            ),
            endpoints: vec![
                dhttp::dquic::qbase::net::addr::EndpointAddr::direct(
                    "192.0.2.10:4433".parse().unwrap(),
                );
                endpoints
            ],
            sources: vec![Source::Dht],
        }
    }

    #[test]
    fn merge_preserves_online_order_then_appends_offline_certificate_order() {
        let candidates = merge_candidates(
            EndpointCandidates {
                groups: vec![group(2, 2), group(1, 1)],
            },
            [
                CertPrimaryMetadata {
                    sequence: CertificateSequence::from(1u8),
                    device_name: Some("MacBook Pro".to_string()),
                    status: Some("active".to_string()),
                },
                CertPrimaryMetadata {
                    sequence: CertificateSequence::from(3u8),
                    device_name: Some("ThinkPad".to_string()),
                    status: Some("active".to_string()),
                },
                CertPrimaryMetadata {
                    sequence: CertificateSequence::from(0u8),
                    device_name: Some("Server".to_string()),
                    status: Some("expired".to_string()),
                },
            ],
        );

        assert_eq!(
            candidates
                .iter()
                .map(|candidate| candidate.sequence.get())
                .collect::<Vec<_>>(),
            vec![2, 1, 3, 0]
        );
        assert!(candidates[0].online);
        assert_eq!(candidates[0].endpoint_count, 2);
        assert_eq!(candidates[1].device_name.as_deref(), Some("MacBook Pro"));
        assert!(!candidates[2].online);
        assert_eq!(candidates[2].device_name.as_deref(), Some("ThinkPad"));
        assert_eq!(candidates[3].device_name.as_deref(), Some("Server"));
    }

    #[test]
    fn server_ranked_selection_uses_first_online_candidate() {
        let mut candidates = vec![
            SshPrimaryCandidate {
                sequence: CertificateSequence::from(2u8),
                online: true,
                endpoint_count: 1,
                device_name: None,
                cert_status: None,
            },
            SshPrimaryCandidate {
                sequence: CertificateSequence::from(1u8),
                online: true,
                endpoint_count: 1,
                device_name: None,
                cert_status: None,
            },
        ];

        assert_eq!(
            choose_server_ranked("alice.device", &candidates)
                .unwrap()
                .get(),
            2
        );

        candidates[0].online = false;
        assert_eq!(
            choose_server_ranked("alice.device", &candidates)
                .unwrap()
                .get(),
            1
        );
    }

    #[test]
    fn empty_candidates_reports_no_primary_sequences() {
        let error = choose_server_ranked("alice.device", &[]).unwrap_err();

        assert!(
            error
                .to_string()
                .contains("No primary sequences were found for alice.device")
        );
    }

    #[test]
    fn cert_list_item_primary_metadata_ignores_secondary() {
        let primary = cert_metadata_from_parts("primary", 2, Some("Laptop"), "active")
            .expect("primary metadata");
        let secondary = cert_metadata_from_parts("secondary", 2, Some("Backup"), "active");

        assert_eq!(primary.sequence.get(), 2);
        assert_eq!(primary.device_name.as_deref(), Some("Laptop"));
        assert!(secondary.is_none());
    }
}
