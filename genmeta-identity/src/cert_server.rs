use std::{path::Path, sync::Arc};

use http_body_util::BodyExt;
use reqwest::header;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use snafu::{FromString, ResultExt, Snafu, Whatever};
use tokio::io::AsyncWriteExt;

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(transparent)]
    Request { source: reqwest::Error },
    #[snafu(display("{message}"))]
    Api {
        status: reqwest::StatusCode,
        code: String,
        message: String,
    },
    #[snafu(display("failed to parse JSON response from cert server"))]
    Json { source: serde_json::Error },
    #[snafu(display("failed to load DHTTP identity endpoint"))]
    DhttpEndpoint { source: dhttp::Error },
    #[snafu(display("failed to load DHTTP identity endpoint from selected profile"))]
    DhttpEndpointFromProfile { source: dhttp::Error },
    #[snafu(display("failed to send DHTTP identity request"))]
    DhttpRequest { source: dhttp::Error },
    #[snafu(display("failed to read DHTTP identity response body"))]
    DhttpRead { source: dhttp::BoxError },
    #[snafu(display("identity authentication failed and email fallback is unavailable"))]
    IdentityFallbackUnavailable,
    #[snafu(transparent)]
    Whatever { source: Whatever },
}

impl snafu::FromString for Error {
    type Source = <Whatever as snafu::FromString>::Source;

    fn without_source(message: String) -> Self {
        Whatever::without_source(message).into()
    }

    fn with_source(source: Self::Source, message: String) -> Self {
        Whatever::with_source(source, message).into()
    }
}

#[derive(Debug, Deserialize)]
struct ErrorResponse {
    error: ErrorEnvelope,
}

#[derive(Debug, Deserialize)]
struct ErrorEnvelope {
    #[serde(deserialize_with = "deserialize_error_code")]
    code: String,
    message: String,
    invoice_no: Option<String>,
}

#[derive(Debug, Deserialize)]
struct DetailedErrorResponse<T> {
    error: DetailedErrorEnvelope<T>,
}

#[derive(Debug, Deserialize)]
struct DetailedErrorEnvelope<T> {
    #[serde(deserialize_with = "deserialize_error_code")]
    code: String,
    message: String,
    details: T,
}

#[derive(Debug, Serialize)]
struct CreateDomainRequest<'a> {
    domain: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    verify_code: Option<&'a str>,
    auto_renew: bool,
    redirect_mode: &'static str,
    terms_accepted: bool,
    terms_version: &'static str,
}

impl<'a> CreateDomainRequest<'a> {
    fn new(domain: &'a str, email: Option<&'a str>, verify_code: Option<&'a str>) -> Self {
        Self {
            domain,
            email,
            verify_code,
            auto_renew: false,
            redirect_mode: "payment_required",
            terms_accepted: true,
            terms_version: "v1",
        }
    }
}

fn deserialize_error_code<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum WireErrorCode {
        Symbol(String),
        Number(u16),
    }

    Ok(match WireErrorCode::deserialize(deserializer)? {
        WireErrorCode::Symbol(code) => code,
        WireErrorCode::Number(code) => code.to_string(),
    })
}

fn normalize_api_code(code: &str) -> &str {
    match code {
        "1002" => "unauthorized",
        "1101" => "email_invalid",
        "1102" => "verify_code_invalid",
        "1103" => "verify_code_expired",
        "1104" => "verify_code_attempt_exceeded",
        "1105" => "verify_code_too_frequent",
        "1106" => "verify_code_rate_limited",
        "1110" => "user_blocked",
        "1201" => "domain_invalid",
        "1202" => "domain_not_found",
        "1203" => "domain_forbidden",
        "1208" => "domain_conflict",
        "1211" => "domain_email_not_matched",
        "1212" => "domain_expired",
        "1213" => "domain_revoked",
        "1303" => "subdomain_conflict",
        "1304" => "subdomain_quota_exceeded",
        "1407" => "cert_sequence_not_found",
        "1420" => "certificate_key_reuse_not_allowed",
        "1421" => "certificate_renewal_idempotency_invalid",
        "1422" => "certificate_renewal_idempotency_conflict",
        "1426" => "certificate_status_unavailable",
        "1427" => "code_signing_unavailable",
        "1428" => "code_signing_entitlement_required",
        "1429" => "code_signing_identity_required",
        "1430" => "certificate_purpose_mismatch",
        "1432" => "certificate_serial_ambiguous",
        "1433" => "purchase_idempotency_invalid",
        "1434" => "purchase_idempotency_conflict",
        "1435" => "purchase_in_progress",
        "1436" => "purchase_ended",
        "1437" => "developer_root_required",
        "1438" => "developer_domain_conflict",
        "1439" => "developer_domain_required",
        "1440" => "developer_domain_managed",
        _ => code,
    }
}

fn idempotency_header(value: &str) -> Result<http::HeaderValue, Error> {
    http::HeaderValue::from_str(value)
        .map_err(|error| Error::without_source(format!("invalid idempotency key: {error}")))
}

const SUBDOMAIN_QUOTA_MESSAGE: &str = "The parent identity has reached its sub-identity seat limit. Update your subscription plan to add more seats, then try again.";

fn user_facing_api_message(code: &str, server_message: &str) -> String {
    if normalize_api_code(code) == "subdomain_quota_exceeded" {
        SUBDOMAIN_QUOTA_MESSAGE.to_string()
    } else {
        server_message.to_string()
    }
}

fn extract_string_field(value: &Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| value.get(*key)?.as_str().map(ToOwned::to_owned))
}

fn extract_i64_field(value: &Value, keys: &[&str]) -> Option<i64> {
    keys.iter().find_map(|key| value.get(*key)?.as_i64())
}

fn extract_subdomain_quota_quote(details: &Value) -> Option<SubdomainQuotaQuote> {
    let quote_source = details
        .get("quota_quote")
        .or_else(|| details.get("quote"))
        .unwrap_or(details);
    let domain = extract_string_field(details, &["domain"])
        .or_else(|| extract_string_field(quote_source, &["domain"]))?;
    let due = extract_i64_field(quote_source, &["due"])?;
    let currency = extract_string_field(quote_source, &["currency"])?;

    Some(SubdomainQuotaQuote {
        domain,
        due,
        currency,
        days_left: extract_i64_field(quote_source, &["days_left"]).unwrap_or(0),
        days_total: extract_i64_field(quote_source, &["days_total"]).unwrap_or(0),
        renewal: extract_i64_field(quote_source, &["renewal"]).unwrap_or(0),
    })
}

fn parse_subdomain_quota_quote(
    status: reqwest::StatusCode,
    body: &[u8],
) -> Result<Option<SubdomainQuotaQuote>, Error> {
    if status != reqwest::StatusCode::UNPROCESSABLE_ENTITY {
        return Ok(None);
    }

    let Ok(parsed) = serde_json::from_slice::<DetailedErrorResponse<Value>>(body) else {
        return Ok(None);
    };
    if normalize_api_code(&parsed.error.code) != "subdomain_quota_exceeded" {
        return Ok(None);
    }
    let _ = &parsed.error.message;

    Ok(extract_subdomain_quota_quote(&parsed.error.details))
}

pub fn parse_error_body(status: reqwest::StatusCode, body: &[u8]) -> Result<(), Error> {
    let parsed = serde_json::from_slice::<ErrorResponse>(body).context(JsonSnafu {})?;
    let ErrorEnvelope {
        code,
        mut message,
        invoice_no,
    } = parsed.error;
    if normalize_api_code(&code) == "purchase_in_progress"
        && let Some(invoice) = invoice_no.filter(|n| {
            n.starts_with("INV") && n.len() <= 100 && n.bytes().all(|b| b.is_ascii_alphanumeric())
        })
    {
        message.push_str(&format!(" (invoice_no={invoice})"));
    }
    ApiSnafu {
        status,
        message: user_facing_api_message(&code, &message),
        code,
    }
    .fail()
}

#[derive(Debug, Clone, Deserialize)]
pub struct EmailVerifyResponse {
    pub email: String,
    pub expires_at: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LoginResponse {
    pub email: String,
    pub access_token: String,
    pub token_expires_at: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DomainLoginResponse {
    pub domain: String,
    pub access_token: String,
    pub token_expires_at: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DomainAvailabilityResponse {
    pub domain: String,
    pub availability: String,
    pub currency: String,
    pub prices: Vec<PricingItem>,
}

impl DomainAvailabilityResponse {
    pub fn monthly_amount(&self) -> Option<i64> {
        self.prices
            .iter()
            .find(|price| price.interval == "monthly")
            .map(|price| price.amount)
    }

    pub fn yearly_amount(&self) -> Option<i64> {
        self.prices
            .iter()
            .find(|price| price.interval == "yearly")
            .map(|price| price.amount)
    }

    pub fn is_free(&self) -> bool {
        !self.prices.is_empty() && self.prices.iter().all(|price| price.amount == 0)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct PricingItem {
    pub interval: String,
    pub amount: i64,
    #[serde(default)]
    pub discount: Option<f64>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateDomainResponse {
    pub domain: String,
    pub quotes: DomainQuotes,
    pub reservation: Option<ReservationInfo>,
    pub payment_entry: Option<PaymentEntryInfo>,
    pub next_action: String,
    pub selected_billing_cycle: Option<String>,
    pub subscription: Option<SubscriptionInfo>,
    pub invoice: Option<InvoiceInfo>,
    pub auth: Option<CreateDomainAuthInfo>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DomainQuotes {
    pub currency: String,
    pub monthly: i64,
    pub yearly: i64,
    pub default_billing_cycle: String,
    #[serde(default)]
    pub options: Vec<DomainQuoteOption>,
}

impl DomainQuotes {
    pub fn promotion_percent_off(&self) -> Option<i32> {
        self.options.iter().find_map(|option| match option.benefit {
            Some(DomainQuoteBenefit::Promotion { percent_off }) => Some(percent_off),
            _ => None,
        })
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct DomainQuoteOption {
    pub billing_cycle: String,
    pub price_code: String,
    pub list_amount: i64,
    pub discount_amount: i64,
    pub payable_amount: i64,
    pub benefit: Option<DomainQuoteBenefit>,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DomainQuoteBenefit {
    Promotion { percent_off: i32 },
    StarterEntitlement,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ReservationInfo {
    pub reservation_no: String,
    pub status: String,
    pub expires_at: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PaymentEntryInfo {
    pub url: String,
    pub checkout_token: String,
    pub expires_at: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateDomainAuthInfo {
    pub email: String,
    pub is_new_user: bool,
    pub access_token: String,
    pub token_expires_at: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SubscriptionInfo {
    pub subscription_no: String,
    pub status: String,
    pub url: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct InvoiceInfo {
    pub number: String,
    pub status: String,
    pub amount: i64,
    pub currency: String,
    pub billing_cycle: Option<String>,
    pub expires_at: Option<i64>,
    pub paid_at: Option<i64>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateSubdomainResponse {
    pub domain: String,
    pub parent: String,
    pub status: String,
    pub expires_at: Option<i64>,
    pub cert: SubdomainCertQuota,
    pub url: String,
    pub certs_url: String,
    pub created_at: i64,
    pub invoice: Option<SubdomainInvoice>,
}

#[derive(Debug, Clone)]
pub enum CreateSubdomainAttempt {
    Created(CreateSubdomainResponse),
    QuotaExceeded(SubdomainQuotaQuote),
}

#[derive(Debug, Clone, Deserialize)]
pub struct SubdomainCertQuota {
    pub limit: i32,
    pub used: i32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SubdomainInvoice {
    pub number: String,
    pub amount: i64,
    pub currency: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubdomainQuotaQuote {
    pub domain: String,
    pub due: i64,
    pub currency: String,
    pub days_left: i64,
    pub days_total: i64,
    pub renewal: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CertificateDetail {
    pub domain: String,
    pub device_name: Option<String>,
    pub sequence: u32,
    pub kind: String,
    pub serial_number: Option<String>,
    pub ski: Option<String>,
    pub ski_version: Option<String>,
    pub status: String,
    pub csr: String,
    pub cert_pem: String,
    pub issued_at: i64,
    pub valid_not_after: i64,
    pub created_at: i64,
}

#[derive(Debug, Clone, Copy)]
pub struct CertificateRenewalRequest<'a> {
    domain: &'a str,
    kind: &'a str,
    sequence: u32,
    device_name: Option<&'a str>,
    csr_pem: &'a str,
    idempotency_key: Option<&'a str>,
}

impl<'a> CertificateRenewalRequest<'a> {
    pub fn new(
        domain: &'a str,
        kind: &'a str,
        sequence: u32,
        device_name: Option<&'a str>,
        csr_pem: &'a str,
    ) -> Self {
        Self {
            domain,
            kind,
            sequence,
            device_name,
            csr_pem,
            idempotency_key: None,
        }
    }

    pub fn with_idempotency_key(mut self, idempotency_key: &'a str) -> Self {
        self.idempotency_key = Some(idempotency_key);
        self
    }

    fn body(self) -> Value {
        json!({
            "domain": self.domain,
            "kind": self.kind,
            "sequence": self.sequence,
            "device_name": self.device_name,
            "csr": self.csr_pem,
        })
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct InvoiceDetail {
    pub invoice_no: String,
    pub domain: String,
    pub status: String,
    pub amount: i64,
    pub currency: String,
    pub url: String,
    pub expires_at: Option<i64>,
    pub updated_at: Option<i64>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CertificateListPage {
    pub list: Vec<CertificateListItem>,
    pub pagination: PageInfo,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PageInfo {
    pub page: usize,
    pub page_size: usize,
    pub total: usize,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CertificateListItem {
    pub domain: String,
    pub device_name: Option<String>,
    pub sequence: u32,
    pub kind: String,
    pub serial_number: Option<String>,
    pub ski: Option<String>,
    pub ski_version: Option<String>,
    pub status: String,
    pub issued_at: i64,
    pub valid_not_after: i64,
    pub revoked_at: Option<i64>,
    pub created_at: i64,
}

async fn parse_response<T: DeserializeOwned>(response: reqwest::Response) -> Result<T, Error> {
    let status = response.status();
    let body = response.bytes().await?;
    if !status.is_success() {
        return parse_error_body(status, &body).and_then(|()| unreachable!());
    }
    serde_json::from_slice::<T>(&body).context(JsonSnafu {})
}

async fn parse_create_domain_response(
    response: reqwest::Response,
) -> Result<CreateDomainResponse, Error> {
    let status = response.status();
    let body = response.bytes().await?;
    if status == reqwest::StatusCode::PAYMENT_REQUIRED {
        let parsed = serde_json::from_slice::<CreateDomainResponse>(&body).context(JsonSnafu {})?;
        if parsed.next_action == "payment" || parsed.payment_entry.is_some() {
            return Ok(parsed);
        }
        return parse_error_body(status, &body).and_then(|()| unreachable!());
    }
    if !status.is_success() {
        return parse_error_body(status, &body).and_then(|()| unreachable!());
    }
    serde_json::from_slice::<CreateDomainResponse>(&body).context(JsonSnafu {})
}

async fn parse_create_subdomain_response(
    response: reqwest::Response,
) -> Result<CreateSubdomainAttempt, Error> {
    let status = response.status();
    let body = response.bytes().await?;
    if let Some(quote) = parse_subdomain_quota_quote(status, &body)? {
        return Ok(CreateSubdomainAttempt::QuotaExceeded(quote));
    }
    if !status.is_success() {
        return parse_error_body(status, &body).and_then(|()| unreachable!());
    }
    serde_json::from_slice::<CreateSubdomainResponse>(&body)
        .map(CreateSubdomainAttempt::Created)
        .context(JsonSnafu {})
}

async fn parse_dhttp_response<T: DeserializeOwned>(
    response: http::Response<dhttp::Body>,
) -> Result<T, Error> {
    let status = response.status();
    let body = response
        .into_body()
        .collect()
        .await
        .map_err(|source| Error::DhttpRead { source })?
        .to_bytes();
    if !status.is_success() {
        return parse_error_body(status, &body).and_then(|()| unreachable!());
    }
    serde_json::from_slice::<T>(&body).context(JsonSnafu {})
}

#[derive(Debug, Clone)]
pub struct CertServer {
    base_url: Arc<str>,
    http_client: reqwest::Client,
}

impl CertServer {
    async fn identity_endpoint(identity_domain: &str) -> Result<dhttp::Endpoint, Error> {
        let home = dhttp_home::DhttpHome::load(dhttp_home::HomeScope::User).map_err(|source| {
            Error::DhttpEndpoint {
                source: std::io::Error::other(source).into(),
            }
        })?;
        let name = identity_domain
            .parse::<dhttp_identity::name::DhttpName>()
            .map_err(
                |source: dhttp_identity::name::InvalidDhttpName| Error::DhttpEndpoint {
                    source: std::io::Error::other(source).into(),
                },
            )?;
        let profile = home
            .resolve_identity_profile((name).as_full())
            .await
            .map_err(|source| Error::DhttpEndpoint {
                source: std::io::Error::other(source).into(),
            })?;
        Self::identity_endpoint_from_profile(profile.path()).await
    }

    async fn identity_endpoint_from_profile(profile_dir: &Path) -> Result<dhttp::Endpoint, Error> {
        let endpoint = dhttp::Endpoint::load_from_with_ocsp(profile_dir)
            .await
            .context(DhttpEndpointFromProfileSnafu)?;
        init_network(
            &[ddns::DnsScheme::System, ddns::DnsScheme::H3],
            &["*".to_owned()],
        )
        .await
        .context(DhttpEndpointSnafu)?;
        Ok(endpoint)
    }

    pub fn new(base_url: impl Into<Arc<str>>) -> Result<Self, Whatever> {
        let base_url = base_url.into();
        let base_url =
            reqwest::Url::parse(&base_url).whatever_context("failed to parse cert server URL")?;

        let root_cert = reqwest::Certificate::from_der(dhttp::trust::DHTTP_ROOT_CA_DER)
            .whatever_context("failed to parse DHTTP root certificate")?;
        let http_client = reqwest::Client::builder()
            .tls_certs_merge([root_cert])
            .gzip(true)
            .zstd(true)
            .build()
            .whatever_context("failed to build HTTP client")?;
        Ok(Self {
            base_url: Arc::from(base_url.as_str().trim_end_matches('/')),
            http_client,
        })
    }

    fn service_url(&self, path: &str) -> String {
        format!("{}{path}", self.base_url)
    }

    async fn send_identity_json<T: DeserializeOwned>(
        &self,
        identity_domain: &str,
        method: http::Method,
        path: &str,
        body: serde_json::Value,
    ) -> Result<T, Error> {
        self.send_identity_json_with_idempotency(identity_domain, method, path, body, None)
            .await
    }

    async fn send_identity_json_with_idempotency<T: DeserializeOwned>(
        &self,
        identity_domain: &str,
        method: http::Method,
        path: &str,
        body: serde_json::Value,
        idempotency_key: Option<&str>,
    ) -> Result<T, Error> {
        let endpoint = Self::identity_endpoint(identity_domain).await?;
        let uri = self.service_url(path);
        let mut request = http::Request::builder().method(method).uri(uri).header(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("application/json"),
        );
        if let Some(idempotency_key) = idempotency_key {
            request = request.header("idempotency-key", idempotency_header(idempotency_key)?);
        }
        let request = request
            .body(dhttp::WndBuf::new(64 * 1024))
            .map_err(|source| Error::DhttpRequest {
                source: std::io::Error::other(source).into(),
            })?;
        let (mut writer, response) = endpoint
            .from_request(request)
            .await
            .context(DhttpRequestSnafu)?;
        let upload = async {
            writer
                .write_all(body.to_string().as_bytes())
                .await
                .map_err(dhttp::Error::from)?;
            writer.shutdown().await.map_err(dhttp::Error::from)
        };
        let (_, response) = tokio::try_join!(upload, response).context(DhttpRequestSnafu)?;
        parse_dhttp_response(response).await
    }

    #[cfg(feature = "cli")]
    async fn send_identity_profile_json<T: DeserializeOwned>(
        &self,
        profile_dir: &Path,
        method: http::Method,
        path: &str,
        body: serde_json::Value,
    ) -> Result<T, Error> {
        self.send_identity_profile_json_with_idempotency(profile_dir, method, path, body, None)
            .await
    }

    #[cfg(feature = "cli")]
    async fn send_identity_profile_json_with_idempotency<T: DeserializeOwned>(
        &self,
        profile_dir: &Path,
        method: http::Method,
        path: &str,
        body: serde_json::Value,
        idempotency_key: Option<&str>,
    ) -> Result<T, Error> {
        let endpoint = Self::identity_endpoint_from_profile(profile_dir).await?;
        let uri = self.service_url(path);
        let mut request = http::Request::builder().method(method).uri(uri).header(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("application/json"),
        );
        if let Some(idempotency_key) = idempotency_key {
            request = request.header("idempotency-key", idempotency_header(idempotency_key)?);
        }
        let request = request
            .body(dhttp::WndBuf::new(64 * 1024))
            .map_err(|source| Error::DhttpRequest {
                source: std::io::Error::other(source).into(),
            })?;
        let (mut writer, response) = endpoint
            .from_request(request)
            .await
            .context(DhttpRequestSnafu)?;
        let upload = async {
            writer
                .write_all(body.to_string().as_bytes())
                .await
                .map_err(dhttp::Error::from)?;
            writer.shutdown().await.map_err(dhttp::Error::from)
        };
        let (_, response) = tokio::try_join!(upload, response).context(DhttpRequestSnafu)?;
        parse_dhttp_response(response).await
    }

    async fn get_identity<T: DeserializeOwned>(
        &self,
        identity_domain: &str,
        path_and_query: &str,
    ) -> Result<T, Error> {
        let endpoint = Self::identity_endpoint(identity_domain).await?;
        let uri = self.service_url(path_and_query);
        let uri = uri
            .parse::<http::Uri>()
            .map_err(|source| Error::DhttpRequest {
                source: source.into(),
            })?;
        let request = http::Request::builder()
            .uri(uri)
            .body(dhttp::Empty::new())
            .expect("valid request");
        let response = endpoint
            .from_request(request)
            .await
            .context(DhttpRequestSnafu)?;
        parse_dhttp_response(response).await
    }

    pub async fn send_email_verification(&self, email: &str) -> Result<EmailVerifyResponse, Error> {
        let response = self
            .http_client
            .post(self.service_url("/v2/email/verify"))
            .json(&json!({ "email": email }))
            .send()
            .await?;
        parse_response(response).await
    }

    pub async fn inspect_domain_availability(
        &self,
        domain: &str,
    ) -> Result<DomainAvailabilityResponse, Error> {
        let response = self
            .http_client
            .get(self.service_url("/v2/pricing"))
            .query(&[("domain", domain)])
            .send()
            .await?;
        parse_response(response).await
    }

    pub async fn inspect_domain_availability_with_token(
        &self,
        access_token: &str,
        domain: &str,
    ) -> Result<DomainAvailabilityResponse, Error> {
        let response = self
            .http_client
            .get(self.service_url("/v2/pricing"))
            .header(header::AUTHORIZATION, format!("Bearer {access_token}"))
            .query(&[("domain", domain)])
            .send()
            .await?;
        parse_response(response).await
    }

    pub async fn login(&self, email: &str, verify_code: &str) -> Result<LoginResponse, Error> {
        let response = self
            .http_client
            .post(self.service_url("/v2/user/login"))
            .json(&json!({
                "email": email,
                "verify_code": verify_code,
            }))
            .send()
            .await?;
        parse_response(response).await
    }

    pub async fn domain_login(
        &self,
        domain: &str,
        email: &str,
        verify_code: &str,
    ) -> Result<DomainLoginResponse, Error> {
        let response = self
            .http_client
            .post(self.service_url("/v2/user/domain-login"))
            .json(&json!({
                "domain": domain,
                "email": email,
                "verify_code": verify_code,
            }))
            .send()
            .await?;
        parse_response(response).await
    }

    pub async fn create_domain_with_email(
        &self,
        domain: &str,
        email: &str,
        verify_code: &str,
    ) -> Result<CreateDomainResponse, Error> {
        let response = self
            .http_client
            .post(self.service_url("/v2/domain"))
            .json(&CreateDomainRequest::new(
                domain,
                Some(email),
                Some(verify_code),
            ))
            .send()
            .await?;
        parse_create_domain_response(response).await
    }

    pub async fn create_domain_with_token(
        &self,
        access_token: &str,
        domain: &str,
    ) -> Result<CreateDomainResponse, Error> {
        let response = self
            .http_client
            .post(self.service_url("/v2/domain"))
            .header(header::AUTHORIZATION, format!("Bearer {access_token}"))
            .json(&CreateDomainRequest::new(domain, None, None))
            .send()
            .await?;
        parse_create_domain_response(response).await
    }

    pub async fn get_checkout(&self, checkout_token: &str) -> Result<CreateDomainResponse, Error> {
        let response = self
            .http_client
            .get(self.service_url("/v2/checkout"))
            .query(&[("token", checkout_token)])
            .send()
            .await?;
        parse_response(response).await
    }

    pub async fn create_subdomain(
        &self,
        access_token: &str,
        parent: &str,
        label: &str,
        expected_amount: Option<i64>,
    ) -> Result<CreateSubdomainResponse, Error> {
        match self
            .create_subdomain_attempt(access_token, parent, label, expected_amount)
            .await?
        {
            CreateSubdomainAttempt::Created(response) => Ok(response),
            CreateSubdomainAttempt::QuotaExceeded(_) => Err(Error::Api {
                status: reqwest::StatusCode::UNPROCESSABLE_ENTITY,
                code: "1304".to_string(),
                message: user_facing_api_message("1304", "subdomain quota exceeded"),
            }),
        }
    }

    pub async fn create_subdomain_attempt(
        &self,
        access_token: &str,
        parent: &str,
        label: &str,
        expected_amount: Option<i64>,
    ) -> Result<CreateSubdomainAttempt, Error> {
        let response = self
            .http_client
            .post(self.service_url("/v2/subdomain"))
            .header(header::AUTHORIZATION, format!("Bearer {access_token}"))
            .json(&json!({
                "parent": parent,
                "label": label,
                "expected_amount": expected_amount,
            }))
            .send()
            .await?;
        parse_create_subdomain_response(response).await
    }

    pub async fn create_subdomain_with_identity(
        &self,
        identity_domain: &str,
        parent: &str,
        label: &str,
        expected_amount: Option<i64>,
    ) -> Result<CreateSubdomainResponse, Error> {
        self.send_identity_json(
            identity_domain,
            http::Method::POST,
            "/v2/subdomain",
            json!({
                "parent": parent,
                "label": label,
                "expected_amount": expected_amount,
            }),
        )
        .await
    }

    #[cfg(feature = "cli")]
    pub(crate) async fn create_subdomain_with_identity_profile(
        &self,
        profile_dir: &Path,
        parent: &str,
        label: &str,
        expected_amount: Option<i64>,
    ) -> Result<CreateSubdomainResponse, Error> {
        self.send_identity_profile_json(
            profile_dir,
            http::Method::POST,
            "/v2/subdomain",
            json!({
                "parent": parent,
                "label": label,
                "expected_amount": expected_amount,
            }),
        )
        .await
    }

    pub async fn issue_cert(
        &self,
        access_token: &str,
        domain: &str,
        kind: &str,
        sequence: Option<u32>,
        device_name: &str,
        csr_pem: &str,
    ) -> Result<CertificateDetail, Error> {
        let response = self
            .http_client
            .post(self.service_url("/v2/cert"))
            .header(header::AUTHORIZATION, format!("Bearer {access_token}"))
            .json(&json!({
                "domain": domain,
                "kind": kind,
                "sequence": sequence,
                "device_name": device_name,
                "csr": csr_pem,
            }))
            .send()
            .await?;
        parse_response(response).await
    }

    pub async fn get_invoice(
        &self,
        access_token: &str,
        invoice_no: &str,
    ) -> Result<InvoiceDetail, Error> {
        let response = self
            .http_client
            .get(self.service_url("/v2/invoice"))
            .header(header::AUTHORIZATION, format!("Bearer {access_token}"))
            .query(&[("no", invoice_no)])
            .send()
            .await?;
        parse_response(response).await
    }

    pub async fn cancel_reservation(
        &self,
        access_token: &str,
        reservation_no: &str,
    ) -> Result<(), Error> {
        let response = self
            .http_client
            .post(self.service_url("/v2/invoice/cancel"))
            .header(header::AUTHORIZATION, format!("Bearer {access_token}"))
            .json(&json!({ "reservation_no": reservation_no }))
            .send()
            .await?;
        let _: Value = parse_response(response).await?;
        Ok(())
    }

    pub async fn issue_cert_with_identity(
        &self,
        identity_domain: &str,
        domain: &str,
        kind: &str,
        sequence: Option<u32>,
        device_name: &str,
        csr_pem: &str,
    ) -> Result<CertificateDetail, Error> {
        self.send_identity_json(
            identity_domain,
            http::Method::POST,
            "/v2/cert",
            json!({
                "domain": domain,
                "kind": kind,
                "sequence": sequence,
                "device_name": device_name,
                "csr": csr_pem,
            }),
        )
        .await
    }

    #[cfg(feature = "cli")]
    pub(crate) async fn issue_cert_with_identity_profile(
        &self,
        profile_dir: &Path,
        domain: &str,
        kind: &str,
        sequence: Option<u32>,
        device_name: &str,
        csr_pem: &str,
    ) -> Result<CertificateDetail, Error> {
        self.send_identity_profile_json(
            profile_dir,
            http::Method::POST,
            "/v2/cert",
            json!({
                "domain": domain,
                "kind": kind,
                "sequence": sequence,
                "device_name": device_name,
                "csr": csr_pem,
            }),
        )
        .await
    }

    pub async fn renew_cert(
        &self,
        access_token: &str,
        domain: &str,
        kind: &str,
        sequence: u32,
        device_name: Option<&str>,
        csr_pem: &str,
    ) -> Result<CertificateDetail, Error> {
        self.renew_cert_request(
            access_token,
            CertificateRenewalRequest::new(domain, kind, sequence, device_name, csr_pem),
        )
        .await
    }

    pub async fn renew_cert_request(
        &self,
        access_token: &str,
        request: CertificateRenewalRequest<'_>,
    ) -> Result<CertificateDetail, Error> {
        let mut builder = self
            .http_client
            .post(self.service_url("/v2/cert/renew"))
            .header(header::AUTHORIZATION, format!("Bearer {access_token}"));
        if let Some(idempotency_key) = request.idempotency_key {
            builder = builder.header("idempotency-key", idempotency_header(idempotency_key)?);
        }
        parse_response(builder.json(&request.body()).send().await?).await
    }

    pub async fn renew_cert_with_identity(
        &self,
        identity_domain: &str,
        domain: &str,
        kind: &str,
        sequence: u32,
        device_name: Option<&str>,
        csr_pem: &str,
    ) -> Result<CertificateDetail, Error> {
        self.renew_cert_with_identity_request(
            identity_domain,
            CertificateRenewalRequest::new(domain, kind, sequence, device_name, csr_pem),
        )
        .await
    }

    pub async fn renew_cert_with_identity_request(
        &self,
        identity_domain: &str,
        request: CertificateRenewalRequest<'_>,
    ) -> Result<CertificateDetail, Error> {
        let idempotency_key = request.idempotency_key;
        let body = request.body();
        self.send_identity_json_with_idempotency(
            identity_domain,
            http::Method::POST,
            "/v2/cert/renew",
            body,
            idempotency_key,
        )
        .await
    }

    #[cfg(feature = "cli")]
    pub(crate) async fn renew_cert_with_identity_profile_request(
        &self,
        profile_dir: &Path,
        request: CertificateRenewalRequest<'_>,
    ) -> Result<CertificateDetail, Error> {
        let idempotency_key = request.idempotency_key;
        let body = request.body();
        self.send_identity_profile_json_with_idempotency(
            profile_dir,
            http::Method::POST,
            "/v2/cert/renew",
            body,
            idempotency_key,
        )
        .await
    }

    pub async fn list_certs(
        &self,
        access_token: &str,
        domain: &str,
        kind: Option<&str>,
        sequence: Option<u32>,
    ) -> Result<CertificateListPage, Error> {
        let mut request = self
            .http_client
            .get(self.service_url("/v2/cert"))
            .header(header::AUTHORIZATION, format!("Bearer {access_token}"))
            .query(&[("domain", domain)]);
        if let Some(kind) = kind {
            request = request.query(&[("kind", kind)]);
        }
        if let Some(sequence) = sequence {
            request = request.query(&[("sequence", sequence)]);
        }
        let response = request.send().await?;
        parse_response(response).await
    }

    pub async fn list_certs_with_identity(
        &self,
        identity_domain: &str,
        domain: &str,
        kind: Option<&str>,
        sequence: Option<u32>,
    ) -> Result<CertificateListPage, Error> {
        let mut query = format!("/v2/cert?domain={}", urlencoding::encode(domain));
        if let Some(kind) = kind {
            query.push_str("&kind=");
            query.push_str(&urlencoding::encode(kind));
        }
        if let Some(sequence) = sequence {
            query.push_str("&sequence=");
            query.push_str(&sequence.to_string());
        }
        self.get_identity(identity_domain, &query).await
    }

    pub async fn get_cert_detail(
        &self,
        access_token: &str,
        serial_number: &str,
    ) -> Result<CertificateDetail, Error> {
        let response = self
            .http_client
            .get(self.service_url("/v2/cert"))
            .header(header::AUTHORIZATION, format!("Bearer {access_token}"))
            .query(&[("serial_number", serial_number)])
            .send()
            .await?;
        parse_response(response).await
    }

    pub async fn get_cert_detail_with_identity(
        &self,
        identity_domain: &str,
        serial_number: &str,
    ) -> Result<CertificateDetail, Error> {
        let query = format!(
            "/v2/cert?serial_number={}",
            urlencoding::encode(serial_number)
        );
        self.get_identity(identity_domain, &query).await
    }
}

impl Error {
    pub fn identity_fallback_disabled() -> Self {
        Self::IdentityFallbackUnavailable
    }

    pub fn api_code(&self) -> Option<&str> {
        match self {
            Self::Api { code, .. } => Some(normalize_api_code(code)),
            _ => None,
        }
    }

    pub fn is_api_code(&self, expected: &str) -> bool {
        self.api_code() == Some(expected)
    }

    pub fn is_api(&self, expected_status: reqwest::StatusCode, expected_code: &str) -> bool {
        matches!(
            self,
            Self::Api { status, .. }
                if *status == expected_status && self.api_code() == Some(expected_code)
        )
    }
}

async fn init_network(schemes: &[ddns::DnsScheme], binds: &[String]) -> dhttp::Result<()> {
    if binds.iter().any(|bind| bind != "*") {
        return Err(dhttp::Error::InvalidRequest {
            message: "the process-wide DHTTP network currently requires --interface '*'".into(),
        });
    }
    let mdns = ddns::install_resolvers(schemes)?;
    let network = dhttp::DhttpNetwork::init().await?;
    if let Some(mdns) = mdns {
        static MAINTENANCE: tokio::sync::OnceCell<()> = tokio::sync::OnceCell::const_new();
        MAINTENANCE
            .get_or_try_init(|| async {
                mdns.maintain(std::time::Duration::from_secs(1), move || {
                    Ok(network
                        .active_bindings()
                        .map_err(std::io::Error::other)?
                        .into_iter()
                        .filter(|binding| {
                            dhttp::resolve::EndpointAddr::direct(binding.address).scope()
                                == Some(dhttp::Scope::Internal)
                        })
                        .map(|binding| {
                            ddns::mdns::MdnsBinding::new(binding.device, binding.address.ip())
                        })
                        .collect())
                })
                .await?;
                Ok::<(), std::io::Error>(())
            })
            .await?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "../tests/unit/cert_server.rs"]
mod tests;

/// Public evidence for an exact leaf instance. Never substitute a sequence's current leaf.
#[derive(Debug, Clone, Deserialize)]
pub struct SigningCertificateStatus {
    pub domain: String,
    pub purpose: String,
    pub kind: String,
    pub sequence: u32,
    pub ski: Option<String>,
    pub issuer_id: Option<String>,
    pub serial_number: Option<String>,
    pub fingerprint_sha256: String,
    pub cert_pem: String,
    pub valid_not_before: i64,
    pub valid_not_after: i64,
    pub revoked_at: Option<i64>,
    pub checked_at: i64,
    pub revocation_status: String,
    pub issuer_status: String,
    pub publication_allowed: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DeveloperCertificate {
    pub purpose: String,
    #[serde(flatten)]
    pub certificate: CertificateDetail,
}

impl CertServer {
    /// Account-only product APIs intentionally never fall back to a TLS identity.
    pub async fn code_signing_pricing(&self, domain: &str) -> Result<Value, Error> {
        parse_response(
            self.http_client
                .get(self.service_url("/v2/pricing"))
                .query(&[("domain", domain)])
                .send()
                .await?,
        )
        .await
    }

    pub async fn code_signing_subscriptions(
        &self,
        token: &str,
        domain: &str,
    ) -> Result<Value, Error> {
        parse_response(
            self.http_client
                .get(self.service_url("/v2/subscription"))
                .bearer_auth(token)
                .query(&[("product", "code_signing"), ("domain", domain)])
                .send()
                .await?,
        )
        .await
    }

    pub async fn purchase_code_signing(
        &self,
        token: &str,
        domain: &str,
        key: &str,
    ) -> Result<Value, Error> {
        if !(8..=200).contains(&key.len()) || !key.is_ascii() {
            return Err(Error::without_source(
                "Idempotency-Key must contain 8–200 ASCII characters".into(),
            ));
        }
        parse_response(
            self.http_client
                .post(self.service_url("/v2/subscription"))
                .bearer_auth(token)
                .header("Idempotency-Key", idempotency_header(key)?)
                .json(&json!({"domain":domain,"product":"code_signing"}))
                .send()
                .await?,
        )
        .await
    }

    pub async fn set_code_signing_renewal(
        &self,
        token: &str,
        subscription_no: &str,
        auto_renew: bool,
    ) -> Result<Value, Error> {
        parse_response(
            self.http_client
                .patch(self.service_url("/v2/subscription"))
                .bearer_auth(token)
                .json(&json!({"subscription_no":subscription_no,"auto_renew":auto_renew}))
                .send()
                .await?,
        )
        .await
    }

    pub async fn code_signing_certificates(
        &self,
        token: &str,
        domain: &str,
        page: usize,
    ) -> Result<CertificateListPage, Error> {
        parse_response(
            self.http_client
                .get(self.service_url("/v2/cert"))
                .bearer_auth(token)
                .query(&[
                    ("domain", domain),
                    ("purpose", "code_signing"),
                    ("page", &page.to_string()),
                    ("page_size", "100"),
                ])
                .send()
                .await?,
        )
        .await
    }

    pub async fn issue_developer_certificate(
        &self,
        token: &str,
        domain: &str,
        device: &str,
        csr: &str,
    ) -> Result<DeveloperCertificate, Error> {
        parse_response(self.http_client.post(self.service_url("/v2/cert"))
            .bearer_auth(token).json(&json!({"domain":domain,"purpose":"code_signing","kind":"primary","device_name":device,"csr":csr}))
            .send().await?).await
    }

    pub async fn renew_developer_certificate(
        &self,
        token: &str,
        domain: &str,
        sequence: u32,
        csr: &str,
        key: &str,
    ) -> Result<DeveloperCertificate, Error> {
        parse_response(self.http_client.post(self.service_url("/v2/cert/renew"))
            .bearer_auth(token).header("Idempotency-Key",idempotency_header(key)?)
            .json(&json!({"domain":domain,"purpose":"code_signing","kind":"primary","sequence":sequence,"csr":csr}))
            .send().await?).await
    }

    pub async fn revoke_developer_certificate(
        &self,
        token: &str,
        serial: &str,
        issuer: &str,
        whole_sequence: bool,
    ) -> Result<Value, Error> {
        parse_response(self.http_client.post(self.service_url("/v2/cert/revoke"))
            .bearer_auth(token).json(&json!({"serial_number":serial,"issuer_id":issuer,"scope":if whole_sequence {"sequence"} else {"certificate"},"reason_code":0}))
            .send().await?).await
    }

    pub async fn exact_certificate_status(
        &self,
        domain: &str,
        fingerprint: &str,
    ) -> Result<SigningCertificateStatus, Error> {
        parse_response(
            self.http_client
                .get(self.service_url("/v2/cert"))
                .header(header::CACHE_CONTROL, "no-cache, no-store")
                .query(&[("domain", domain), ("fingerprint_sha256", fingerprint)])
                .timeout(std::time::Duration::from_secs(30))
                .send()
                .await?,
        )
        .await
    }
}

impl CertServer {
    pub async fn developer_certificate_detail(
        &self,
        token: &str,
        serial: &str,
    ) -> Result<DeveloperCertificate, Error> {
        parse_response(
            self.http_client
                .get(self.service_url("/v2/cert"))
                .bearer_auth(token)
                .query(&[("serial_number", serial)])
                .send()
                .await?,
        )
        .await
    }
}

#[cfg(test)]
#[path = "../tests/unit/cert_server_developer.rs"]
mod developer_tests;

impl CertServer {
    pub async fn cancel_code_signing_renewal(
        &self,
        token: &str,
        subscription_no: &str,
    ) -> Result<Value, Error> {
        parse_response(
            self.http_client
                .post(self.service_url("/v2/subscription/cancel"))
                .bearer_auth(token)
                .json(&json!({"subscription_no":subscription_no}))
                .send()
                .await?,
        )
        .await
    }
}
