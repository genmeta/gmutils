use std::{path::Path, sync::Arc};

use reqwest::header;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use snafu::{FromString, ResultExt, Snafu, Whatever};

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
    DhttpEndpoint {
        source: dhttp::endpoint::LoadEndpointError<dhttp::name::InvalidDhttpName>,
    },
    #[snafu(display("failed to load DHTTP identity endpoint from selected profile"))]
    DhttpEndpointFromProfile {
        source: dhttp::endpoint::LoadEndpointFromPathError,
    },
    #[snafu(display("failed to send DHTTP identity request"))]
    DhttpRequest {
        source: dhttp::endpoint::client::RequestError,
    },
    #[snafu(display("failed to read DHTTP identity response body"))]
    DhttpRead {
        source: dhttp::message::ReadBufferedBodyError,
    },
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
        "1303" => "subdomain_conflict",
        "1304" => "subdomain_quota_exceeded",
        "1407" => "cert_sequence_not_found",
        _ => code,
    }
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
    let ErrorEnvelope { code, message } = parsed.error;
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
    mut response: dhttp::endpoint::client::Response,
) -> Result<T, Error> {
    let status = response.status();
    let body = response.read_to_bytes().await;
    // Explicitly finish the response stream before dropping it. This avoids
    // noisy dquic drop diagnostics when the server has already sent a body.
    _ = response.stop(dhttp::h3x::error::Code::H3_NO_ERROR).await;
    let body = body.context(DhttpReadSnafu)?;
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
    async fn identity_endpoint(
        identity_domain: &str,
    ) -> Result<Arc<dhttp::endpoint::Endpoint>, Error> {
        let endpoint = dhttp::endpoint::Endpoint::load(identity_domain)
            .await
            .context(DhttpEndpointSnafu)?;
        Ok(Arc::new(endpoint))
    }

    async fn identity_endpoint_from_profile(
        profile_dir: &Path,
    ) -> Result<Arc<dhttp::endpoint::Endpoint>, Error> {
        let endpoint = dhttp::endpoint::Endpoint::load_from(profile_dir)
            .await
            .context(DhttpEndpointFromProfileSnafu)?;
        Ok(Arc::new(endpoint))
    }

    pub fn new(base_url: impl Into<Arc<str>>) -> Result<Self, Whatever> {
        let base_url = base_url.into();
        let base_url =
            reqwest::Url::parse(&base_url).whatever_context("failed to parse cert server URL")?;
        let mut http_url = base_url.clone();
        http_url.set_port(None).map_err(|()| {
            Whatever::without_source("failed to remove port from cert server URL".to_string())
        })?;

        let root_cert = reqwest::Certificate::from_pem(dhttp::trust::DHTTP_ROOT_CA)
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

    fn http_url(&self, path: &str) -> String {
        let mut url = reqwest::Url::parse(&self.base_url)
            .expect("cert server base URL was validated during construction");
        url.set_port(None)
            .expect("cert server base URL should support HTTP routing");
        format!("{}{path}", url.as_str().trim_end_matches('/'))
    }

    fn h3_url(&self, path: &str) -> String {
        format!("{}{path}", self.base_url)
    }

    async fn send_identity_json<T: DeserializeOwned>(
        &self,
        identity_domain: &str,
        method: http::Method,
        path: &str,
        body: serde_json::Value,
    ) -> Result<T, Error> {
        let endpoint = Self::identity_endpoint(identity_domain).await?;
        let uri = self.h3_url(path);
        let response = endpoint
            .new_request()
            .method(method)
            .uri(uri)
            .header(
                http::header::CONTENT_TYPE,
                http::HeaderValue::from_static("application/json"),
            )
            .body(body.to_string())
            .await
            .context(DhttpRequestSnafu)?;
        parse_dhttp_response(response).await
    }

    async fn send_identity_profile_json<T: DeserializeOwned>(
        &self,
        profile_dir: &Path,
        method: http::Method,
        path: &str,
        body: serde_json::Value,
    ) -> Result<T, Error> {
        let endpoint = Self::identity_endpoint_from_profile(profile_dir).await?;
        let uri = self.h3_url(path);
        let response = endpoint
            .new_request()
            .method(method)
            .uri(uri)
            .header(
                http::header::CONTENT_TYPE,
                http::HeaderValue::from_static("application/json"),
            )
            .body(body.to_string())
            .await
            .context(DhttpRequestSnafu)?;
        parse_dhttp_response(response).await
    }

    async fn get_identity<T: DeserializeOwned>(
        &self,
        identity_domain: &str,
        path_and_query: &str,
    ) -> Result<T, Error> {
        let endpoint = Self::identity_endpoint(identity_domain).await?;
        let uri = self.h3_url(path_and_query);
        let response = endpoint.get(uri).await.context(DhttpRequestSnafu)?;
        parse_dhttp_response(response).await
    }

    pub async fn send_email_verification(&self, email: &str) -> Result<EmailVerifyResponse, Error> {
        let response = self
            .http_client
            .post(self.http_url("/v2/email/verify"))
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
            .get(self.http_url("/v2/pricing"))
            .query(&[("domain", domain)])
            .send()
            .await?;
        parse_response(response).await
    }

    pub async fn login(&self, email: &str, verify_code: &str) -> Result<LoginResponse, Error> {
        let response = self
            .http_client
            .post(self.http_url("/v2/user/login"))
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
            .post(self.http_url("/v2/user/domain-login"))
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
            .post(self.http_url("/v2/domain"))
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
            .post(self.http_url("/v2/domain"))
            .header(header::AUTHORIZATION, format!("Bearer {access_token}"))
            .json(&CreateDomainRequest::new(domain, None, None))
            .send()
            .await?;
        parse_create_domain_response(response).await
    }

    pub async fn get_checkout(&self, checkout_token: &str) -> Result<CreateDomainResponse, Error> {
        let response = self
            .http_client
            .get(self.http_url("/v2/checkout"))
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
            .post(self.http_url("/v2/subdomain"))
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
            .post(self.http_url("/v2/cert"))
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
            .get(self.http_url("/v2/invoice"))
            .header(header::AUTHORIZATION, format!("Bearer {access_token}"))
            .query(&[("no", invoice_no)])
            .send()
            .await?;
        parse_response(response).await
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
        let response = self
            .http_client
            .post(self.http_url("/v2/cert/renew"))
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

    pub async fn renew_cert_with_identity(
        &self,
        identity_domain: &str,
        domain: &str,
        kind: &str,
        sequence: u32,
        device_name: Option<&str>,
        csr_pem: &str,
    ) -> Result<CertificateDetail, Error> {
        self.send_identity_json(
            identity_domain,
            http::Method::POST,
            "/v2/cert/renew",
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

    pub(crate) async fn renew_cert_with_identity_profile(
        &self,
        profile_dir: &Path,
        domain: &str,
        kind: &str,
        sequence: u32,
        device_name: Option<&str>,
        csr_pem: &str,
    ) -> Result<CertificateDetail, Error> {
        self.send_identity_profile_json(
            profile_dir,
            http::Method::POST,
            "/v2/cert/renew",
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

    pub async fn list_certs(
        &self,
        access_token: &str,
        domain: &str,
        kind: Option<&str>,
        sequence: Option<u32>,
    ) -> Result<CertificateListPage, Error> {
        let mut request = self
            .http_client
            .get(self.http_url("/v2/cert"))
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
            .get(self.http_url("/v2/cert"))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_configured_h3_port_and_uses_https_default_port_for_tcp() {
        let configured = CertServer::new("https://api.genmeta.net:4433").unwrap();
        assert_eq!(
            configured.http_url("/v2/cert"),
            "https://api.genmeta.net/v2/cert"
        );
        assert_eq!(
            configured.h3_url("/v2/cert"),
            "https://api.genmeta.net:4433/v2/cert"
        );

        let custom_port = CertServer::new("https://api.example.test:8443").unwrap();
        assert_eq!(
            custom_port.http_url("/v2/cert"),
            "https://api.example.test/v2/cert"
        );
        assert_eq!(
            custom_port.h3_url("/v2/cert"),
            "https://api.example.test:8443/v2/cert"
        );

        let no_port = CertServer::new("https://api.example.test").unwrap();
        assert_eq!(
            no_port.http_url("/v2/cert"),
            "https://api.example.test/v2/cert"
        );
        assert_eq!(
            no_port.h3_url("/v2/cert"),
            "https://api.example.test/v2/cert"
        );
    }

    #[test]
    fn parses_v2_error_envelope() {
        let payload =
            br#"{"error":{"code":"domain_forbidden","message":"domain access is forbidden"}}"#;
        let error = parse_error_body(reqwest::StatusCode::FORBIDDEN, payload).unwrap_err();
        match error {
            Error::Api {
                status,
                code,
                message,
            } => {
                assert_eq!(status, reqwest::StatusCode::FORBIDDEN);
                assert_eq!(code, "domain_forbidden");
                assert_eq!(message, "domain access is forbidden");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn api_code_helpers_match_api_errors() {
        let error = Error::Api {
            status: reqwest::StatusCode::CONFLICT,
            code: "starter_domain_limit_reached".to_string(),
            message: "starter plan is limited to 3 free domains per account".to_string(),
        };

        assert_eq!(error.api_code(), Some("starter_domain_limit_reached"));
        assert!(error.is_api_code("starter_domain_limit_reached"));
        assert!(!error.is_api_code("domain_not_found"));
        assert!(error.is_api(
            reqwest::StatusCode::CONFLICT,
            "starter_domain_limit_reached"
        ));
        assert!(!error.is_api(
            reqwest::StatusCode::INTERNAL_SERVER_ERROR,
            "starter_domain_limit_reached"
        ));
    }

    #[test]
    fn api_error_displays_the_certserver_problem_message_verbatim() {
        let error = Error::Api {
            status: reqwest::StatusCode::FORBIDDEN,
            code: "domain_forbidden".to_string(),
            message: "domain access is forbidden".to_string(),
        };

        assert_eq!(error.to_string(), "domain access is forbidden");
    }

    #[test]
    fn parses_numeric_v2_error_code_and_preserves_the_wire_value() {
        let payload = br#"{"error":{"code":1101,"message":"The email address is invalid."}}"#;
        let error = parse_error_body(reqwest::StatusCode::BAD_REQUEST, payload).unwrap_err();

        assert_eq!(error.api_code(), Some("email_invalid"));
        assert_eq!(error.to_string(), "The email address is invalid.");
        match error {
            Error::Api { code, .. } => assert_eq!(code, "1101"),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn unknown_numeric_error_code_remains_decimal() {
        let payload = br#"{"error":{"code":2999,"message":"future problem"}}"#;
        let error = parse_error_body(reqwest::StatusCode::CONFLICT, payload).unwrap_err();

        assert_eq!(error.api_code(), Some("2999"));
        assert_eq!(error.to_string(), "future problem");
    }

    #[test]
    fn subdomain_quota_error_explains_how_to_add_seats() {
        let payload = br#"{"error":{"code":1304,"message":"The parent name has no available sub-identity slots."}}"#;
        let error =
            parse_error_body(reqwest::StatusCode::UNPROCESSABLE_ENTITY, payload).unwrap_err();

        assert_eq!(
            error.to_string(),
            "The parent identity has reached its sub-identity seat limit. Update your subscription plan to add more seats, then try again."
        );
    }

    #[test]
    fn malformed_error_code_stays_a_json_response_error() {
        let payload = br#"{"error":{"code":true,"message":"invalid envelope"}}"#;
        assert!(matches!(
            parse_error_body(reqwest::StatusCode::BAD_REQUEST, payload),
            Err(Error::Json { .. })
        ));
    }

    #[test]
    fn domain_availability_response_reads_pricing_envelope() {
        let payload = r#"
        {
          "domain":"alice.smith.dhttp.net",
          "availability":"conflict",
          "currency":"USD",
          "prices":[
            {"interval":"monthly","amount":500},
            {"interval":"yearly","amount":3000,"discount":0.5}
          ]
        }
        "#;
        let response: DomainAvailabilityResponse = serde_json::from_str(payload).unwrap();
        assert_eq!(response.domain, "alice.smith.dhttp.net");
        assert_eq!(response.availability, "conflict");
        assert_eq!(response.currency, "USD");
        assert_eq!(response.monthly_amount(), Some(500));
        assert_eq!(response.yearly_amount(), Some(3000));
        assert!(!response.is_free());
    }

    #[test]
    fn domain_registration_requests_disable_implicit_auto_renewal() {
        let token_request = serde_json::to_value(CreateDomainRequest::new(
            "alice.smith.dhttp.net",
            None,
            None,
        ))
        .unwrap();
        let email_request = serde_json::to_value(CreateDomainRequest::new(
            "alice.smith.dhttp.net",
            Some("alice@example.test"),
            Some("123456"),
        ))
        .unwrap();

        assert_eq!(token_request["auto_renew"], false);
        assert!(token_request.get("email").is_none());
        assert!(token_request.get("verify_code").is_none());
        assert_eq!(email_request["auto_renew"], false);
        assert_eq!(email_request["email"], "alice@example.test");
        assert_eq!(email_request["verify_code"], "123456");
    }

    #[test]
    fn create_domain_response_accepts_payment_payload() {
        let payload = r#"
        {
          "domain":"alice.smith.dhttp.net",
          "quotes":{"currency":"USD","monthly":9900,"yearly":99000,"default_billing_cycle":"yearly"},
          "reservation":{"reservation_no":"RSV123","status":"reserved","expires_at":1760001800},
          "payment_entry":{"url":"https://dhttp.net/checkout/ckt_123","checkout_token":"ckt_123","expires_at":1760000300},
          "next_action":"payment",
          "auth":{"email":"alice@example.com","is_new_user":true,"access_token":"token","token_expires_at":1760090000}
        }
        "#;
        let response: CreateDomainResponse = serde_json::from_str(payload).unwrap();
        assert_eq!(response.domain, "alice.smith.dhttp.net");
        assert_eq!(response.next_action, "payment");
        assert_eq!(response.payment_entry.unwrap().checkout_token, "ckt_123");
        assert_eq!(response.auth.unwrap().access_token, "token");
    }

    #[test]
    fn subdomain_quota_error_details_are_parsed() {
        let payload = br#"{
          "error": {
            "code": 1304,
            "message": "subdomain quota exceeded",
            "details": {
              "domain": "phone.alice.smith.dhttp.net",
              "quota_quote": {
                "due": 500,
                "currency": "USD",
                "days_left": 120,
                "days_total": 365,
                "renewal": 1200
              }
            }
          }
        }"#;

        assert_eq!(
            parse_subdomain_quota_quote(reqwest::StatusCode::UNPROCESSABLE_ENTITY, payload)
                .unwrap(),
            Some(SubdomainQuotaQuote {
                domain: "phone.alice.smith.dhttp.net".to_string(),
                due: 500,
                currency: "USD".to_string(),
                days_left: 120,
                days_total: 365,
                renewal: 1200,
            })
        );
    }

    #[test]
    fn subdomain_quota_error_details_accept_missing_term_fields() {
        let payload = br#"{
          "error": {
            "code": "subdomain_quota_exceeded",
            "message": "subdomain quota exceeded",
            "details": {
              "domain": "phone.alice.smith.dhttp.net",
              "quota_quote": {
                "due": 500,
                "currency": "USD"
              }
            }
          }
        }"#;

        assert_eq!(
            parse_subdomain_quota_quote(reqwest::StatusCode::UNPROCESSABLE_ENTITY, payload)
                .unwrap(),
            Some(SubdomainQuotaQuote {
                domain: "phone.alice.smith.dhttp.net".to_string(),
                due: 500,
                currency: "USD".to_string(),
                days_left: 0,
                days_total: 0,
                renewal: 0,
            })
        );
    }

    #[test]
    fn subdomain_quota_error_details_accept_flat_quote_fields() {
        let payload = br#"{
          "error": {
            "code": "subdomain_quota_exceeded",
            "message": "subdomain quota exceeded",
            "details": {
              "domain": "phone.alice.smith.dhttp.net",
              "due": 500,
              "currency": "USD"
            }
          }
        }"#;

        assert_eq!(
            parse_subdomain_quota_quote(reqwest::StatusCode::UNPROCESSABLE_ENTITY, payload)
                .unwrap(),
            Some(SubdomainQuotaQuote {
                domain: "phone.alice.smith.dhttp.net".to_string(),
                due: 500,
                currency: "USD".to_string(),
                days_left: 0,
                days_total: 0,
                renewal: 0,
            })
        );
    }
}
