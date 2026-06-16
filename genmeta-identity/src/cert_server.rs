use std::sync::Arc;

use reqwest::header;
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::json;
use snafu::{FromString, ResultExt, Snafu, Whatever};

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(transparent)]
    Request { source: reqwest::Error },
    #[snafu(display("cert server returned {status} {code}: {message}"))]
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
    code: String,
    message: String,
}

#[derive(Debug, Deserialize)]
struct DetailedErrorResponse<T> {
    error: DetailedErrorEnvelope<T>,
}

#[derive(Debug, Deserialize)]
struct DetailedErrorEnvelope<T> {
    code: String,
    message: String,
    details: T,
}

#[derive(Debug, Deserialize)]
struct SubdomainQuotaQuoteDetailsEnvelope {
    domain: String,
    quota_quote: SubdomainQuotaQuoteDetails,
}

#[derive(Debug, Deserialize)]
struct SubdomainQuotaQuoteDetails {
    due: i64,
    currency: String,
    days_left: i64,
    days_total: i64,
    renewal: i64,
}

fn parse_subdomain_quota_quote(
    status: reqwest::StatusCode,
    body: &[u8],
) -> Result<Option<SubdomainQuotaQuote>, Error> {
    if status != reqwest::StatusCode::UNPROCESSABLE_ENTITY {
        return Ok(None);
    }

    let Ok(parsed) =
        serde_json::from_slice::<DetailedErrorResponse<SubdomainQuotaQuoteDetailsEnvelope>>(body)
    else {
        return Ok(None);
    };
    if parsed.error.code != "subdomain_quota_exceeded" {
        return Ok(None);
    }
    let _ = &parsed.error.message;

    Ok(Some(SubdomainQuotaQuote {
        domain: parsed.error.details.domain,
        due: parsed.error.details.quota_quote.due,
        currency: parsed.error.details.quota_quote.currency,
        days_left: parsed.error.details.quota_quote.days_left,
        days_total: parsed.error.details.quota_quote.days_total,
        renewal: parsed.error.details.quota_quote.renewal,
    }))
}

pub fn parse_error_body(status: reqwest::StatusCode, body: &[u8]) -> Result<(), Error> {
    let parsed = serde_json::from_slice::<ErrorResponse>(body).context(JsonSnafu {})?;
    ApiSnafu {
        status,
        code: parsed.error.code,
        message: parsed.error.message,
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
    let body = response.read_to_bytes().await.context(DhttpReadSnafu)?;
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

    pub fn new(base_url: impl Into<Arc<str>>) -> Result<Self, Whatever> {
        let root_cert = reqwest::Certificate::from_pem(dhttp::trust::DHTTP_ROOT_CA)
            .whatever_context("failed to parse DHTTP root certificate")?;
        let http_client = reqwest::Client::builder()
            .tls_certs_merge([root_cert])
            .gzip(true)
            .zstd(true)
            .build()
            .whatever_context("failed to build HTTP client")?;
        Ok(Self {
            base_url: base_url.into(),
            http_client,
        })
    }

    async fn send_identity_json<T: DeserializeOwned>(
        &self,
        identity_domain: &str,
        method: http::Method,
        path: &str,
        body: serde_json::Value,
    ) -> Result<T, Error> {
        let endpoint = Self::identity_endpoint(identity_domain).await?;
        let uri = format!("{}{}", self.base_url, path);
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
        let uri = format!("{}{}", self.base_url, path_and_query);
        let response = endpoint.get(uri).await.context(DhttpRequestSnafu)?;
        parse_dhttp_response(response).await
    }

    pub async fn send_email_verification(&self, email: &str) -> Result<EmailVerifyResponse, Error> {
        let response = self
            .http_client
            .post(format!("{}/v2/email/verify", self.base_url))
            .json(&json!({ "email": email }))
            .send()
            .await?;
        parse_response(response).await
    }

    pub async fn login(&self, email: &str, verify_code: &str) -> Result<LoginResponse, Error> {
        let response = self
            .http_client
            .post(format!("{}/v2/user/login", self.base_url))
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
            .post(format!("{}/v2/user/domain-login", self.base_url))
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
            .post(format!("{}/v2/domain", self.base_url))
            .json(&json!({
                "domain": domain,
                "email": email,
                "verify_code": verify_code,
                "redirect_mode": "payment_required",
                "terms_accepted": true,
                "terms_version": "v1",
            }))
            .send()
            .await?;
        parse_create_domain_response(response).await
    }

    pub async fn get_checkout(&self, checkout_token: &str) -> Result<CreateDomainResponse, Error> {
        let response = self
            .http_client
            .get(format!("{}/v2/checkout", self.base_url))
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
            CreateSubdomainAttempt::QuotaExceeded(quote) => Err(Whatever::without_source(
                format!(
                    "creating {} requires interactive checkout to add one more sub-identity slot under {} ({})",
                    quote.domain, parent, quote.currency
                ),
            )
            .into()),
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
            .post(format!("{}/v2/subdomain", self.base_url))
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
            .post(format!("{}/v2/cert", self.base_url))
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
            .get(format!("{}/v2/invoice", self.base_url))
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
            .post(format!("{}/v2/cert/renew", self.base_url))
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

    pub async fn list_certs(
        &self,
        access_token: &str,
        domain: &str,
        kind: Option<&str>,
        sequence: Option<u32>,
    ) -> Result<CertificateListPage, Error> {
        let mut request = self
            .http_client
            .get(format!("{}/v2/cert", self.base_url))
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
            .get(format!("{}/v2/cert", self.base_url))
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
}

#[cfg(test)]
mod tests {
    use super::*;

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
            "code": "subdomain_quota_exceeded",
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
}
