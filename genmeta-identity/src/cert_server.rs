#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(transparent)]
    Request { source: reqwest::Error },
    #[snafu(display(
        "server returned HTTP status code `{status}`{}", 
        if message.is_empty() { String::new() } else { format!(": {message}", ) }
    ))]
    Status {
        status: reqwest::StatusCode,
        message: String,
    },
    #[snafu(display("cert server returned {status} {code}: {message}"))]
    Api {
        status: reqwest::StatusCode,
        code: String,
        message: String,
    },
    #[snafu(display(
        "server returned error code `{code}`{}", 
        message.as_ref().map_or(String::new(), |m| format!(": {}", m))
    ))]
    Code { code: i32, message: Option<String> },
    #[snafu(display("failed to parse JSON response from cert server",))]
    Json { source: serde_json::Error },
    #[snafu(display("server responded with invalid Base64 data `{data:?}`"))]
    Base64 {
        data: Bytes,
        source: base64::DecodeError,
    },
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
}

use std::sync::Arc;

use base64::Engine;
use bytes::Bytes;
use dhttp_identity::name::DhttpName as Name;
use reqwest::header;
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::json;
use snafu::{ResultExt, Snafu, Whatever, whatever};

#[derive(Debug, Deserialize)]
struct Response<T> {
    code: i32,
    #[serde(flatten)]
    body: ResponseBody<T>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum ResponseBody<T> {
    Data { data: T },
    Msg { msg: String },
}

impl<T> Response<T> {
    pub fn body(self) -> Result<T, Error> {
        match self.code {
            0 => match self.body {
                ResponseBody::Data { data } => Ok(data),
                ResponseBody::Msg { msg } => {
                    whatever!("bad response: expected data but got message: {msg}")
                }
            },
            code => {
                let message = match self.body {
                    ResponseBody::Msg { msg } => Some(msg.clone()),
                    _ => None,
                };
                CodeSnafu { code, message }.fail()
            }
        }
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

pub fn parse_error_body(status: reqwest::StatusCode, body: &[u8]) -> Result<(), Error> {
    let parsed = serde_json::from_slice::<ErrorResponse>(body).context(JsonSnafu {})?;
    ApiSnafu {
        status,
        code: parsed.error.code,
        message: parsed.error.message,
    }
    .fail()
}

#[derive(Debug, Deserialize)]
pub struct CheckUsernameResponse {
    pub exists: bool,
}

#[derive(Debug, Deserialize)]
pub struct CheckEmailResponse {
    pub exists: bool,
}

#[derive(Debug, Deserialize)]
pub struct OriginalRegisterResponse {
    pub cert: String,
}

#[derive(Debug)]
pub struct RegisterResponse {
    pub cert_pem: Vec<u8>,
}

#[derive(Debug, Deserialize)]
pub struct LoginResponse {
    pub access_token: String,
    pub domains: Vec<Name<'static>>,
}

#[derive(Debug, Deserialize)]
pub struct OriginalResignResponse {
    pub cert: String,
}

#[derive(Debug)]
pub struct ResignResponse {
    pub cert_pem: Vec<u8>,
}

#[derive(Debug, Deserialize)]
pub struct UserResponse {
    pub id: i64,
    pub name: String,
    pub email: String,
    pub limit_count: i64,
    pub used: i64,
}

#[derive(Debug, Deserialize)]
pub struct OriginalCertInfoResponse {
    pub cert: String,
    pub domain: String,
    pub expire_time: i64,
}

#[derive(Debug)]
pub struct CertInfoResponse {
    pub cert_pem: Vec<u8>,
    pub domain: String,
    pub expire_time: i64,
}

#[derive(Debug, Deserialize)]
pub struct OriginalRenewResponse {
    pub cert: String,
}

#[derive(Debug)]
pub struct RenewResponse {
    pub cert_pem: Vec<u8>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EmailVerifyResponse {
    pub email: String,
    pub expires_at: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct V2LoginResponse {
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
pub struct CertificateDetail {
    pub domain: String,
    pub device_name: Option<String>,
    pub sequence: i32,
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
    pub sequence: i32,
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
    let response = match response.status() {
        status if status.is_success() => response,
        status => {
            let message = response.text().await.unwrap_or_default();
            return StatusSnafu { status, message }.fail();
        }
    };
    let response = response.bytes().await?;
    tracing::debug!("response bytes: {:?}", response);
    let response = serde_json::from_slice::<Response<T>>(&response).context(JsonSnafu {})?;
    response.body()
}

async fn parse_v2_response<T: DeserializeOwned>(response: reqwest::Response) -> Result<T, Error> {
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

#[derive(Debug, Clone)]
pub struct CertServer {
    base_url: Arc<str>,
    http_client: reqwest::Client,
}

impl CertServer {
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

    #[doc(alias = "send_email")]
    pub async fn send_captcha(&self, email: &str) -> Result<(), Error> {
        let response = self
            .http_client
            .post(format!("{}/api/v1/email/send", self.base_url))
            .json(&json!({
                "email": email,
            }))
            .send()
            .await?;
        parse_response::<()>(response).await
    }

    pub async fn send_email_verification(&self, email: &str) -> Result<EmailVerifyResponse, Error> {
        let response = self
            .http_client
            .post(format!("{}/v2/email/verify", self.base_url))
            .json(&json!({ "email": email }))
            .send()
            .await?;
        parse_v2_response(response).await
    }

    pub async fn login_v2(&self, email: &str, verify_code: &str) -> Result<V2LoginResponse, Error> {
        let response = self
            .http_client
            .post(format!("{}/v2/user/login", self.base_url))
            .json(&json!({
                "email": email,
                "verify_code": verify_code,
            }))
            .send()
            .await?;
        parse_v2_response(response).await
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
        parse_v2_response(response).await
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
        parse_v2_response(response).await
    }

    pub async fn login(&self, email: &str, captcha: &str) -> Result<LoginResponse, Error> {
        let response = self
            .http_client
            .post(format!("{}/api/v1/login", self.base_url))
            .json(&json!({
                "email": email,
                "email_captcha": captcha,
            }))
            .send()
            .await?;
        parse_response::<LoginResponse>(response).await
    }

    pub async fn resign_cert(
        &self,
        access_token: &str,
        domain: &str,
        csr_pem: &str,
    ) -> Result<ResignResponse, Error> {
        let response = self
            .http_client
            .post(format!("{}/api/v1/cert/resign", self.base_url))
            .header(header::AUTHORIZATION, access_token)
            .json(&json!({
                "domain": domain,
                "csr": base64::engine::general_purpose::STANDARD.encode(csr_pem),
            }))
            .send()
            .await?;
        let OriginalResignResponse { cert } =
            parse_response::<OriginalResignResponse>(response).await?;

        let cert_pem = base64::engine::general_purpose::STANDARD
            .decode(&cert)
            .context(Base64Snafu { data: cert })?;
        Ok(ResignResponse { cert_pem })
    }

    pub async fn issue_cert(
        &self,
        access_token: &str,
        domain: &str,
        kind: &str,
        sequence: Option<i32>,
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
        parse_v2_response(response).await
    }

    pub async fn renew_cert(
        &self,
        access_token: &str,
        domain: &str,
        csr_pem: &str,
    ) -> Result<RenewResponse, Error> {
        let response = self
            .http_client
            .post(format!("{}/api/v1/cert/renew", self.base_url))
            .header(header::AUTHORIZATION, access_token)
            .json(&json!({
                "domain": domain,
                "csr": base64::engine::general_purpose::STANDARD.encode(csr_pem),
            }))
            .send()
            .await?;
        let OriginalRenewResponse { cert } =
            parse_response::<OriginalRenewResponse>(response).await?;

        let cert_pem = base64::engine::general_purpose::STANDARD
            .decode(&cert)
            .context(Base64Snafu { data: cert })?;
        Ok(RenewResponse { cert_pem })
    }

    pub async fn renew_cert_v2(
        &self,
        access_token: &str,
        domain: &str,
        kind: &str,
        sequence: i32,
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
        parse_v2_response(response).await
    }

    pub async fn list_certs(
        &self,
        access_token: &str,
        domain: &str,
        kind: Option<&str>,
        sequence: Option<i32>,
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
        parse_v2_response(response).await
    }

    pub async fn get_user(&self, access_token: &str) -> Result<UserResponse, Error> {
        let response = self
            .http_client
            .get(format!("{}/api/v1/user", self.base_url))
            .header(header::AUTHORIZATION, access_token)
            .send()
            .await?;
        parse_response::<UserResponse>(response).await
    }

    pub async fn get_cert_by_domain(&self, domain: &str) -> Result<CertInfoResponse, Error> {
        let response = self
            .http_client
            .get(format!("{}/api/v1/cert/{domain}", self.base_url))
            .send()
            .await?;
        let OriginalCertInfoResponse {
            cert,
            domain,
            expire_time,
        } = parse_response::<OriginalCertInfoResponse>(response).await?;

        let cert_pem = base64::engine::general_purpose::STANDARD
            .decode(&cert)
            .context(Base64Snafu { data: cert })?;
        Ok(CertInfoResponse {
            cert_pem,
            domain,
            expire_time,
        })
    }

    pub async fn check_name(&self, username: &str) -> Result<CheckUsernameResponse, Error> {
        let response = self
            .http_client
            .get(format!("{}/api/v1/check/{username}", self.base_url))
            .send()
            .await?;
        parse_response::<CheckUsernameResponse>(response).await
    }

    pub async fn check_email(&self, email: &str) -> Result<CheckEmailResponse, Error> {
        let response = self
            .http_client
            .get(format!("{}/api/v1/check-email/{email}", self.base_url))
            .send()
            .await?;
        parse_response::<CheckEmailResponse>(response).await
    }

    pub async fn register(
        &self,
        username: &str,
        email: &str,
        email_captcha: &str,
        csr_pem: &str,
    ) -> Result<RegisterResponse, Error> {
        let response = self
            .http_client
            .post(format!("{}/api/v1/register", self.base_url))
            .json(&json!({
                "username": username,
                "email": email,
                "email_captcha": email_captcha,
                "csr": base64::engine::general_purpose::STANDARD.encode(csr_pem),
            }))
            .send()
            .await?;
        let OriginalRegisterResponse { cert } =
            parse_response::<OriginalRegisterResponse>(response).await?;

        let cert_pem = base64::engine::general_purpose::STANDARD
            .decode(&cert)
            .context(Base64Snafu { data: cert })?;
        Ok(RegisterResponse { cert_pem })
    }
}
