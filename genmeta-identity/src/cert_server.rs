#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(transparent)]
    Request { source: reqwest::Error },
    #[snafu(display(
        "HTTP Status Code {status}{}", 
        if message.is_empty() { String::new() } else { format!(": {message}", ) }
    ))]
    Status {
        status: reqwest::StatusCode,
        message: String,
    },
    #[snafu(display(
        "Code {code}{}", 
        message.as_ref().map_or(String::new(), |m| format!(": {}", m))
    ))]
    Code { code: i32, message: Option<String> },
    #[snafu(display("failed to parse JSON response from cert server",))]
    Json { source: serde_json::Error },
    #[snafu(display("server responded invalid Base64 data {data:?}",))]
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

use std::sync::Arc;

use base64::Engine;
use bytes::Bytes;
use genmeta_home::identity::Name;
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

async fn parse_response<T: DeserializeOwned>(response: reqwest::Response) -> Result<T, Error> {
    let response = match response.status() {
        status if status.is_success() => response,
        status => {
            let message = response.text().await.unwrap_or_default();
            return StatusSnafu { status, message }.fail();
        }
    };
    let response = response.bytes().await?;
    tracing::debug!("Response bytes: {:?}", response);
    let response = serde_json::from_slice::<Response<T>>(&response).context(JsonSnafu {})?;
    response.body()
}

#[derive(Debug, Clone)]
pub struct CertServer {
    base_url: Arc<str>,
    http_client: reqwest::Client,
}

impl CertServer {
    pub fn new(base_url: impl Into<Arc<str>>) -> Result<Self, Whatever> {
        let http_client = reqwest::Client::builder()
            // .tls_certs_only(reqwest::Certificate::from_pem(include_bytes!(
            //     "../root.crt"
            // )))
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
