use std::{collections::BTreeMap, str::FromStr};

use http::{Request, Response, StatusCode, Uri, uri::Authority};
use serde::Deserialize;
use serde_json::{Value, json};
use snafu::ResultExt;

use crate::{
    Error,
    cli::{Command, PathOperation},
    error,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Method {
    Unspecified,
    Specified(http::Method),
}
impl FromStr for Method {
    type Err = std::io::Error;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value == "*" {
            return Ok(Self::Unspecified);
        }
        if value.bytes().any(|byte| byte.is_ascii_lowercase()) {
            return Err(std::io::Error::other("HTTP method must be uppercase or *"));
        }
        http::Method::from_bytes(value.as_bytes())
            .map(Self::Specified)
            .map_err(std::io::Error::other)
    }
}
impl Method {
    fn as_str(&self) -> &str {
        match self {
            Self::Unspecified => "*",
            Self::Specified(method) => method.as_str(),
        }
    }
}
#[derive(Clone, Copy, Debug)]
pub(crate) enum Effect {
    Allow,
    Deny,
    Review,
}
impl Effect {
    fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::Review => "review",
        }
    }
}

// Wire DTOs are client-side types; the daccess service owns database and policy state.
#[derive(Debug, Deserialize)]
struct Effects {
    allow: Vec<String>,
    review: Vec<String>,
    deny: Vec<String>,
}
type RulesByMethod = BTreeMap<String, Effects>;
type RulesByApi = BTreeMap<String, RulesByMethod>;

pub(crate) trait Transport {
    async fn send(&self, request: Request<Vec<u8>>) -> Result<Response<Vec<u8>>, Error>;
}

struct Api<'a, T> {
    transport: &'a T,
    server: &'a Authority,
}
impl<T: Transport> Api<'_, T> {
    async fn request(
        &self,
        method: http::Method,
        path: &str,
        body: Option<Value>,
        expected: StatusCode,
    ) -> Result<Vec<u8>, Error> {
        let uri = Uri::builder()
            .scheme("https")
            .authority(self.server.clone())
            .path_and_query(path)
            .build()
            .context(error::RequestUriSnafu)?;
        let mut request = Request::new(match body {
            Some(body) => serde_json::to_vec(&body).context(error::JsonSnafu)?,
            None => Vec::new(),
        });
        *request.method_mut() = method;
        *request.uri_mut() = uri;
        request.headers_mut().insert(
            http::header::ACCEPT,
            http::HeaderValue::from_static("application/json"),
        );
        if !request.body().is_empty() {
            request.headers_mut().insert(
                http::header::CONTENT_TYPE,
                http::HeaderValue::from_static("application/json"),
            );
        }
        let response = self.transport.send(request).await?;
        let status = response.status();
        let body = response.into_body();
        if status != expected {
            return Err(Error::Api {
                status,
                path: path.to_owned(),
                message: if status == StatusCode::ACCEPTED {
                    format!(
                        "request is pending approval; the operation has not completed: {}",
                        String::from_utf8_lossy(&body)
                    )
                } else {
                    String::from_utf8_lossy(&body).into_owned()
                },
            });
        }
        Ok(body)
    }
    async fn all_rules(&self) -> Result<RulesByApi, Error> {
        let body = self
            .request(http::Method::GET, "/std/acl/access", None, StatusCode::OK)
            .await?;
        serde_json::from_slice(&body).context(error::JsonSnafu)
    }
    async fn path_rules(&self, path: &str) -> Result<RulesByMethod, Error> {
        let body = self
            .request(http::Method::GET, &access_path(path), None, StatusCode::OK)
            .await?;
        serde_json::from_slice(&body).context(error::JsonSnafu)
    }
    async fn remove(&self, path: &str, method: &str, grantee: &str) -> Result<(), Error> {
        self.request(
            http::Method::DELETE,
            &format!("/std/acl/allow/{}", urlencoding::encode(grantee)),
            Some(json!({ "method": method, "api": path })),
            StatusCode::NO_CONTENT,
        )
        .await?;
        Ok(())
    }
    async fn clear(&self, path: &str, method: Option<&Method>) -> Result<(), Error> {
        let rules = self.path_rules(path).await?;
        for (rule_method, effects) in rules {
            if method.is_some_and(|method| method.as_str() != rule_method) {
                continue;
            }
            for grantee in effects
                .allow
                .into_iter()
                .chain(effects.review)
                .chain(effects.deny)
            {
                self.remove(path, &rule_method, &grantee).await?;
            }
        }
        Ok(())
    }
}

fn access_path(path: &str) -> String {
    // An encoded slash supplies a nonempty wildcard route for the root API.
    let suffix = if path == "/" {
        "%2F".into()
    } else {
        urlencoding::encode(&path[1..]).into_owned()
    };
    format!("/std/acl/access/{suffix}")
}

fn render(rules: RulesByApi, method: Option<&Method>, wide: bool) -> String {
    let mut output = String::new();
    for (path, methods) in rules {
        let mut displayed = false;
        for (rule_method, effects) in methods {
            if method.is_some_and(|method| method.as_str() != rule_method) {
                continue;
            }
            for (effect, names) in [
                ("allow", effects.allow),
                ("review", effects.review),
                ("deny", effects.deny),
            ] {
                for grantee in names {
                    if wide {
                        output.push_str(&format!("{path}\t{rule_method}\t{effect} {grantee}\n"));
                    }
                    displayed = true;
                }
            }
        }
        if !wide && displayed {
            output.push_str(&format!("{path}\n"));
        }
    }
    output
}

pub(crate) async fn execute<T: Transport>(
    transport: &T,
    server: &Authority,
    command: Command,
) -> Result<String, Error> {
    let api = Api { transport, server };
    match command {
        Command::Print { output } => return Ok(output),
        Command::List { wide, method } => {
            return Ok(render(api.all_rules().await?, method.as_ref(), wide));
        }
        Command::RemovePaths { paths, method } => {
            for path in paths {
                api.clear(&path, method.as_ref()).await?;
            }
        }
        Command::Path {
            path,
            method,
            operation,
        } => match operation {
            PathOperation::List => {
                return Ok(render(
                    BTreeMap::from([(path.clone(), api.path_rules(&path).await?)]),
                    method.as_ref(),
                    true,
                ));
            }
            PathOperation::Set { effect, grantee } => {
                api.request(
                    http::Method::POST,
                    &access_path(&path),
                    Some(json!({
                        "method": method.unwrap_or(Method::Unspecified).as_str(),
                        "effect": effect.as_str(), "grantee": grantee,
                    })),
                    StatusCode::NO_CONTENT,
                )
                .await?;
            }
            PathOperation::Clear | PathOperation::Remove { all: true, .. } => {
                api.clear(&path, method.as_ref()).await?
            }
            PathOperation::Remove { grantees, .. } => {
                let method = method.unwrap_or(Method::Unspecified);
                for grantee in grantees {
                    api.remove(&path, method.as_str(), &grantee).await?;
                }
            }
        },
    }
    Ok(String::new())
}

#[cfg(test)]
mod tests;
