use http::{HeaderMap, Method, StatusCode, Uri, header::LOCATION};
use snafu::ResultExt;

use crate::error::{self, Error};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RedirectTarget {
    pub(crate) uri: Uri,
    pub(crate) method: Method,
    pub(crate) switched_to_get: bool,
}

pub(crate) fn resolve_redirect(
    status: StatusCode,
    headers: &HeaderMap,
    current_uri: &Uri,
    current_method: &Method,
) -> Result<Option<RedirectTarget>, Error> {
    let Some(location) = headers.get(LOCATION) else {
        return Ok(None);
    };
    let location_str = location.to_str().unwrap_or("");
    let base_url =
        url::Url::parse(&current_uri.to_string()).context(error::ParseRedirectUrlSnafu {
            url: current_uri.to_string(),
        })?;
    let resolved = base_url
        .join(location_str)
        .context(error::ParseRedirectUrlSnafu {
            url: location_str.to_string(),
        })?;
    let uri: Uri = resolved
        .as_str()
        .parse()
        .context(error::InvalidRedirectLocationSnafu)?;
    let switched_to_get = matches!(
        status,
        StatusCode::MOVED_PERMANENTLY | StatusCode::FOUND | StatusCode::SEE_OTHER
    );
    let method = if switched_to_get {
        Method::GET
    } else {
        current_method.clone()
    };
    Ok(Some(RedirectTarget {
        uri,
        method,
        switched_to_get,
    }))
}

#[cfg(test)]
mod tests {
    use http::{HeaderMap, Method, StatusCode, Uri, header::LOCATION};

    use crate::redirect::resolve_redirect;

    #[test]
    fn see_other_switches_to_get() {
        let mut headers = HeaderMap::new();
        headers.insert(LOCATION, "/next".parse().unwrap());
        let current: Uri = "https://example.dhttp.net/start".parse().unwrap();
        let redirect = resolve_redirect(StatusCode::SEE_OTHER, &headers, &current, &Method::POST)
            .unwrap()
            .unwrap();
        assert_eq!(redirect.uri.to_string(), "https://example.dhttp.net/next");
        assert_eq!(redirect.method, Method::GET);
    }

    #[test]
    fn temporary_redirect_keeps_method() {
        let mut headers = HeaderMap::new();
        headers.insert(LOCATION, "/next".parse().unwrap());
        let current: Uri = "https://example.dhttp.net/start".parse().unwrap();
        let redirect = resolve_redirect(
            StatusCode::TEMPORARY_REDIRECT,
            &headers,
            &current,
            &Method::PUT,
        )
        .unwrap()
        .unwrap();
        assert_eq!(redirect.method, Method::PUT);
    }
}
