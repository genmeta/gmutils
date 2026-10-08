use http::{Uri, uri::Authority};
use snafu::{ResultExt, Snafu};
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum IntoAuthorityError {
    #[snafu(display("failed to parse authority"))]
    Parse { source: http::uri::InvalidUri },
    #[snafu(display("failed to expand dhttp shorthand in authority"))]
    Expand {
        source: crate::name::ExpandAuthorityError,
    },
}

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum IntoUriError {
    #[snafu(display("failed to parse uri"))]
    Parse { source: http::uri::InvalidUri },
    #[snafu(display("failed to normalize uri authority"))]
    Authority { source: IntoAuthorityError },
    #[snafu(display("failed to reconstruct uri"))]
    Reconstruct { source: http::uri::InvalidUriParts },
}

/// Converts common authority input types into a normalized [`http::uri::Authority`].
pub trait IntoAuthority {
    fn into_authority(
        self,
        self_name: Option<&crate::name::DhttpName<'_>>,
    ) -> Result<Authority, IntoAuthorityError>;
}

/// Converts common URI input types into a normalized [`http::Uri`].
pub trait IntoUri {
    fn into_uri(self, self_name: Option<&crate::name::DhttpName<'_>>) -> Result<Uri, IntoUriError>;
}

impl IntoAuthority for Authority {
    fn into_authority(
        self,
        self_name: Option<&crate::name::DhttpName<'_>>,
    ) -> Result<Authority, IntoAuthorityError> {
        crate::name::DhttpName::expand_authority_with_base(self_name, self)
            .context(into_authority_error::ExpandSnafu)
    }
}

impl IntoAuthority for &Authority {
    fn into_authority(
        self,
        self_name: Option<&crate::name::DhttpName<'_>>,
    ) -> Result<Authority, IntoAuthorityError> {
        self.clone().into_authority(self_name)
    }
}

impl IntoAuthority for &str {
    fn into_authority(
        self,
        self_name: Option<&crate::name::DhttpName<'_>>,
    ) -> Result<Authority, IntoAuthorityError> {
        Authority::try_from(self)
            .context(into_authority_error::ParseSnafu)?
            .into_authority(self_name)
    }
}

impl IntoAuthority for String {
    fn into_authority(
        self,
        self_name: Option<&crate::name::DhttpName<'_>>,
    ) -> Result<Authority, IntoAuthorityError> {
        Authority::try_from(self)
            .context(into_authority_error::ParseSnafu)?
            .into_authority(self_name)
    }
}

impl IntoAuthority for &String {
    fn into_authority(
        self,
        self_name: Option<&crate::name::DhttpName<'_>>,
    ) -> Result<Authority, IntoAuthorityError> {
        self.as_str().into_authority(self_name)
    }
}

impl IntoUri for Uri {
    fn into_uri(self, self_name: Option<&crate::name::DhttpName<'_>>) -> Result<Uri, IntoUriError> {
        let mut parts = self.into_parts();
        if let Some(authority) = parts.authority {
            let authority = authority
                .into_authority(self_name)
                .context(into_uri_error::AuthoritySnafu)?;
            parts.authority = Some(authority);
        }
        Uri::from_parts(parts).context(into_uri_error::ReconstructSnafu)
    }
}

impl IntoUri for &Uri {
    fn into_uri(self, self_name: Option<&crate::name::DhttpName<'_>>) -> Result<Uri, IntoUriError> {
        self.clone().into_uri(self_name)
    }
}

impl IntoUri for &str {
    fn into_uri(self, self_name: Option<&crate::name::DhttpName<'_>>) -> Result<Uri, IntoUriError> {
        Uri::try_from(self)
            .context(into_uri_error::ParseSnafu)?
            .into_uri(self_name)
    }
}

impl IntoUri for String {
    fn into_uri(self, self_name: Option<&crate::name::DhttpName<'_>>) -> Result<Uri, IntoUriError> {
        Uri::try_from(self)
            .context(into_uri_error::ParseSnafu)?
            .into_uri(self_name)
    }
}

impl IntoUri for &String {
    fn into_uri(self, self_name: Option<&crate::name::DhttpName<'_>>) -> Result<Uri, IntoUriError> {
        self.as_str().into_uri(self_name)
    }
}

impl IntoUri for &[u8] {
    fn into_uri(self, self_name: Option<&crate::name::DhttpName<'_>>) -> Result<Uri, IntoUriError> {
        Uri::try_from(self)
            .context(into_uri_error::ParseSnafu)?
            .into_uri(self_name)
    }
}

impl IntoUri for Vec<u8> {
    fn into_uri(self, self_name: Option<&crate::name::DhttpName<'_>>) -> Result<Uri, IntoUriError> {
        Uri::try_from(self)
            .context(into_uri_error::ParseSnafu)?
            .into_uri(self_name)
    }
}
