// TODO: migrate cert_server.rs from reqwest to h3x client

mod bootstrap;

#[cfg(feature = "cli")]
pub mod cli;
#[cfg(feature = "cli")]
pub use cli::{Cli, Error, Options, run, run_listen};

#[cfg(feature = "cli")]
pub mod auth;
pub mod cert_server;
#[cfg(feature = "cli")]
pub mod checkout;
pub mod code_signing;
pub mod local_identity;

/// Render DHTTP identities and links using the trailing tilde shorthand.
pub fn display_identity(name: &str) -> std::borrow::Cow<'_, str> {
    let mut rendered = String::new();
    let mut copied = 0;
    let lowercase = name.to_ascii_lowercase();
    for (start, _) in lowercase.match_indices("dhttp.net") {
        let end = start + "dhttp.net".len();
        if name
            .as_bytes()
            .get(end)
            .is_some_and(|next| next.is_ascii_alphanumeric() || matches!(next, b'.' | b'_' | b'-'))
        {
            continue;
        }
        let begin = match start.checked_sub(1).map(|index| name.as_bytes()[index]) {
            Some(b'.') => start - 1,
            Some(previous)
                if previous.is_ascii_alphanumeric() || matches!(previous, b'_' | b'-') =>
            {
                continue;
            }
            _ => start,
        };
        rendered.push_str(&name[copied..begin]);
        rendered.push('~');
        copied = end;
    }
    if copied == 0 {
        std::borrow::Cow::Borrowed(name)
    } else {
        rendered.push_str(&name[copied..]);
        std::borrow::Cow::Owned(rendered)
    }
}

pub const DEFAULT_DEVICE_NAME: &str = "local device";

pub const DEFAULT_DHTTP_CA_SERVICE: &str = "https://api.genmeta.net";
pub const DHTTP_CA_SERVICE: &str = bootstrap::DHTTP_CA_SERVICE;

#[cfg(test)]
#[path = "../tests/unit/lib.rs"]
mod tests;
