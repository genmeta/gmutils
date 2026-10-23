//! Abbreviations for CLI output; protocol values keep their canonical names.
use std::borrow::Cow;

use serde_json::Value;

pub(super) fn identity(name: &str) -> Cow<'_, str> {
    match name.strip_suffix(dhttp_home::DHTTP_SUFFIX) {
        Some(short) if !short.is_empty() => Cow::Owned(format!("{short}~")),
        _ => Cow::Borrowed(name),
    }
}

pub(super) fn publisher(name: &str) -> Cow<'_, str> {
    if name == "std.dhttp.net" {
        Cow::Borrowed("std")
    } else {
        identity(name)
    }
}

pub(super) fn package_id(id: &str) -> Cow<'_, str> {
    match id.split_once('/') {
        Some((author, name)) => Cow::Owned(format!("{}/{name}", publisher(author))),
        None => Cow::Borrowed(id),
    }
}

fn url(value: &str) -> Cow<'_, str> {
    let Ok(mut url) = url::Url::parse(value) else {
        return Cow::Borrowed(value);
    };
    let Some(host) = url.host_str() else {
        return Cow::Borrowed(value);
    };
    let Cow::Owned(host) = identity(host) else {
        return Cow::Borrowed(value);
    };
    if url.set_host(Some(&host)).is_err() {
        return Cow::Borrowed(value);
    }
    Cow::Owned(url.into())
}

/// Format only package identity fields and URL hosts, preserving metadata and paths.
pub(super) fn package_output(mut value: Value) -> Value {
    match &mut value {
        Value::Array(items) => {
            for item in items {
                *item = package_output(item.take());
            }
        }
        Value::Object(fields) => {
            for (key, field) in fields {
                if key == "dependencies" {
                    *field = package_output(field.take());
                    continue;
                }
                if let Value::String(text) = field {
                    let abbreviated = match key.as_str() {
                        "id" => package_id(text),
                        "publisher" | "author" => publisher(text),
                        "identity" => identity(text),
                        "entry_url" | "detail_url" => url(text),
                        _ => continue,
                    };
                    *text = abbreviated.into_owned();
                }
            }
        }
        _ => {}
    }
    value
}
