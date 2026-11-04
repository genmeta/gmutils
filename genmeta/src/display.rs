//! Abbreviations for CLI output; protocol values keep their canonical names.
use std::borrow::Cow;

use serde_json::Value;

#[cfg(test)]
#[path = "../tests/unit/display.rs"]
mod tests;

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

fn line(text: &str) -> String {
    text.chars()
        .map(|ch| if ch.is_control() { ' ' } else { ch })
        .collect::<String>()
        .trim()
        .to_owned()
}

fn package_columns(package: &Value) -> [String; 3] {
    let id = package["id"].as_str().unwrap_or("");
    let (author, name) = id.split_once('/').unwrap_or(("-", id));
    [
        line(package["name"].as_str().unwrap_or(name)),
        line(&publisher(
            package["author"]
                .as_str()
                .or_else(|| package["publisher"].as_str())
                .unwrap_or(author),
        )),
        line(package["version"].as_str().unwrap_or("-")),
    ]
}

pub(super) fn package_list(packages: &[Value], verbose: bool) -> String {
    if packages.is_empty() {
        return "No packages installed.".into();
    }
    if verbose {
        return packages
            .iter()
            .map(package_details)
            .collect::<Vec<_>>()
            .join("\n\n");
    }
    let mut rows = vec![["NAME".into(), "AUTHOR".into(), "VERSION".into()]];
    rows.extend(packages.iter().map(package_columns));
    let width = |column: usize| {
        rows.iter()
            .map(|row| row[column].chars().count())
            .max()
            .unwrap_or(0)
    };
    let name_width = width(0);
    let author_width = width(1);
    rows.iter()
        .map(|[name, author, version]| {
            format!("{name:<name_width$}  {author:<author_width$}  {version}")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub(super) fn package_details(package: &Value) -> String {
    let [name, author, version] = package_columns(package);
    let mut lines = vec![format!("{name} {version}"), format!("  Author: {author}")];
    let kind = match (package["has_app"].as_bool(), package["has_lib"].as_bool()) {
        (Some(true), Some(true)) => Some("App + Lib"),
        (Some(true), _) => Some("App"),
        (_, Some(true)) => Some("Lib"),
        _ => None,
    };
    if let Some(kind) = kind {
        lines.push(format!("  Type: {kind}"));
    }
    for (key, label) in [
        ("title", "Title"),
        ("description", "Description"),
        ("license", "License"),
        ("repository", "Repository"),
        ("author_owner_hash", "Author owner"),
        ("package_sha256", "Package SHA256"),
        ("signer_leaf_fingerprint_sha256", "Signer SHA256"),
    ] {
        if let Some(text) = package[key].as_str().filter(|text| !text.is_empty()) {
            lines.push(format!("  {label}: {}", line(text)));
        }
    }
    if package["has_app"] == true {
        lines.push(format!("  App: /app/{name}/"));
    }
    if let Some(dependencies) = package["dependencies"]
        .as_array()
        .filter(|items| !items.is_empty())
    {
        lines.push("  Dependencies:".into());
        for dependency in dependencies {
            let [name, author, version] = package_columns(dependency);
            lines.push(format!("    {author}/{name} {version}"));
        }
    }
    if let Some(endpoints) = package["endpoints"]
        .as_array()
        .filter(|items| !items.is_empty())
    {
        lines.push("  APIs:".into());
        for endpoint in endpoints {
            if let (Some(method), Some(path)) =
                (endpoint["method"].as_str(), endpoint["path"].as_str())
            {
                lines.push(format!("    {} {}", line(method), line(path)));
            }
        }
    }
    lines.join("\n")
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
