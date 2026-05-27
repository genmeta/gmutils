pub mod manifest;
pub mod prompt;

#[allow(unused_imports)]
pub use manifest::{ArtifactKind, PackageArtifact, PackageManifest};

#[allow(dead_code)]
pub const KNOWN_PACKAGE_TARGETS: &[&str] = &["deb", "rpm", "brew", "scoop"];
