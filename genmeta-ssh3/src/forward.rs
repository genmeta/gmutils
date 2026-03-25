//! Re-exports forwarding rule types from the core `genmeta-ssh` crate.
//!
//! See [`genmeta_ssh::forward::spec`] for type definitions, PEG parser,
//! and OpenSSH-compatible syntax documentation.

pub use genmeta_ssh::forward::spec::{DynamicForward, Endpoint, LocalForward, RemoteForward};
