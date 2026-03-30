//! Re-exports forwarding rule types from the core `genmeta-ssh` crate.
//!
//! See [`genmeta_ssh_core::forward::spec`] for type definitions, PEG parser,
//! and OpenSSH-compatible syntax documentation.

pub use genmeta_ssh_core::forward::spec::{DynamicForward, Endpoint, LocalForward, RemoteForward};
