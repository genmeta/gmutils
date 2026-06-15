//! Re-exports forwarding rule types from the core `dshell` crate.
//!
//! See [`dshell::forward::spec`] for type definitions, PEG parser,
//! and OpenSSH-compatible syntax documentation.

pub use dshell::forward::spec::{DynamicForward, Endpoint, LocalForward, RemoteForward};
