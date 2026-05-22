//! Re-exports forwarding rule types from the core `dssh` crate.
//!
//! See [`dssh::forward::spec`] for type definitions, PEG parser,
//! and OpenSSH-compatible syntax documentation.

pub use dssh::forward::spec::{DynamicForward, Endpoint, LocalForward, RemoteForward};
