#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

/// Error types
pub mod error;
pub(crate) mod signable;
/// Signing for outgoing requests
pub mod signer;
/// Signature verification for incoming requests
pub mod verifier;

mod pem_format;
