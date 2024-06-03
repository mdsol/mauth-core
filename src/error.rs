use thiserror::Error;

/// All of the possible errors that can happen while performing mauth operations
#[derive(Debug, Error)]
pub enum Error {
    /// A UTF8 decode error while attempting to process the URL
    #[error("Unable to handle the URL as the format was invalid: {0}")]
    UrlEncodingError(#[from] std::string::FromUtf8Error),
    /// A MAuth version that is not supported was requested
    #[error("Version {0} is not supported")]
    UnsupportedVersion(u8),
    /// The provided private key could not be parsed
    #[error("Unable to parse RSA private key: {0}")]
    PrivateKeyDecodeError(#[from] rsa::pkcs1::Error),
    /// The provided public key could not be parsed
    #[error("Unable to parse RSA public key: {0}")]
    PublicKeyDecodeError(#[from] spki::Error),
    /// An algorithm failure occurred while trying to sign a request
    #[error("RSA algorithm error: {0}")]
    RsaSignError(#[from] rsa::Error),
    /// An algorithm failure occurred while trying to verify a request
    #[error("Unable to verify RSA signature: {0}")]
    SignatureVerifyError(#[from] rsa::signature::Error),
    /// A base64 error was encountered while attempting to verify a v1 signature
    #[error("Unable to decode base64-encoded signature: {0}")]
    SignatureDecodeError(#[from] base64::DecodeError),
}
