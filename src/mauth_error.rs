use thiserror::Error;

#[derive(Debug, Error)]
pub enum MAuthError {
    #[error("Unable to handle the URL as the format was invalid: {0}")]
    UrlFormatError(#[from] std::string::FromUtf8Error),
    #[error("Version {0} is not supported")]
    UnsupportedVersion(u8),
    #[error("Unable to parse RSA private key: {0}")]
    PrivateKeyDecodeError(#[from] rsa::pkcs1::Error),
    #[error("Unable to parse RSA public key: {0}")]
    PublicKeyDecodeError(#[from] spki::Error),
    #[error("RSA algorithm error: {0}")]
    RsaSignError(#[from] rsa::Error),
    #[error("Unable to verify RSA signature: {0}")]
    SignatureVerifyError(#[from] rsa::signature::Error),
    #[error("Unable to decode base64-encoded signature: {0}")]
    SignatureDecodeError(#[from] base64::DecodeError),
}
