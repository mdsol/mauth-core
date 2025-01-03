use crate::pem_format;
use crate::{error::Error, signable::Signable};
use base64::{engine::general_purpose, Engine as _};
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::RsaPrivateKey;
use sha2::Sha512;

/// Used to sign outgoing requests. Struct can be initialized once and used to sign many requests.
#[derive(Debug, Clone)]
pub struct Signer {
    app_uuid: String,
    private_key: RsaPrivateKey,
    signing_key: rsa::pkcs1v15::SigningKey<Sha512>,
}

impl Signer {
    /// Initialize a new signer with the app UUID and the private key. The format of the private key
    /// should be a raw RSA private key in the PKCS1 PEM format, as generated by `openssl genrsa`. An
    /// error will be returned if the input data is unable to be parsed as a private key. The `app_uuid`
    /// is expected to be a valid UUID, however this is not checked. If you pass something other than
    /// a valid UUID, no error will be returned, but none of the created signatures will be able to
    /// be validated by other MAuth verifiers.
    ///
    /// ```
    /// # use mauth_core::signer::Signer;
    /// # let private_key = std::fs::read_to_string("tests/mauth-protocol-test-suite/signing-params/rsa-key").unwrap();
    /// let signer = Signer::new("101c139a-236c-11ef-b5e3-125eb8485a60", private_key);
    /// assert!(signer.is_ok());
    /// ```
    pub fn new(app_uuid: impl Into<String>, private_key_data: String) -> Result<Self, Error> {
        let private_key = RsaPrivateKey::from_pkcs1_pem(&pem_format::normalize_rsa_private_key(
            private_key_data,
        ))?;
        let signing_key = rsa::pkcs1v15::SigningKey::<Sha512>::new(private_key.to_owned());

        Ok(Self {
            app_uuid: app_uuid.into(),
            private_key,
            signing_key,
        })
    }

    /// This function will generate a valid MAuth signature string of the specified version, or error
    /// if it is unable to.
    ///
    /// ```
    /// # use mauth_core::signer::Signer;
    /// # let private_key = std::fs::read_to_string("tests/mauth-protocol-test-suite/signing-params/rsa-key").unwrap();
    /// # let signer = Signer::new("101c139a-236c-11ef-b5e3-125eb8485a60", private_key).unwrap();
    /// let result = signer.sign_string(2, "GET", "/item", "page=2", b"", "2024-01-28T19:11:35.000");
    /// assert!(result.is_ok());
    /// ```
    pub fn sign_string(
        &self,
        version: u8,
        verb: impl Into<String>,
        path: impl Into<String>,
        query: impl Into<String>,
        body: &[u8],
        timestamp: impl Into<String>,
    ) -> Result<String, Error> {
        let signable = Signable::new(verb, path, query, body, timestamp, &self.app_uuid);

        match version {
            1 => self.sign_string_v1(&signable),
            2 => self.sign_string_v2(&signable),
            v => Err(Error::UnsupportedVersion(v)),
        }
    }

    fn sign_string_v1(&self, signable: &Signable) -> Result<String, Error> {
        let signature = self.private_key.sign(
            rsa::Pkcs1v15Sign::new_unprefixed(),
            &signable.signing_string_v1()?,
        )?;
        Ok(general_purpose::STANDARD.encode(signature))
    }

    fn sign_string_v2(&self, signable: &Signable) -> Result<String, Error> {
        use rsa::signature::{SignatureEncoding, Signer};

        let sign = self.signing_key.sign(&signable.signing_string_v2()?);
        Ok(general_purpose::STANDARD.encode(sign.to_bytes().as_ref()))
    }
}
