use crate::{mauth_error::MAuthError, signable::Signable};
use base64::{engine::general_purpose, Engine as _};
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::RsaPrivateKey;
use sha2::Sha512;

#[derive(Debug, Clone)]
pub struct Signer {
    app_uuid: String,
    private_key: RsaPrivateKey,
    signing_key: rsa::pkcs1v15::SigningKey<Sha512>,
}

impl Signer {
    pub fn new(app_uuid: impl Into<String>, private_key_data: String) -> Result<Self, MAuthError> {
        let private_key = RsaPrivateKey::from_pkcs1_pem(&private_key_data)?;
        let signing_key = rsa::pkcs1v15::SigningKey::<Sha512>::new(private_key.to_owned());

        Ok(Self {
            app_uuid: app_uuid.into(),
            private_key,
            signing_key,
        })
    }

    pub fn sign_string(
        &self,
        version: u8,
        verb: impl Into<String>,
        path: impl Into<String>,
        query: impl Into<String>,
        body: &[u8],
        timestamp: impl Into<String>,
    ) -> Result<String, MAuthError> {
        let signable = Signable::new(verb, path, query, body, timestamp, &self.app_uuid);

        match version {
            1 => self.sign_string_v1(&signable),
            2 => self.sign_string_v2(&signable),
            v => Err(MAuthError::UnsupportedVersion(v)),
        }
    }

    fn sign_string_v1(&self, signable: &Signable) -> Result<String, MAuthError> {
        let signature = self.private_key.sign(
            rsa::Pkcs1v15Sign::new_unprefixed(),
            &signable.signing_string_v1()?,
        )?;
        Ok(general_purpose::STANDARD.encode(signature))
    }

    fn sign_string_v2(&self, signable: &Signable) -> Result<String, MAuthError> {
        use rsa::signature::{SignatureEncoding, Signer};

        let sign = self.signing_key.sign(&signable.signing_string_v2()?);
        Ok(general_purpose::STANDARD.encode(sign.to_bytes().as_ref()))
    }
}
