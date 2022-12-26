use crate::signable::Signable;
use anyhow::{bail, Result};
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::RsaPrivateKey;
use sha2::Sha512;

pub struct Signer {
    app_uuid: String,
    private_key: RsaPrivateKey,
    signing_key: rsa::pkcs1v15::SigningKey<Sha512>,
}

impl Signer {
    pub fn new(app_uuid: impl Into<String>, private_key_data: String) -> Result<Self> {
        let private_key = RsaPrivateKey::from_pkcs1_pem(&private_key_data)?;
        let signing_key =
            rsa::pkcs1v15::SigningKey::<Sha512>::new_with_prefix(private_key.to_owned());

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
    ) -> Result<String> {
        let signable = Signable::new(verb, path, query, body, timestamp, &self.app_uuid);

        match version {
            1 => self.sign_string_v1(&signable),
            2 => self.sign_string_v2(&signable),
            _ => bail!("Version {version} is not supported."),
        }
    }

    fn sign_string_v1(&self, signable: &Signable) -> Result<String> {
        let signature = self.private_key.sign(
            rsa::PaddingScheme::new_pkcs1v15_sign_raw(),
            &signable.signing_string_v1()?,
        )?;
        Ok(base64::encode(signature))
    }

    fn sign_string_v2(&self, signable: &Signable) -> Result<String> {
        use rsa::signature::Signer;

        let sign = self.signing_key.sign(&signable.signing_string_v2()?);
        Ok(base64::encode(sign.as_ref()))
    }
}
