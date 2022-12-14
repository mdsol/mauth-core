use crate::signable::Signable;
use anyhow::{bail, Result};
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Public};
use openssl::rsa::Padding;

pub struct Verifier {
    app_uuid: String,
    public_key: PKey<Public>,
}

impl Verifier {
    pub fn new(app_uuid: impl Into<String>, public_key_data: String) -> Result<Self> {
        let public_key = PKey::public_key_from_pem(public_key_data.as_bytes())?;

        Ok(Self {
            app_uuid: app_uuid.into(),
            public_key,
        })
    }

    pub fn verify_signature(
        &self,
        version: u8,
        verb: impl Into<String>,
        path: impl Into<String>,
        query: impl Into<String>,
        body: &[u8],
        timestamp: impl Into<String>,
        signature: impl Into<String>,
    ) -> Result<bool> {
        let signable = Signable::new(verb, path, query, body, timestamp, &self.app_uuid);

        match version {
            1 => self.verify_signature_v1(&signable, signature.into()),
            2 => self.verify_signature_v2(&signable, signature.into()),
            _ => bail!("Version {version} is not supported."),
        }
    }

    fn verify_signature_v1(&self, signable: &Signable, signature: String) -> Result<bool> {
        let rsa_public_key = self.public_key.rsa()?;
        let mut buf: Vec<u8> = vec![0; rsa_public_key.size() as usize];
        let len =
            rsa_public_key.public_decrypt(&base64::decode(signature)?, &mut buf, Padding::PKCS1)?;

        Ok(buf[0..len] == signable.signing_string_v1()?)
    }

    fn verify_signature_v2(&self, signable: &Signable, signature: String) -> Result<bool> {
        let mut verifier = openssl::sign::Verifier::new(MessageDigest::sha512(), &self.public_key)?;
        verifier.set_rsa_padding(Padding::PKCS1)?;
        verifier.update(&signable.signing_string_v2()?)?;
        Ok(verifier.verify(&base64::decode(signature)?)?)
    }
}
