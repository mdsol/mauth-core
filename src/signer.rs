use crate::signable::Signable;
use anyhow::{bail, Result};
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::rsa::{Padding, Rsa};

pub struct Signer {
    app_uuid: String,
    private_key: PKey<Private>,
    rsa_private_key: Rsa<Private>,
}

impl Signer {
    pub fn new(app_uuid: impl Into<String>, private_key_data: String) -> Result<Self> {
        let private_key = PKey::private_key_from_pem(private_key_data.as_bytes())?;
        let rsa_private_key = private_key.rsa()?;

        Ok(Self {
            app_uuid: app_uuid.into(),
            private_key,
            rsa_private_key,
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
        let mut signature = vec![0; self.rsa_private_key.size() as usize];

        self.rsa_private_key.private_encrypt(
            &signable.signing_string_v1()?,
            &mut signature,
            Padding::PKCS1,
        )?;
        Ok(base64::encode(&signature))
    }

    fn sign_string_v2(&self, signable: &Signable) -> Result<String> {
        let mut signer = openssl::sign::Signer::new(MessageDigest::sha512(), &self.private_key)?;
        let signature = signer.sign_oneshot_to_vec(&signable.signing_string_v2()?)?;
        Ok(base64::encode(&signature))
    }
}
