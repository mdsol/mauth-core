use crate::{error::Error, signable::Signable};
use base64::{engine::general_purpose, Engine as _};
use rsa::pkcs1v15::Signature;
use rsa::pkcs8::DecodePublicKey;
use rsa::RsaPublicKey;
use sha2::Sha512;

#[derive(Debug, Clone)]
pub struct Verifier {
    app_uuid: String,
    public_key: RsaPublicKey,
    verifying_key: rsa::pkcs1v15::VerifyingKey<Sha512>,
}

impl Verifier {
    pub fn new(app_uuid: impl Into<String>, public_key_data: String) -> Result<Self, Error> {
        let public_key = RsaPublicKey::from_public_key_pem(&public_key_data)?;
        let verifying_key = rsa::pkcs1v15::VerifyingKey::<Sha512>::new(public_key.to_owned());

        Ok(Self {
            app_uuid: app_uuid.into(),
            public_key,
            verifying_key,
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
    ) -> Result<(), Error> {
        let signable = Signable::new(verb, path, query, body, timestamp, &self.app_uuid);

        match version {
            1 => self.verify_signature_v1(&signable, signature.into()),
            2 => self.verify_signature_v2(&signable, signature.into()),
            v => Err(Error::UnsupportedVersion(v)),
        }
    }

    fn verify_signature_v1(
        &self,
        signable: &Signable,
        signature: String,
    ) -> Result<(), Error> {
        self.public_key.verify(
            rsa::Pkcs1v15Sign::new_unprefixed(),
            &signable.signing_string_v1()?,
            &general_purpose::STANDARD.decode(signature)?,
        )?;

        Ok(())
    }

    fn verify_signature_v2(
        &self,
        signable: &Signable,
        signature: String,
    ) -> Result<(), Error> {
        use rsa::signature::Verifier;

        let signature =
            Signature::try_from(general_purpose::STANDARD.decode(signature)?.as_slice())?;
        self.verifying_key
            .verify(&signable.signing_string_v2()?, &signature)?;

        Ok(())
    }
}
