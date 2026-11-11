use std::fmt;

use fedimint_aead::{LessSafeKey, UnboundKey, decrypt, encrypt};
use fedimint_core::encoding::{Decodable, Encodable};
use ring::aead::CHACHA20_POLY1305;
use serde::{Serialize, Serializer};

use crate::frost::dkg::DkgError;
use crate::frost::session::SessionId;

/// encrypted dkg secret
#[derive(Clone, PartialEq, Eq, Hash, Encodable, Decodable)]
pub struct EncryptedPackage(Vec<u8>);

impl fmt::Debug for EncryptedPackage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Sealed(<{} bytes>)", self.0.len())
    }
}

impl Serialize for EncryptedPackage {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str("<sealed>")
    }
}

pub struct StateKey(LessSafeKey);

impl StateKey {
    pub fn new(bytes: &[u8; 32]) -> Self {
        Self(LessSafeKey::new(
            UnboundKey::new(&CHACHA20_POLY1305, bytes).expect("32 byte key"),
        ))
    }

    pub fn encrypt(
        &self,
        session_id: &SessionId,
        field: &str,
        secret: &[u8],
    ) -> Result<EncryptedPackage, DkgError> {
        let mut plain = Vec::with_capacity(33 + field.len() + secret.len());
        plain.extend_from_slice(&session_id.0);
        plain.push(field.len() as u8);
        plain.extend_from_slice(field.as_bytes());
        plain.extend_from_slice(secret);

        encrypt(plain, &self.0)
            .map(EncryptedPackage)
            .map_err(|_| DkgError::Other(anyhow::anyhow!("could not encrypt dkg state")))
    }

    pub fn decrypt(
        &self,
        session_id: &SessionId,
        field: &str,
        sealed: &EncryptedPackage,
    ) -> Result<Vec<u8>, DkgError> {
        let mut buf = sealed.0.clone();
        let plain = decrypt(&mut buf, &self.0)
            .map_err(|_| DkgError::Other(anyhow::anyhow!("could not decrypt dkg state")))?;

        let header = 33 + field.len();
        if plain.len() < header
            || plain[..32] != session_id.0
            || plain[32] as usize != field.len()
            || &plain[33..header] != field.as_bytes()
        {
            return Err(DkgError::Other(anyhow::anyhow!(
                "dkg state belongs to another session or field"
            )));
        }
        Ok(plain[header..].to_vec())
    }
}
