use std::time::UNIX_EPOCH;

use fedimint_core::secp256k1::PublicKey;
use jsonwebtoken::{encode, EncodingKey, Header};
use serde::{Deserialize, Serialize};

const SESSION_EXPIRY_SECONDS: u64 = 60 * 30; // 30 minute

pub struct AuthManager {
    ///gateway id
    gateway_id: PublicKey,
    /// A secret key to encode a JWT with
    pub encoding_secret: [u8; 16],
}

impl AuthManager {
    /// Create a new auth manager
    pub fn new(encoding_secret: [u8; 16], gateway_id: PublicKey) -> Self {
        Self {
            gateway_id,
            encoding_secret,
        }
    }
    pub fn generate_session(&self) -> anyhow::Result<Session> {
        let session = Session::new(self.gateway_id, SESSION_EXPIRY_SECONDS);
        Ok(session)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Session {
    /// the unique identifier of the session.
    pub id: PublicKey,
    /// the expire time of the session
    pub exp: u64,
}

impl Session {
    pub fn new(id: PublicKey, expiry: u64) -> Self {
        let now = fedimint_core::time::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();
        Self {
            id,
            exp: now + expiry,
        }
    }

    pub fn encode_jwt(self, encoding_secret: &[u8; 16]) -> anyhow::Result<String> {
        let claim = self;
        encode(
            &Header::default(),
            &claim,
            &EncodingKey::from_secret(encoding_secret),
        )
        .map_err(|_| anyhow::anyhow!("Unable to generate jwt token session"))
    }
}
