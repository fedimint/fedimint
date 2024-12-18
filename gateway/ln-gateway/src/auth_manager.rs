use std::time::UNIX_EPOCH;

use fedimint_core::secp256k1::PublicKey;
use jsonwebtoken::{encode, DecodingKey, EncodingKey, Header};
use serde::{Deserialize, Serialize};

const SESSION_EXPIRY_SECONDS: u64 = 60 * 30; // 30 minute

#[derive(Clone)]
pub struct AuthManager {
    ///gateway id
    gateway_id: PublicKey,
    /// A secret key to encode a JWT with
    encoding_key: EncodingKey,
    /// A secret key to decode a JWT with
    decoding_key: DecodingKey,
}

impl AuthManager {
    /// Create a new auth manager
    pub fn new(
        encoding_key: EncodingKey,
        decoding_key: DecodingKey,
        gateway_id: PublicKey,
    ) -> Self {
        Self {
            gateway_id,
            encoding_key,
            decoding_key,
        }
    }

    /// generate a jwt token
    pub fn generate_jwt(&self) -> anyhow::Result<String> {
        let session = Session::new(self.gateway_id, SESSION_EXPIRY_SECONDS);
        encode(&Header::default(), &session, &self.encoding_key)
            .map_err(|_| anyhow::anyhow!("Unable to generate jwt token session"))
        // session.encode_jwt(&self.encoding_key)
    }

    /// validate that a JWT is valid
    pub fn is_jwt_valid(&self, token: &str) -> bool {
        if let Ok(decoded_token_data) = jsonwebtoken::decode::<Session>(
            token,
            &self.decoding_key,
            &jsonwebtoken::Validation::default(),
        ) {
            let now = fedimint_core::time::now()
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards")
                .as_secs();
            return now < decoded_token_data.claims.exp;
        }
        false
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct Session {
    /// the unique identifier of the session.
    id: PublicKey,
    /// the expire time of the session
    exp: u64,
}

impl Session {
    fn new(id: PublicKey, expiry: u64) -> Self {
        let now = fedimint_core::time::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();
        Self {
            id,
            exp: now + expiry,
        }
    }
}
