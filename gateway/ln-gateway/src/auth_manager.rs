use std::collections::BTreeSet;
use std::fmt::Display;
use std::str::FromStr;
use std::time::UNIX_EPOCH;

use bitcoin::hashes::{sha256, Hash as BitcoinHash};
use bitcoin::secp256k1::schnorr::Signature;
use bitcoin::secp256k1::{Keypair, Message, SecretKey};
use fedimint_core::secp256k1::PublicKey;
use fedimint_core::util::SafeUrl;
use jsonwebtoken::{encode, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::rpc::AuthChallengePayload;

const CHALLENGE_EXPIRY_SECONDS: u64 = 60; // 1 minute
const SESSION_EXPIRY_SECONDS: u64 = 60 * 30; // 30 minute

pub struct AuthManager {
    /// The public key of the gateway
    gateway_id: PublicKey,
    /// The API endpoint of the gateway
    gateway_api: SafeUrl,
    /// Challenges with their expiry times
    challenges: BTreeSet<AuthChallenge>,
    /// A secret key to encode a JWT with
    pub encoding_secret: [u8; 16],
    /// A secret key for creating a Keypair
    secret_key: SecretKey,
}

impl AuthManager {
    /// Create a new auth manager
    pub fn new(gateway_id: PublicKey, gateway_api: SafeUrl, encoding_secret: [u8; 16]) -> Self {
        let secret_key = SecretKey::new(&mut rand::thread_rng());
        Self {
            gateway_id,
            gateway_api,
            challenges: BTreeSet::new(),
            encoding_secret,
            secret_key,
        }
    }

    /// Create a new challenge
    pub fn create_challenge(&mut self) -> anyhow::Result<String> {
        let challenge = AuthChallenge::new(self.gateway_id, self.gateway_api.clone());
        self.challenges.insert(challenge.clone());
        let encode_challenge = urlencoding::encode(challenge.to_string().as_ref()).to_string();
        Ok(encode_challenge)
    }

    /// sign the challenge
    pub fn sign_challenge(
        &self,
        ctx: &bitcoin::secp256k1::global::GlobalContext,
        challenge_payload: &str,
    ) -> anyhow::Result<Signature> {
        let decode_challenge = urlencoding::decode(challenge_payload)?;
        let challenge = AuthChallenge::from_str(&decode_challenge)?;
        if !self.challenges.contains(&challenge)
            || challenge.gateway_id != self.gateway_id
            || challenge.gateway_api != self.gateway_api
        {
            return Err(anyhow::anyhow!("Invalid challenge"));
        }
        if challenge.expiry
            < fedimint_core::time::now()
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards")
                .as_secs()
        {
            return Err(anyhow::anyhow!("Challenge expired"));
        }
        let sk = Keypair::from_secret_key(ctx, &self.secret_key);
        let message = Message::from_digest(
            sha256::Hash::hash(challenge.to_string().as_bytes()).to_byte_array(),
        );
        let signature = ctx.sign_schnorr(&message, &sk);
        Ok(signature)
    }

    /// Verify the challenge
    pub fn verify_challenge_response(
        &mut self,
        ctx: &bitcoin::secp256k1::global::GlobalContext,
        challenge_response: &AuthChallengePayload,
    ) -> anyhow::Result<Session> {
        let decode_challenge = urlencoding::decode(&challenge_response.challenge)?;
        let challenge = AuthChallenge::from_str(&decode_challenge)?;
        if !self.challenges.contains(&challenge)
            || challenge.gateway_id != self.gateway_id
            || challenge.gateway_api != self.gateway_api
        {
            return Err(anyhow::anyhow!("Invalid challenge"));
        }
        if challenge.expiry
            < fedimint_core::time::now()
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards")
                .as_secs()
        {
            return Err(anyhow::anyhow!("Challenge expired"));
        }

        let sk = bitcoin::secp256k1::Keypair::from_secret_key(ctx, &self.secret_key);

        // Verify the schnorr signature against the gateway's pubkey
        let message = Message::from_digest(
            sha256::Hash::hash(challenge.to_string().as_bytes()).to_byte_array(),
        );
        let signature = challenge_response.response;
        ctx.verify_schnorr(&signature, &message, &sk.x_only_public_key().0)
            .map_err(|_| anyhow::anyhow!("Invalid signature"))?;

        // If valid, remove the challenge from the set
        self.challenges.remove(&challenge);
        let id = Uuid::new_v4();
        let session = Session::new(id, SESSION_EXPIRY_SECONDS);
        Ok(session)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AuthChallenge {
    gateway_id: PublicKey,
    gateway_api: SafeUrl,
    /// The expiry time of the challenge
    expiry: u64,
}

/// Structure to represent a challenge.
/// gatewayid-gatewayapi-timestamp
impl AuthChallenge {
    /// Create a new challenge with a random string and an expiry time of 1
    /// minute.
    pub fn new(gateway_id: PublicKey, gateway_api: SafeUrl) -> Self {
        let now = fedimint_core::time::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();
        let expiry = now + CHALLENGE_EXPIRY_SECONDS;
        Self {
            gateway_id,
            gateway_api,
            expiry,
        }
    }
}

impl FromStr for AuthChallenge {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts = s.split('-').collect::<Vec<&str>>();
        let gateway_id = PublicKey::from_str(parts[0])?;
        let gateway_api = SafeUrl::parse(parts[1])?;
        let expiry = parts[2].parse::<u64>()?;
        Ok(Self {
            gateway_id,
            gateway_api,
            expiry,
        })
    }
}

impl Display for AuthChallenge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}-{}-{}",
            self.gateway_id, self.gateway_api, self.expiry
        )
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Session {
    /// the unique identifier of the session.
    pub id: Uuid,
    /// the expire time of the session
    pub exp: u64,
}

impl Session {
    pub fn new(id: Uuid, expiry: u64) -> Self {
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
