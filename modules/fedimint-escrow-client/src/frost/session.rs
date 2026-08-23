use fedimint_core::BitcoinHash;
use fedimint_core::bitcoin::hashes::{HashEngine, sha256};
use fedimint_core::config::FederationId;
use fedimint_core::secp256k1::PublicKey;
use frost_secp256k1::Secp256K1Sha256;
use frost_secp256k1::keys::dkg::round1::SecretPackage;
use frost_secp256k1::keys::dkg::round2::SecretPackage;
use frost_secp256k1::keys::{KeyPackage, PublicKeyPackage};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::frost::dkg::DkgRunner;
use crate::frost::transport::file::FileTransport;

pub struct SessionId(pub [u8; 32]);

pub struct FrostDkgSession {
    session_id: SessionId,
    participant_id: PublicKey,
    participants: Vec<PublicKey>,
    max_signers: u16,
    min_signers: u16,
    round1_secret: SecretPackage<Secp256K1Sha256>,
    round2_secret: SecretPackage<Secp256K1Sha256>,
    key_package: KeyPackage<Secp256K1Sha256>,
    public_key_package: PublicKeyPackage<Secp256K1Sha256>,
}

impl Serialize for SessionId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(self.0))
    }
}

impl<'de> Deserialize<'de> for SessionId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;

        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 32 bytes"))?;

        Ok(SessionId(arr))
    }
}

fn create_session_id(participants: &Vec<PublicKey>, federation_id: &FederationId) -> SessionId {
    let mut rng = SystemRandom::new();
    let mut nonce = [0u8; 32];
    rng.fill(&mut nonce);
    let engine = sha256::HashEngine::default();
    engine.input(b"fedimint_escrow_dkg_consortium");
    engine.input(federation_id.0.to_byte_array());
    engine.input(nonce);
    engine.input(participants);
    SessionId(sha256::Hash::from_engine(engine).to_byte_array())
}

pub struct FrostSessionArgs {
    participant_id: PublicKey,
    participants: Vec<PublicKey>,
    federation_id: FederationId,
    max_signers: u16,
    min_signers: u16,
}

impl FrostDkgSession {
    pub fn new(args: FrostSessionArgs) -> Self {
        let session_id = create_session_id(&args.participants, &args.federation_id);
        let transport = FileTransport::default();
        DkgRunner::run_dkg(transport, &args); // should return dkgresult
        Self {
            session_id,
            participant_id: args.participant_id,
            participants: args.participants,
            max_signers: args.max_signers,
            min_signers: args.min_signers,
            round1_secret: (),
            round2_secret: (),
            key_package: (),
            public_key_package: (),
        }
    }
}
