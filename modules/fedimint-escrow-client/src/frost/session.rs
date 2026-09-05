use fedimint_core::BitcoinHash;
use fedimint_core::bitcoin::hashes::{HashEngine, sha256};
use fedimint_core::config::FederationId;
use fedimint_core::db::Database;
use fedimint_core::secp256k1::PublicKey;
use frost_secp256k1::keys::dkg::round1::SecretPackage;
use frost_secp256k1::keys::dkg::round2::SecretPackage;
use frost_secp256k1::keys::{KeyPackage, PublicKeyPackage};
use frost_secp256k1::{Identifier, Secp256K1Sha256};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::frost::dkg::DkgRunner;
use crate::frost::transport::file::FileTransport;

pub struct SessionId(pub [u8; 32]);

pub struct FrostParticipant {
    identity: PublicKey,
    identifier: Identifier,
}

pub enum FrostDkgState {
    Created,
    Round1 {
        round1_secret: SecretPackage<Secp256K1Sha256>,
    },
    Round2 {
        round2_secret: SecretPackage<Secp256K1Sha256>,
    },
    Finalize {
        key_package: KeyPackage<Secp256K1Sha256>,
        public_key_package: PublicKeyPackage<Secp256K1Sha256>,
    },
    Failed {
        error: String,
    },
}

pub struct FrostDkgSession {
    session_id: SessionId,
    participant_id: FrostParticipant,
    participants: Vec<FrostParticipant>,
    max_signers: u16,
    min_signers: u16,
    state: FrostDkgState,
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
    participants.sort_by_key(|pk| pk.serialize());
    let engine = sha256::HashEngine::default();
    engine.input(b"fedimint_escrow_dkg_consortium");
    engine.input(federation_id.0.to_byte_array());
    for participant in &participants {
        engine.input(&participant);
    }
    engine.input(nonce);

    SessionId(sha256::Hash::from_engine(engine).to_byte_array())
}

pub struct FrostSessionArgs {
    database: &Database,
    participant_id: FrostParticipant,
    participants: Vec<FrostParticipant>,
    federation_id: FederationId,
}

impl FrostDkgSession {
    pub fn new(args: FrostSessionArgs) -> Self {
        let session_id = create_session_id(&args.participants, &args.federation_id);
        let max_signers = args.participants.len() as u16;
        let f = (max_signers.saturating_sub(1)) / 3;
        let min_signers = max_signers - f;

        let transport = FileTransport::new("path".to_string(), &session_id, &max_signers);
        DkgRunner::run_dkg(
            transport,
            args.database,
            &args.participant_id,
            args.participants,
            &args.federation_id,
            &min_signers,
        ); // should return dkgresult

        Self {
            session_id,
            participant_id: args.participant_id,
            participants: args.participants,
            max_signers: max_signers,
            min_signers: min_signers,
            state: FrostDkgState::Created,
        }
    }
}
