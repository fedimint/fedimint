use std::collections::BTreeMap;

use fedimint_core::BitcoinHash;
use fedimint_core::bitcoin::hashes::{HashEngine, sha256};
use fedimint_core::config::FederationId;
use fedimint_core::db::{Database, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::encoding::{Decodable, DecodeError, Encodable};
use fedimint_core::secp256k1::PublicKey;
use frost_secp256k1::keys::dkg::round1::{
    Package as Round1Package, SecretPackage as Round1SecretPackage,
};
use frost_secp256k1::keys::dkg::round2::{
    Package as Round2Package, SecretPackage as Round2SecretPackage,
};
use frost_secp256k1::keys::{KeyPackage, PublicKeyPackage};
use frost_secp256k1::{Error, Identifier};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::client_db::{FrostDkgSessionKey, FrostDkgSessionRecordkey};
use crate::frost::dkg::{DkgError, DkgResult, DkgRunner};
use crate::frost::transport::DkgTransport;

#[derive(Debug, Clone, Copy, Hash, Encodable, Decodable, PartialEq, Eq)]
pub struct SessionId(pub [u8; 32]);

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct ParticipantId(pub [u8; 32]);

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct FrostParticipant {
    pub identifier: Identifier,
}

impl Encodable for FrostParticipant {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<(), std::io::Error> {
        self.identifier.serialize().consensus_encode(writer)?;
        Ok(())
    }
}

impl Decodable for FrostParticipant {
    fn consensus_decode_partial<R: std::io::Read>(
        r: &mut R,
        modules: &fedimint_core::module::registry::ModuleDecoderRegistry,
    ) -> Result<Self, fedimint_core::encoding::DecodeError> {
        let identifier_bytes: Vec<u8> = Decodable::consensus_decode_partial(r, modules)?;

        let identifier = Identifier::deserialize(&identifier_bytes).map_err(|e| {
            DecodeError::new_custom(anyhow::anyhow!("Invalid FROST identifier: {e}"))
        })?;

        Ok(Self { identifier })
    }
}

impl Serialize for FrostParticipant {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(self.identifier.serialize()))
    }
}

impl<'de> Deserialize<'de> for FrostParticipant {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        let identifier = Identifier::deserialize(&bytes).map_err(serde::de::Error::custom)?;
        Ok(Self { identifier })
    }
}

impl FrostParticipant {
    pub fn from_pubkey(pubkey: PublicKey) -> anyhow::Result<Self> {
        let identifier = Identifier::derive(&pubkey.serialize())?;

        Ok(Self { identifier })
    }
}

#[derive(Debug, Clone, Encodable, Decodable, Serialize, Deserialize)]
pub enum FrostDkgState {
    Created,
    Round1Complete {
        round1_secret: Vec<u8>,
        round1_received: BTreeMap<Vec<u8>, Vec<u8>>,
    },
    Round2Complete {
        round1_received: BTreeMap<Vec<u8>, Vec<u8>>,
        round2_secret: Vec<u8>,
        round2_received: BTreeMap<Vec<u8>, Vec<u8>>,
    },
    Finalized {
        key_package: Vec<u8>,
        public_key_package: Vec<u8>,
    },
    Failed {
        round: u8,
        error: String,
    },
}

#[derive(Debug, Clone, Hash, Encodable, Decodable, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrostDkgSessionRecord {
    pub session_id: SessionId,
    pub participant_id: FrostParticipant,
    pub participants: Vec<FrostParticipant>,
    pub max_signers: u16,
    pub min_signers: u16,
}

#[derive(Debug, Clone, Encodable, Decodable, Serialize, Deserialize)]
pub struct FrostDkgSession {
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

fn create_session_id(participants: &[FrostParticipant], federation_id: &FederationId) -> SessionId {
    let mut identifiers: Vec<Vec<u8>> = participants
        .iter()
        .map(|p| p.identifier.serialize().to_vec())
        .collect();

    identifiers.sort();
    let mut engine = sha256::HashEngine::default();

    engine.input(b"fedimint_escrow_dkg_consortium");
    engine.input(&federation_id.0.to_byte_array());

    for identifier in identifiers {
        engine.input(&identifier);
    }

    SessionId(sha256::Hash::from_engine(engine).to_byte_array())
}

impl FrostDkgSessionRecord {
    pub async fn new(
        participant_id: FrostParticipant,
        participants: Vec<FrostParticipant>,
        federation_id: FederationId,
        db: &Database,
    ) -> anyhow::Result<Self> {
        if participants.is_empty() {
            return Err(anyhow::anyhow!("participant list cannot be empty"));
        }

        let session_id = create_session_id(&participants, &federation_id);
        let mut identities = std::collections::BTreeSet::new();

        let max_signers = participants.len() as u16;
        anyhow::ensure!(max_signers > 2, "participant length must be greater than 2");

        for participant in &participants {
            anyhow::ensure!(
                identities.insert(participant.identifier),
                "duplicate participant identity"
            );
        }

        anyhow::ensure!(
            participants
                .iter()
                .any(|p| p.identifier == participant_id.identifier),
            "local participant is not in participant list"
        );
        let f = (max_signers.saturating_sub(1)) / 3;
        let min_signers = max_signers - f;

        let record = Self {
            session_id,
            participant_id,
            participants,
            max_signers,
            min_signers,
        };
        let mut dbtx = db.begin_transaction().await;
        if let Some(existing) = dbtx.get_value(&FrostDkgSessionRecordkey(session_id)).await {
            return Ok(existing);
        }
        dbtx.insert_entry(&FrostDkgSessionRecordkey(session_id), &record)
            .await;
        dbtx.commit_tx().await;

        anyhow::Ok(record)
    }

    async fn persist_state(db: &Database, session_id: SessionId, state: FrostDkgState) {
        let mut dbtx = db.begin_transaction().await;
        dbtx.insert_entry(&FrostDkgSessionKey(session_id), &FrostDkgSession { state })
            .await;
        dbtx.commit_tx().await;
    }

    pub async fn run<T: DkgTransport>(
        &self,
        db: &Database,
        transport: T,
    ) -> Result<DkgResult, DkgError> {
        let dkg_runner = DkgRunner::new(transport);

        let mut read_tx = db.begin_transaction_nc().await;
        let mut state: FrostDkgState = read_tx
            .get_value(&FrostDkgSessionKey(self.session_id))
            .await
            .map(|s: FrostDkgSession| s.state)
            .unwrap_or(FrostDkgState::Created);

        drop(read_tx);

        loop {
            state = match state {
                FrostDkgState::Created => {
                    let round1 = dkg_runner
                        .run_round1(
                            &self.session_id,
                            &self.participant_id,
                            &self.participants,
                            self.min_signers,
                        )
                        .await;
                    match round1 {
                        Ok(dkg_round1) => FrostDkgState::Round1Complete {
                            round1_secret: dkg_round1
                                .round1_secret_package
                                .serialize()
                                .map_err(|e| DkgError::FrostError(e.to_string()))?,
                            round1_received: dkg_round1
                                .round1_packages
                                .into_iter()
                                .map(|(id, pkg): (Identifier, Round1Package)| {
                                    Ok((
                                        id.serialize().to_vec(),
                                        pkg.serialize()
                                            .map_err(|e| DkgError::FrostError(e.to_string()))?,
                                    ))
                                })
                                .collect::<Result<_, DkgError>>()?,
                        },
                        Err(e) => FrostDkgState::Failed {
                            round: 1,
                            error: e.to_string(),
                        },
                    }
                }
                FrostDkgState::Round1Complete {
                    round1_secret,
                    round1_received,
                } => {
                    let secret = Round1SecretPackage::deserialize(&round1_secret)
                        .map_err(|err| DkgError::FrostError(err.to_string()))?;

                    let received: BTreeMap<Identifier, Round1Package> = round1_received
                        .iter()
                        .map(|(id, bytes)| {
                            let identifier = Identifier::deserialize(id)
                                .map_err(|e| DkgError::FrostError(e.to_string()))?;
                            let package = Round1Package::deserialize(bytes)
                                .map_err(|e| DkgError::FrostError(e.to_string()))?;
                            Ok((identifier, package))
                        })
                        .collect::<Result<_, DkgError>>()?;

                    let round2 = dkg_runner
                        .run_round2(
                            &self.session_id,
                            &self.participants,
                            &self.participant_id,
                            secret,
                            &received,
                        )
                        .await;

                    match round2 {
                        Ok(dkg_round2) => FrostDkgState::Round2Complete {
                            round1_received,
                            round2_secret: dkg_round2
                                .round2_secret_package
                                .serialize()
                                .map_err(|err| DkgError::FrostError(err.to_string()))?,
                            round2_received: dkg_round2
                                .round2_received
                                .into_iter()
                                .map(|(id, pkg): (Identifier, Round2Package)| {
                                    Ok((
                                        id.serialize().to_vec(),
                                        pkg.serialize().map_err(|e: Error| {
                                            DkgError::FrostError(e.to_string())
                                        })?,
                                    ))
                                })
                                .collect::<Result<_, DkgError>>()?,
                        },
                        Err(err) => FrostDkgState::Failed {
                            round: 2,
                            error: err.to_string(),
                        },
                    }
                }
                FrostDkgState::Round2Complete {
                    round1_received,
                    round2_secret,
                    round2_received,
                } => {
                    let r1: BTreeMap<Identifier, Round1Package> = round1_received
                        .iter()
                        .map(|(id, b)| {
                            let identifier = Identifier::deserialize(id)
                                .map_err(|e| DkgError::FrostError(e.to_string()))?;
                            let package = Round1Package::deserialize(b)
                                .map_err(|e| DkgError::FrostError(e.to_string()))?;
                            Ok((identifier, package))
                        })
                        .collect::<Result<_, DkgError>>()?;

                    let secret2 = Round2SecretPackage::deserialize(&round2_secret)
                        .map_err(|e| DkgError::FrostError(e.to_string()))?;

                    let r2: BTreeMap<Identifier, Round2Package> = round2_received
                        .iter()
                        .map(|(id, b)| {
                            let identifier = Identifier::deserialize(id)
                                .map_err(|e| DkgError::FrostError(e.to_string()))?;
                            let package = Round2Package::deserialize(b)
                                .map_err(|e| DkgError::FrostError(e.to_string()))?;
                            Ok((identifier, package))
                        })
                        .collect::<Result<_, DkgError>>()?;

                    let round3 = dkg_runner.finalize(&r1, &secret2, &r2);

                    match round3 {
                        Ok(dkg_result) => FrostDkgState::Finalized {
                            key_package: dkg_result
                                .key_package
                                .serialize()
                                .map_err(|err| DkgError::FrostError(err.to_string()))?,
                            public_key_package: dkg_result
                                .pubkey_package
                                .serialize()
                                .map_err(|err| DkgError::FrostError(err.to_string()))?,
                        },
                        Err(err) => FrostDkgState::Failed {
                            round: 3,
                            error: err.to_string(),
                        },
                    }
                }
                FrostDkgState::Finalized {
                    key_package,
                    public_key_package,
                } => {
                    let kp = KeyPackage::deserialize(&key_package)
                        .map_err(|e| DkgError::FrostError(e.to_string()))?;

                    let pkp = PublicKeyPackage::deserialize(&public_key_package)
                        .map_err(|e| DkgError::FrostError(e.to_string()))?;

                    return Ok(DkgResult {
                        key_package: kp,
                        pubkey_package: pkp,
                    });
                }
                FrostDkgState::Failed { round, error } => {
                    Self::persist_state(
                        db,
                        self.session_id,
                        FrostDkgState::Failed {
                            round,
                            error: error.clone(),
                        },
                    )
                    .await;
                    return Err(DkgError::FrostError(format!(
                        "round {round} failed: {error}"
                    )));
                }
            };
            Self::persist_state(db, self.session_id, state.clone()).await;
        }
    }
}
