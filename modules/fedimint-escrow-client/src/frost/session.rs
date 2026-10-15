use std::collections::BTreeMap;
use std::time::Duration;

use fedimint_core::BitcoinHash;
use fedimint_core::bitcoin::XOnlyPublicKey;
use fedimint_core::bitcoin::hashes::{HashEngine, sha256};
use fedimint_core::config::FederationId;
use fedimint_core::db::{Database, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::encoding::{Decodable, DecodeError, Encodable};
use fedimint_core::runtime::sleep;
use fedimint_core::secp256k1::PublicKey;
use fedimint_escrow_common::x_only;
use frost_secp256k1_tr;
use frost_secp256k1_tr::keys::dkg::round1::{
    Package as Round1Package, SecretPackage as Round1SecretPackage,
};
use frost_secp256k1_tr::keys::dkg::round2::{
    Package as Round2Package, SecretPackage as Round2SecretPackage,
};
use frost_secp256k1_tr::keys::{KeyPackage, PublicKeyPackage};
use frost_secp256k1_tr::{Error, Identifier};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use tracing::warn;

use crate::client_db::{FrostDkgSessionKey, FrostDkgSessionRecordkey};
use crate::frost::dkg::{DkgError, DkgResult, DkgRunner};
use crate::frost::transport::DkgTransport;

const MAX_ATTEMPTS: u32 = 3;
const RETRY_DELAY: Duration = Duration::from_secs(3);

#[derive(Debug, Clone, Copy, Hash, Encodable, Decodable, PartialEq, Eq, PartialOrd, Ord)]
pub struct SessionId(pub [u8; 32]);

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

        let identifier = Identifier::deserialize(&identifier_bytes)
            .map_err(|e| DecodeError::custom(format!("Invalid FROST identifier: {e}")))?;

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
        let identifier = Identifier::derive(&x_only(&pubkey).serialize())?;

        Ok(Self { identifier })
    }
}

#[derive(Debug, Clone, Encodable, Decodable, Serialize, Deserialize)]
pub enum FrostDkgState {
    Created,
    Round1Started {
        round1_secret: Vec<u8>,
        round1_package: Vec<u8>,
    },
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

fn frost_err(e: Error) -> DkgError {
    DkgError::FrostError(e.to_string())
}

fn decode_map<T>(
    map: &BTreeMap<Vec<u8>, Vec<u8>>,
    de: impl Fn(&[u8]) -> Result<T, Error>,
) -> Result<BTreeMap<Identifier, T>, DkgError> {
    let mut out = BTreeMap::new();
    for (id, bytes) in map {
        out.insert(
            Identifier::deserialize(id).map_err(frost_err)?,
            de(bytes.as_slice()).map_err(frost_err)?,
        );
    }
    Ok(out)
}

fn encode_map<T>(
    map: &BTreeMap<Identifier, T>,
    ser: impl Fn(&T) -> Result<Vec<u8>, Error>,
) -> Result<BTreeMap<Vec<u8>, Vec<u8>>, DkgError> {
    let mut out = BTreeMap::new();
    for (id, value) in map {
        out.insert(id.serialize().to_vec(), ser(value).map_err(frost_err)?);
    }
    Ok(out)
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

    pub async fn load_dkg_result(
        db: &Database,
        session_id: SessionId,
    ) -> Result<DkgResult, DkgError> {
        let mut dbtx = db.begin_transaction_nc().await;
        let session: Option<FrostDkgSession> =
            dbtx.get_value(&FrostDkgSessionKey(session_id)).await;

        match session.map(|s| s.state) {
            Some(FrostDkgState::Finalized {
                key_package,
                public_key_package,
            }) => Ok(DkgResult {
                key_package: KeyPackage::deserialize(&key_package)
                    .map_err(|e| DkgError::FrostError(e.to_string()))?,
                pubkey_package: PublicKeyPackage::deserialize(&public_key_package)
                    .map_err(|e| DkgError::FrostError(e.to_string()))?,
            }),
            _ => Err(DkgError::FrostError(
                "Consortium DKG is not finished".to_string(),
            )),
        }
    }

    pub fn consortium_pubkey(pubkey_package: &PublicKeyPackage) -> Result<PublicKey, DkgError> {
        let bytes = pubkey_package
            .verifying_key()
            .serialize()
            .map_err(|e| DkgError::FrostError(e.to_string()))?;

        match bytes.len() {
            33 => PublicKey::from_slice(&bytes).map_err(|e| DkgError::FrostError(e.to_string())),

            32 => {
                let xonly = XOnlyPublicKey::from_slice(&bytes)
                    .map_err(|e| DkgError::FrostError(e.to_string()))?;

                Ok(PublicKey::from_x_only_public_key(
                    xonly,
                    fedimint_core::secp256k1::Parity::Even,
                ))
            }

            len => Err(DkgError::FrostError(format!(
                "invalid FROST verifying key length: {len}"
            ))),
        }
    }

    async fn persist_state(db: &Database, session_id: SessionId, state: FrostDkgState) {
        let mut dbtx = db.begin_transaction().await;
        dbtx.insert_entry(&FrostDkgSessionKey(session_id), &FrostDkgSession { state })
            .await;
        dbtx.commit_tx().await;
    }

    async fn load_state(db: &Database, session_id: SessionId) -> FrostDkgState {
        let mut dbtx = db.begin_transaction_nc().await;
        dbtx.get_value(&FrostDkgSessionKey(session_id))
            .await
            .map(|s: FrostDkgSession| s.state)
            .unwrap_or(FrostDkgState::Created)
    }

    async fn clear_state(db: &Database, session_id: SessionId) {
        let mut dbtx = db.begin_transaction().await;
        dbtx.remove_entry(&FrostDkgSessionKey(session_id)).await;
        dbtx.commit_tx().await;
    }

    pub async fn reset(&self, db: &Database) -> anyhow::Result<()> {
        let mut dbtx = db.begin_transaction().await;
        if let Some(FrostDkgSession {
            state: FrostDkgState::Finalized { .. },
        }) = dbtx.get_value(&FrostDkgSessionKey(self.session_id)).await
        {
            anyhow::bail!(
                "the consortium key already exists; resetting would destroy this arbiter's key share"
            );
        }
        dbtx.remove_entry(&FrostDkgSessionKey(self.session_id))
            .await;
        dbtx.commit_tx().await;
        Ok(())
    }

    /// Runs the DKG from the last saved step.
    pub async fn run<T: DkgTransport>(
        &self,
        db: &Database,
        transport: T,
    ) -> Result<DkgResult, DkgError> {
        let runner = DkgRunner::new(transport);
        let mut state = Self::load_state(db, self.session_id).await;
        let mut failures = 0u32;

        loop {
            if let FrostDkgState::Finalized {
                key_package,
                public_key_package,
            } = &state
            {
                return Ok(DkgResult {
                    key_package: KeyPackage::deserialize(key_package).map_err(frost_err)?,
                    pubkey_package: PublicKeyPackage::deserialize(public_key_package)
                        .map_err(frost_err)?,
                });
            }

            let result = self.advance(&runner, &state).await;
            match result {
                Ok(next) => {
                    Self::persist_state(db, self.session_id, next.clone()).await;
                    state = next;
                    failures = 0;
                }
                Err(e) if e.is_transient() => {
                    failures += 1;
                    warn!("DKG step failed ({failures}/{MAX_ATTEMPTS}): {e}");
                    if failures >= MAX_ATTEMPTS {
                        return Err(e);
                    }
                    sleep(RETRY_DELAY).await;
                }
                Err(e) => {
                    warn!("DKG attempt failed, discarding its state: {e}");
                    Self::clear_state(db, self.session_id).await;
                    return Err(e);
                }
            }
        }
    }

    /// One step of the protocol: takes the saved state, returns the next state.
    async fn advance<T: DkgTransport>(
        &self,
        runner: &DkgRunner<T>,
        state: &FrostDkgState,
    ) -> Result<FrostDkgState, DkgError> {
        match state {
            FrostDkgState::Created | FrostDkgState::Failed { .. } => {
                let (secret, package) = runner.start_round1(
                    &self.participant_id,
                    self.max_signers,
                    self.min_signers,
                )?;
                Ok(FrostDkgState::Round1Started {
                    round1_secret: secret.serialize().map_err(frost_err)?,
                    round1_package: package.serialize().map_err(frost_err)?,
                })
            }
            FrostDkgState::Round1Started {
                round1_secret,
                round1_package,
            } => {
                let package = Round1Package::deserialize(round1_package).map_err(frost_err)?;
                let received = runner
                    .exchange_round1(
                        &self.session_id,
                        &self.participant_id,
                        &self.participants,
                        package,
                    )
                    .await?;
                Ok(FrostDkgState::Round1Complete {
                    round1_secret: round1_secret.clone(),
                    round1_received: encode_map(&received, |p| p.serialize())?,
                })
            }
            FrostDkgState::Round1Complete {
                round1_secret,
                round1_received,
            } => {
                let secret = Round1SecretPackage::deserialize(round1_secret).map_err(frost_err)?;
                let received = decode_map(round1_received, |b| Round1Package::deserialize(b))?;
                let round2 = runner
                    .run_round2(
                        &self.session_id,
                        &self.participants,
                        &self.participant_id,
                        secret,
                        &received,
                    )
                    .await?;
                Ok(FrostDkgState::Round2Complete {
                    round1_received: round1_received.clone(),
                    round2_secret: round2
                        .round2_secret_package
                        .serialize()
                        .map_err(frost_err)?,
                    round2_received: encode_map(&round2.round2_received, |p| p.serialize())?,
                })
            }
            FrostDkgState::Round2Complete {
                round1_received,
                round2_secret,
                round2_received,
            } => {
                let r1 = decode_map(round1_received, |b| Round1Package::deserialize(b))?;
                let secret2 = Round2SecretPackage::deserialize(round2_secret).map_err(frost_err)?;
                let r2 = decode_map(round2_received, |b| Round2Package::deserialize(b))?;
                let result = runner.finalize(&r1, &secret2, &r2)?;
                Ok(FrostDkgState::Finalized {
                    key_package: result.key_package.serialize().map_err(frost_err)?,
                    public_key_package: result.pubkey_package.serialize().map_err(frost_err)?,
                })
            }
            FrostDkgState::Finalized { .. } => {
                Err(DkgError::Other(anyhow::anyhow!("DKG is already finished")))
            }
        }
    }
}
