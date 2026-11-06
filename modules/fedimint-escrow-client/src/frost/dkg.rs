use std::collections::BTreeMap;

use fedimint_core::bitcoin::hashes::{Hash, HashEngine, sha256};
use frost_secp256k1_tr::Identifier;
use frost_secp256k1_tr::keys::dkg::round1::{
    Package as Round1Package, SecretPackage as Round1SecretPackage,
};
use frost_secp256k1_tr::keys::dkg::round2::{
    Package as Round2Package, SecretPackage as Round2SecretPackage,
};
use frost_secp256k1_tr::keys::{KeyPackage, PublicKeyPackage};
use rand::rngs::OsRng;

use crate::frost::session::{FrostParticipant, SessionId};
use crate::frost::transport::{DkgTransport, TransportError};

const ROUND_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

pub struct DkgRound1 {
    pub round1_packages: BTreeMap<Identifier, Round1Package>,
    pub round1_secret_package: Round1SecretPackage,
}

pub struct DkgRound2 {
    pub round2_received: BTreeMap<Identifier, Round2Package>,
    pub round2_secret_package: Round2SecretPackage,
}

pub struct DkgResult {
    pub key_package: KeyPackage,
    pub pubkey_package: PublicKeyPackage,
}

#[derive(Debug, thiserror::Error)]
pub enum DkgError {
    #[error("transport error: {0}")]
    TransportError(#[from] TransportError),
    #[error("frost protocol error: {0}")]
    FrostError(String),
    #[error("these members have another key than this one: {0:?}")]
    KeyMismatch(Vec<Identifier>),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

fn frost_error(e: frost_secp256k1_tr::Error) -> DkgError {
    DkgError::FrostError(e.to_string())
}

/// What every member must agree on before the key is used: the group key and
/// the verifying share of every member.
pub fn key_digest(
    session_id: &SessionId,
    pubkey_package: &PublicKeyPackage,
) -> Result<[u8; 32], DkgError> {
    let mut engine = sha256::HashEngine::default();
    engine.input(b"fedimint_escrow_dkg_key_confirmation");
    engine.input(&session_id.0);
    engine.input(
        &pubkey_package
            .verifying_key()
            .serialize()
            .map_err(frost_error)?,
    );
    // a BTreeMap, so everybody hashes the shares in the same order
    for (id, share) in pubkey_package.verifying_shares() {
        engine.input(&id.serialize());
        engine.input(&share.serialize().map_err(frost_error)?);
    }
    Ok(sha256::Hash::from_engine(engine).to_byte_array())
}

impl DkgError {
    /// Retrying the same step can succeed (peer offline, timeout, ...).
    /// Anything else means the data of this attempt is bad.
    pub fn is_transient(&self) -> bool {
        matches!(
            self,
            DkgError::TransportError(e)
                if !matches!(
                    e,
                    TransportError::SessionMismatch { .. }
                        | TransportError::InvalidReceiver
                        | TransportError::Serialization(_)
                )
        )
    }
}

pub struct DkgRunner<T> {
    transport: T,
}

impl<T: DkgTransport> DkgRunner<T> {
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    pub fn start_round1(
        &self,
        participant_id: &FrostParticipant,
        max_signers: u16,
        min_signers: u16,
    ) -> Result<(Round1SecretPackage, Round1Package), DkgError> {
        frost_secp256k1_tr::keys::dkg::part1(
            participant_id.identifier,
            max_signers,
            min_signers,
            OsRng,
        )
        .map_err(|e| DkgError::FrostError(e.to_string()))
    }

    /// Sends an already created round 1 package and waits for everyone else's.
    pub async fn exchange_round1(
        &self,
        session_id: &SessionId,
        participant_id: &FrostParticipant,
        participants: &[FrostParticipant],
        package: Round1Package,
    ) -> Result<BTreeMap<Identifier, Round1Package>, DkgError> {
        self.transport
            .broadcast_round1(session_id, &participant_id.identifier, package)
            .await?;

        let receiver: Vec<Identifier> = participants.iter().map(|p| p.identifier).collect();
        let mut packages = self
            .transport
            .recv_round1_all(
                session_id,
                &participant_id.identifier,
                &receiver,
                ROUND_TIMEOUT,
            )
            .await?;

        packages.remove(&participant_id.identifier);
        Ok(packages)
    }

    pub async fn run_round2(
        &self,
        session_id: &SessionId,
        participants: &[FrostParticipant],
        participant_id: &FrostParticipant,
        round1_secret: Round1SecretPackage,
        round1_received: &BTreeMap<Identifier, Round1Package>,
    ) -> Result<DkgRound2, DkgError> {
        let (round2_secret_package, round2_package) =
            frost_secp256k1_tr::keys::dkg::part2(round1_secret.clone(), round1_received)
                .map_err(|e| DkgError::FrostError(e.to_string()))?;

        let mut first_err = None;
        for (receiver, pkg) in round2_package {
            if let Err(e) = self
                .transport
                .send_round2(session_id, &participant_id.identifier, &receiver, pkg)
                .await
            {
                tracing::warn!("round 2: could not reach {receiver:?}: {e}");
                first_err.get_or_insert(e);
            }
        }
        if let Some(e) = first_err {
            return Err(e.into());
        }

        let expected: Vec<Identifier> = participants.iter().map(|p| p.identifier).collect();

        let mut round2_received = self
            .transport
            .recv_round2(
                session_id,
                &participant_id.identifier,
                &expected,
                ROUND_TIMEOUT,
            )
            .await?;

        round2_received.remove(&participant_id.identifier);

        Ok(DkgRound2 {
            round2_received,
            round2_secret_package,
        })
    }

    pub fn finalize(
        &self,
        round1_received: &BTreeMap<Identifier, Round1Package>,
        round2_secret: &Round2SecretPackage,
        round2_received: &BTreeMap<Identifier, Round2Package>,
    ) -> Result<DkgResult, DkgError> {
        frost_secp256k1_tr::keys::dkg::part3(round2_secret, round1_received, round2_received)
            .map(|(key_package, pubkey_package)| DkgResult {
                key_package,
                pubkey_package,
            })
            .map_err(|e| DkgError::FrostError(e.to_string()))
    }

    pub async fn confirm_key(
        &self,
        session_id: &SessionId,
        participant_id: &FrostParticipant,
        participants: &[FrostParticipant],
        pubkey_package: &PublicKeyPackage,
    ) -> Result<(), DkgError> {
        let digest = key_digest(session_id, pubkey_package)?;
        self.transport
            .broadcast_confirmation(session_id, &participant_id.identifier, digest)
            .await?;

        let others: Vec<Identifier> = participants
            .iter()
            .map(|participant| participant.identifier)
            .filter(|id| *id != participant_id.identifier)
            .collect();
        let received = self
            .transport
            .recv_confirmations(
                session_id,
                &participant_id.identifier,
                &others,
                ROUND_TIMEOUT,
            )
            .await?;

        let disagreeing: Vec<Identifier> = others
            .into_iter()
            .filter(|id| received.get(id) != Some(&digest))
            .collect();
        if disagreeing.is_empty() {
            Ok(())
        } else {
            Err(DkgError::KeyMismatch(disagreeing))
        }
    }
}
