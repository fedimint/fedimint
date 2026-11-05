use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use fedimint_core::runtime::{sleep, spawn, timeout};
use fedimint_core::secp256k1::{self, Message, schnorr};
use fedimint_core::time::{duration_since_epoch, now};
use fedimint_escrow_common::{EscrowId, Outcome};
use frost_secp256k1_tr as frost;
use frost_secp256k1_tr::Identifier;
use frost_secp256k1_tr::keys::{KeyPackage, PublicKeyPackage};
use frost_secp256k1_tr::round1::SigningCommitments;
use frost_secp256k1_tr::round2::SignatureShare;
use futures::future::{join_all, try_join_all};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::frost::dkg::DkgError;
use crate::frost::session::{FrostDkgSessionRecord, FrostParticipant};
use crate::frost::transport::{SigningTransport, TransportError};

/// Maximum size of a message from another arbiter
const MAX_MESSAGE_BYTES: usize = 64 * 1024;
/// Maximum lifetime of a vote
const MAX_VOTE_LIFETIME: Duration = Duration::from_secs(60 * 60);
/// Time after which messages nobody read are dropped from the inbox
const INBOX_MESSAGE_LIFETIME: Duration = Duration::from_secs(60 * 60);
/// Maximum time to send a message to an arbiter
const SEND_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_QUEUED_MESSAGES_PER_ESCROW: usize = 128;
const MAX_QUEUED_ESCROWS: usize = 1024;

#[derive(Debug, thiserror::Error)]
pub enum SigningError {
    #[error("transport error: {0}")]
    Transport(#[from] TransportError),
    #[error("frost error: {0}")]
    Frost(String),
    #[error(transparent)]
    Dkg(#[from] DkgError),
    #[error("message encoding error: {0}")]
    Encoding(#[from] serde_json::Error),
    #[error("no outcome got enough votes")]
    NoQuorum,
    #[error("the coordinator asked to sign something the arbiter did not vote for")]
    MessageMismatch,
    #[error("invalid signing package: {0}")]
    InvalidPackage(&'static str),
    #[error("the split of the outcome does not add up to 100%")]
    InvalidOutcome,
    #[error("this escrow is already being signed on this node")]
    AlreadyInProgress,
    #[error("arbiter {0:?} sent an invalid signature share")]
    BadShares(Vec<Identifier>),
    #[error("arbiters did not send their signature share: {0:?}")]
    MissingShares(Vec<Identifier>),
    #[error("the signature does not verify against the consortium key")]
    BadSignature,
    #[error("timed out")]
    Timeout,
}

impl From<frost::Error> for SigningError {
    fn from(e: frost::Error) -> Self {
        SigningError::Frost(e.to_string())
    }
}

/// Messages arbiters send to each other while signing a decision
#[derive(Clone, Serialize, Deserialize)]
enum ArbiterMessage {
    /// Sent by every arbiter to the coordinator, with the outcome it wants and
    /// its commitment. Ignored after `expires_at`.
    Vote {
        outcome: Outcome,
        commitments: Vec<u8>,
        expires_at: SystemTime,
    },
    /// Sent by the coordinator to the arbiters chosen to sign.
    Request { signing_package: Vec<u8> },
    /// Sent by a chosen arbiter to the coordinator. The commitment is the one
    /// it voted with, so the coordinator can tell which signing the share is
    /// for.
    Share {
        commitments: Vec<u8>,
        share: Vec<u8>,
    },
    /// Sent by the coordinator to all arbiters once the decision is signed.
    Finished {
        outcome: Outcome,
        signature: Vec<u8>,
    },
}

/// An [`ArbiterMessage`] with the escrow it belongs to, which is what
/// [`SigningMux`] sorts the messages by.
#[derive(Serialize, Deserialize)]
struct ArbiterEnvelope {
    escrow_id: EscrowId,
    message: ArbiterMessage,
}

struct QueuedArbiterMessage {
    from: Identifier,
    message: ArbiterMessage,
    received_at: SystemTime,
}

/// Sorts the signing messages by escrow.
///
/// [`SigningTransport::recv`] is a single queue, so signings of different
/// escrows reading from it would take each other's messages. The mux is the
/// only reader of the transport and every signing reads the inbox of its own
/// escrow.
pub struct SigningMux<T: SigningTransport + 'static> {
    transport: Arc<T>,
    caller: Identifier,
    participants: BTreeSet<Identifier>,
    inbox: Mutex<HashMap<[u8; 32], VecDeque<QueuedArbiterMessage>>>,
    active_escrows: Mutex<HashSet<[u8; 32]>>,
}

impl<T: SigningTransport + 'static> SigningMux<T> {
    /// Starts reading from the transport, stops when the last `Arc` is dropped
    pub fn start(
        transport: Arc<T>,
        caller: &FrostParticipant,
        participants: &[FrostParticipant],
    ) -> Arc<Self> {
        let mux = Arc::new(Self {
            transport,
            caller: caller.identifier,
            participants: participants.iter().map(|p| p.identifier).collect(),
            inbox: Mutex::default(),
            active_escrows: Mutex::default(),
        });

        let weak_mux = Arc::downgrade(&mux);
        spawn("frost-signing-mux", async move {
            while let Some(mux) = weak_mux.upgrade() {
                let (from, bytes) = match mux
                    .transport
                    .recv(&mux.caller, Duration::from_secs(2))
                    .await
                {
                    Ok(received) => received,
                    Err(TransportError::TimeoutError) => continue,
                    Err(e) => {
                        warn!("signing transport failed to receive: {e}");
                        sleep(Duration::from_secs(1)).await;
                        continue;
                    }
                };

                if from == mux.caller
                    || !mux.participants.contains(&from)
                    || bytes.len() > MAX_MESSAGE_BYTES
                {
                    warn!("dropping signing message from {from:?}");
                    continue;
                }
                let Ok(envelope) = serde_json::from_slice::<ArbiterEnvelope>(&bytes) else {
                    warn!("dropping malformed signing message from {from:?}");
                    continue;
                };

                let expired = |queued: &QueuedArbiterMessage| {
                    now().duration_since(queued.received_at).unwrap_or_default()
                        >= INBOX_MESSAGE_LIFETIME
                };
                let mut inbox = mux.inbox.lock().unwrap();
                if inbox.len() >= MAX_QUEUED_ESCROWS && !inbox.contains_key(&envelope.escrow_id.0) {
                    inbox.retain(|_, queue| queue.back().is_some_and(|queued| !expired(queued)));
                    if inbox.len() >= MAX_QUEUED_ESCROWS {
                        warn!("signing inbox is full, dropping message from {from:?}");
                        continue;
                    }
                }
                let queue = inbox.entry(envelope.escrow_id.0).or_default();
                while queue.front().is_some_and(expired) {
                    queue.pop_front();
                }
                if queue.len() >= MAX_QUEUED_MESSAGES_PER_ESCROW {
                    queue.pop_front();
                }
                queue.push_back(QueuedArbiterMessage {
                    from,
                    message: envelope.message,
                    received_at: now(),
                });
            }
        });

        mux
    }

    async fn send(
        &self,
        to: &Identifier,
        escrow_id: EscrowId,
        message: ArbiterMessage,
    ) -> Result<(), SigningError> {
        let envelope = serde_json::to_vec(&ArbiterEnvelope { escrow_id, message })?;
        timeout(
            SEND_TIMEOUT,
            self.transport.send(&self.caller, to, envelope),
        )
        .await
        .map_err(|_| SigningError::Timeout)??;
        Ok(())
    }

    async fn recv(
        &self,
        escrow_id: &EscrowId,
        deadline: SystemTime,
    ) -> Result<(Identifier, ArbiterMessage), SigningError> {
        loop {
            if let Some(queued) = self
                .inbox
                .lock()
                .unwrap()
                .get_mut(&escrow_id.0)
                .and_then(|queue| queue.pop_front())
            {
                return Ok((queued.from, queued.message));
            }
            if now() >= deadline {
                return Err(SigningError::Timeout);
            }
            sleep(Duration::from_millis(100)).await;
        }
    }

    #[cfg(test)]
    pub(crate) fn has_active_escrows(&self) -> bool {
        !self.active_escrows.lock().unwrap().is_empty()
    }
}

/// Marks an escrow as being signed until dropped, which includes the signing
/// being cancelled.
struct ActiveEscrow<'a> {
    active_escrows: &'a Mutex<HashSet<[u8; 32]>>,
    escrow_id: EscrowId,
}

impl Drop for ActiveEscrow<'_> {
    fn drop(&mut self) {
        self.active_escrows
            .lock()
            .unwrap()
            .remove(&self.escrow_id.0);
    }
}

/// Returns the `Outcome` submitted by min_signers
pub fn pick_outcome(votes: &[Outcome], min_signers: u16) -> Option<Outcome> {
    for candidate in votes {
        let count = votes.iter().filter(|o| *o == candidate).count();
        if count >= min_signers as usize {
            return Some(*candidate);
        }
    }
    None
}

#[derive(Debug)]
pub enum SignerOutcome {
    /// The coordinator finished and the signature is valid for the consortium
    /// key.
    Final {
        outcome: Outcome,
        signature: schnorr::Signature,
    },
    /// The signature share was sent but the result did not arrive in time.
    ShareSent,
}

/// Votes for `caller_outcome` and signs it if the coordinator asks, then waits
/// for the result.
///
/// Fails with [`SigningError::Timeout`] if the arbiter is neither asked to
/// sign nor told the result before `timeout`.
pub async fn sign_as_signer<T: SigningTransport + 'static>(
    mux: &SigningMux<T>,
    coordinator: &Identifier,
    key_package: &KeyPackage,
    escrow_id: EscrowId,
    caller_outcome: Outcome,
    decision_hash_for: impl Fn(Outcome) -> [u8; 32],
    timeout: Duration,
) -> Result<SignerOutcome, SigningError> {
    if !caller_outcome.is_valid() {
        return Err(SigningError::InvalidOutcome);
    }

    let deadline = now().checked_add(timeout).ok_or(SigningError::Timeout)?;
    let min_signers = *key_package.min_signers() as usize;
    let caller_decision_hash = decision_hash_for(caller_outcome);

    // the nonces are used for a single share and never stored
    let (nonces, commitments) = frost::round1::commit(key_package.signing_share(), &mut OsRng);
    let mut nonces = Some(nonces);
    let commitments_bytes = commitments.serialize()?;
    mux.send(
        coordinator,
        escrow_id,
        ArbiterMessage::Vote {
            outcome: caller_outcome,
            commitments: commitments_bytes.clone(),
            expires_at: deadline,
        },
    )
    .await?;

    let mut share_sent = false;
    loop {
        let (from, message) = match mux.recv(&escrow_id, deadline).await {
            Err(SigningError::Timeout) if share_sent => return Ok(SignerOutcome::ShareSent),
            other => other?,
        };

        match message {
            ArbiterMessage::Request { signing_package } if from == *coordinator => {
                let package = frost::SigningPackage::deserialize(&signing_package)?;

                // the package belongs to an earlier attempt
                if package.signing_commitments().get(&mux.caller) != Some(&commitments) {
                    continue;
                }
                if package.signing_commitments().len() < min_signers
                    || package
                        .signing_commitments()
                        .keys()
                        .any(|id| !mux.participants.contains(id))
                {
                    return Err(SigningError::InvalidPackage("bad set of signers"));
                }

                if package.message() != caller_decision_hash.as_slice() {
                    return Err(SigningError::MessageMismatch);
                }

                let Some(nonces) = nonces.take() else {
                    continue;
                };
                let share = frost::round2::sign(&package, &nonces, key_package)?;
                mux.send(
                    coordinator,
                    escrow_id,
                    ArbiterMessage::Share {
                        commitments: commitments_bytes.clone(),
                        share: share.serialize(),
                    },
                )
                .await?;
                share_sent = true;
            }
            // verified against the consortium key, so any arbiter can send it
            ArbiterMessage::Finished { outcome, signature } => {
                if let Ok(frost_signature) = frost::Signature::deserialize(&signature)
                    && key_package
                        .verifying_key()
                        .verify(&decision_hash_for(outcome), &frost_signature)
                        .is_ok()
                    && let Ok(signature) = schnorr::Signature::from_slice(&signature)
                {
                    return Ok(SignerOutcome::Final { outcome, signature });
                }
            }
            _ => {}
        }
    }
}

/// Collects the votes of the arbiters and signs the outcome that got
/// `min_signers` of them. Votes too, and signs if its vote wins.
///
/// Returns the outcome with a BIP340 signature, which the funder or recipient
/// submits with `submit_arbiter_decision`.
pub async fn sign_as_coordinator<T: SigningTransport + 'static>(
    mux: &SigningMux<T>,
    key_package: &KeyPackage,
    pubkey_package: &PublicKeyPackage,
    escrow_id: EscrowId,
    caller_outcome: Outcome,
    decision_hash_for: impl Fn(Outcome) -> [u8; 32],
    timeout: Duration,
) -> Result<(Outcome, schnorr::Signature), SigningError> {
    if !caller_outcome.is_valid() {
        return Err(SigningError::InvalidOutcome);
    }

    let min_signers = *key_package.min_signers() as usize;
    let deadline = now().checked_add(timeout).ok_or(SigningError::Timeout)?;
    let consortium_pubkey = FrostDkgSessionRecord::consortium_pubkey(pubkey_package)?;

    let (caller_nonces, caller_commitments) =
        frost::round1::commit(key_package.signing_share(), &mut OsRng);
    let mut votes = BTreeMap::new();
    votes.insert(mux.caller, (caller_outcome, caller_commitments));

    let winner = loop {
        let outcomes: Vec<Outcome> = votes.values().map(|(outcome, _)| *outcome).collect();
        if let Some(winner) = pick_outcome(&outcomes, min_signers as u16) {
            break winner;
        }

        let (from, message) = match mux.recv(&escrow_id, deadline).await {
            Err(SigningError::Timeout) => return Err(SigningError::NoQuorum),
            other => other?,
        };
        let ArbiterMessage::Vote {
            outcome,
            commitments,
            expires_at,
        } = message
        else {
            continue;
        };

        if expires_at <= now() || expires_at > now() + MAX_VOTE_LIFETIME || !outcome.is_valid() {
            continue;
        }

        if let Ok(commitments) = SigningCommitments::deserialize(&commitments) {
            // the latest vote of an arbiter counts
            votes.insert(from, (outcome, commitments));
        }
    };

    let mut signers: Vec<Identifier> = votes
        .iter()
        .filter(|(id, (outcome, _))| **id != mux.caller && *outcome == winner)
        .map(|(id, _)| *id)
        .collect();
    if caller_outcome == winner {
        signers.insert(0, mux.caller);
    }
    signers.truncate(min_signers);

    let commitments: BTreeMap<_, _> = signers.iter().map(|id| (*id, votes[id].1)).collect();
    let decision_hash = decision_hash_for(winner);
    let package = frost::SigningPackage::new(commitments, &decision_hash);

    let request = ArbiterMessage::Request {
        signing_package: package.serialize()?,
    };
    try_join_all(
        signers
            .iter()
            .filter(|id| **id != mux.caller)
            .map(|id| mux.send(id, escrow_id, request.clone())),
    )
    .await?;

    let mut shares = BTreeMap::new();
    if signers.contains(&mux.caller) {
        shares.insert(
            mux.caller,
            frost::round2::sign(&package, &caller_nonces, key_package)?,
        );
    }
    while shares.len() < signers.len() {
        let (from, message) = match mux.recv(&escrow_id, deadline).await {
            Err(SigningError::Timeout) => {
                return Err(SigningError::MissingShares(
                    signers
                        .iter()
                        .filter(|id| !shares.contains_key(*id))
                        .copied()
                        .collect(),
                ));
            }
            other => other?,
        };
        let ArbiterMessage::Share { commitments, share } = message else {
            continue;
        };
        // only a share made for the commitment in this package counts
        if !signers.contains(&from)
            || shares.contains_key(&from)
            || package.signing_commitments().get(&from)
                != SigningCommitments::deserialize(&commitments).ok().as_ref()
        {
            continue;
        }
        let share =
            SignatureShare::deserialize(&share).map_err(|_| SigningError::BadShares(vec![from]))?;
        shares.insert(from, share);
    }

    let signature = frost::aggregate(&package, &shares, pubkey_package).map_err(|e| {
        let culprits = e.culprits();

        if culprits.is_empty() {
            SigningError::Frost(e.to_string())
        } else {
            SigningError::BadShares(culprits)
        }
    })?;
    let signature = schnorr::Signature::from_slice(&signature.serialize()?)
        .map_err(|e| SigningError::Frost(e.to_string()))?;

    // this is what the federation checks
    secp256k1::global::SECP256K1
        .verify_schnorr(
            &signature,
            &Message::from_digest(decision_hash),
            &consortium_pubkey.x_only_public_key().0,
        )
        .map_err(|_| SigningError::BadSignature)?;

    let finished = &ArbiterMessage::Finished {
        outcome: winner,
        signature: signature.as_ref().to_vec(),
    };
    join_all(
        mux.participants
            .iter()
            .filter(|id| **id != mux.caller)
            .map(|id| async move {
                if let Err(e) = mux.send(id, escrow_id, finished.clone()).await {
                    warn!("could not send the result to {id:?}: {e}");
                }
            }),
    )
    .await;

    Ok((winner, signature))
}

/// Signs the decision on an escrow together with the other arbiters of the
/// consortium. Every arbiter calls it with the outcome they chose.
///
/// Time is divided into slots of `slot`. The coordinator of a slot is derived
/// from the escrow id and the slot number, so the arbiters agree on it without
/// talking to each other. If a slot fails, for example because its coordinator
/// is offline, the next slot continues with another coordinator.
///
/// The clocks of the arbiters have to be in sync. `timeout` is checked at the
/// start of every slot.
#[allow(clippy::too_many_arguments)]
pub async fn sign_with_failover<T: SigningTransport + 'static>(
    mux: &SigningMux<T>,
    key_package: &KeyPackage,
    pubkey_package: &PublicKeyPackage,
    escrow_id: EscrowId,
    caller_outcome: Outcome,
    decision_hash_for: impl Fn(Outcome) -> [u8; 32],
    slot: Duration,
    timeout: Duration,
) -> Result<(Outcome, schnorr::Signature), SigningError> {
    if !mux.active_escrows.lock().unwrap().insert(escrow_id.0) {
        return Err(SigningError::AlreadyInProgress);
    }
    let _active_escrow = ActiveEscrow {
        active_escrows: &mux.active_escrows,
        escrow_id,
    };

    let slot_secs = slot.as_secs().max(1);
    let deadline = now().checked_add(timeout).ok_or(SigningError::Timeout)?;

    loop {
        if now() >= deadline {
            return Err(SigningError::Timeout);
        }
        let now_secs = duration_since_epoch().as_secs();
        let slot_number = now_secs / slot_secs;
        let slot_end = (slot_number + 1) * slot_secs;
        let time_left = Duration::from_secs(slot_end - now_secs);

        // too little of the slot is left to finish
        if time_left * 4 >= Duration::from_secs(slot_secs) {
            // the escrow id is a hash, so its first bytes are a uniform start of the
            // rotation
            let first = u64::from_be_bytes(escrow_id.0[..8].try_into().expect("8 bytes"));
            let coordinator = *mux
                .participants
                .iter()
                .nth((first.wrapping_add(slot_number) % mux.participants.len() as u64) as usize)
                .expect("the rotation is inside the participants");

            let result = if coordinator == mux.caller {
                sign_as_coordinator(
                    mux,
                    key_package,
                    pubkey_package,
                    escrow_id,
                    caller_outcome,
                    &decision_hash_for,
                    time_left,
                )
                .await
                .map(Some)
            } else {
                sign_as_signer(
                    mux,
                    &coordinator,
                    key_package,
                    escrow_id,
                    caller_outcome,
                    &decision_hash_for,
                    time_left,
                )
                .await
                .map(|signer_outcome| match signer_outcome {
                    SignerOutcome::Final { outcome, signature } => Some((outcome, signature)),
                    SignerOutcome::ShareSent => None,
                })
            };

            match result {
                Ok(Some(decision)) => return Ok(decision),
                Ok(None) => {}
                // another slot won't fix these
                Err(
                    e @ (SigningError::InvalidOutcome
                    | SigningError::BadSignature
                    | SigningError::Encoding(_)),
                ) => return Err(e),
                Err(e) => warn!("signing in slot {slot_number} failed: {e}, trying the next slot"),
            }
        }

        sleep(Duration::from_secs(
            (slot_end + 1).saturating_sub(duration_since_epoch().as_secs()),
        ))
        .await;
    }
}
