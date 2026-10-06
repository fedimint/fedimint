use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use fedimint_core::runtime::{sleep, spawn};
use fedimint_core::secp256k1::{self, Message, schnorr};
use fedimint_core::time::{duration_since_epoch, now};
use fedimint_escrow_common::{EscrowId, Outcome, validate_split_bps};
use frost_secp256k1_tr as frost;
use frost_secp256k1_tr::Identifier;
use frost_secp256k1_tr::keys::{KeyPackage, PublicKeyPackage};
use frost_secp256k1_tr::round1::SigningCommitments;
use frost_secp256k1_tr::round2::SignatureShare;
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
    #[error("the coordinator asked us to sign something we did not vote for")]
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
    active_escrows: Arc<Mutex<HashSet<[u8; 32]>>>,
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
            active_escrows: Arc::default(),
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

                let mut inbox = mux.inbox.lock().unwrap();
                inbox.retain(|_, queue| {
                    queue.retain(|queued| {
                        now().duration_since(queued.received_at).unwrap_or_default()
                            < INBOX_MESSAGE_LIFETIME
                    });
                    !queue.is_empty()
                });
                if inbox.len() >= MAX_QUEUED_ESCROWS && !inbox.contains_key(&envelope.escrow_id.0) {
                    warn!("signing inbox is full, dropping message from {from:?}");
                    continue;
                }
                let queue = inbox.entry(envelope.escrow_id.0).or_default();
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
        self.transport.send(&self.caller, to, envelope).await?;
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
            sleep(Duration::from_millis(50)).await;
        }
    }
}

/// Marks an escrow as being signed until dropped, which includes the signing
/// being cancelled.
struct ActiveEscrow {
    active_escrows: Arc<Mutex<HashSet<[u8; 32]>>>,
    escrow_id: EscrowId,
}

impl Drop for ActiveEscrow {
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
    /// We sent our signature share but did not hear the result in time.
    ShareSent,
}

/// Votes for `my_outcome` and signs it if the coordinator asks, then
/// waits for the result.
///
/// Fails with [`SigningError::Timeout`] if we are neither asked to sign nor
/// told the result before `timeout`.
pub async fn sign_as_signer<T: SigningTransport + 'static>(
    mux: &SigningMux<T>,
    coordinator: &Identifier,
    key_package: &KeyPackage,
    escrow_id: EscrowId,
    my_outcome: Outcome,
    decision_hash_for: impl Fn(Outcome) -> [u8; 32],
    timeout: Duration,
) -> Result<SignerOutcome, SigningError> {
    if let Outcome::Split {
        funder_split_bps,
        recipient_split_bps,
    } = my_outcome
        && !validate_split_bps(funder_split_bps, recipient_split_bps)
    {
        return Err(SigningError::InvalidOutcome);
    }
    let deadline = now().checked_add(timeout).ok_or(SigningError::Timeout)?;
    let min_signers = *key_package.min_signers() as usize;
    let my_decision_hash = decision_hash_for(my_outcome);

    // the nonces are used by the one share we make and never stored
    let (nonces, commitments) = frost::round1::commit(key_package.signing_share(), &mut OsRng);
    let mut nonces = Some(nonces);
    let commitments_bytes = commitments.serialize()?;
    mux.send(
        coordinator,
        escrow_id,
        ArbiterMessage::Vote {
            outcome: my_outcome,
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

                // the package is for an earlier attempt
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

                if package.message() != my_decision_hash.as_slice() {
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
    my_outcome: Outcome,
    decision_hash_for: impl Fn(Outcome) -> [u8; 32],
    timeout: Duration,
) -> Result<(Outcome, schnorr::Signature), SigningError> {
    if let Outcome::Split {
        funder_split_bps,
        recipient_split_bps,
    } = my_outcome
        && !validate_split_bps(funder_split_bps, recipient_split_bps)
    {
        return Err(SigningError::InvalidOutcome);
    }
    let min_signers = *key_package.min_signers() as usize;
    let deadline = now().checked_add(timeout).ok_or(SigningError::Timeout)?;
    let consortium_pubkey = FrostDkgSessionRecord::consortium_pubkey(pubkey_package)?;

    let (my_nonces, my_commitments) =
        frost::round1::commit(key_package.signing_share(), &mut OsRng);
    let mut votes = BTreeMap::new();
    votes.insert(mux.caller, (my_outcome, my_commitments));

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
        if expires_at <= now()
            || expires_at > now() + MAX_VOTE_LIFETIME
            || matches!(outcome, Outcome::Split { funder_split_bps, recipient_split_bps }
                if !validate_split_bps(funder_split_bps, recipient_split_bps))
        {
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
    if my_outcome == winner {
        signers.insert(0, mux.caller);
    }
    signers.truncate(min_signers);

    let commitments: BTreeMap<_, _> = signers.iter().map(|id| (*id, votes[id].1)).collect();
    let decision_hash = decision_hash_for(winner);
    let package = frost::SigningPackage::new(commitments, &decision_hash);

    let request = ArbiterMessage::Request {
        signing_package: package.serialize()?,
    };
    for id in signers.iter().filter(|id| **id != mux.caller) {
        mux.send(id, escrow_id, request.clone()).await?;
    }

    let mut shares = BTreeMap::new();
    if signers.contains(&mux.caller) {
        shares.insert(
            mux.caller,
            frost::round2::sign(&package, &my_nonces, key_package)?,
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

    let finished = ArbiterMessage::Finished {
        outcome: winner,
        signature: signature.as_ref().to_vec(),
    };
    for id in mux.participants.iter().filter(|id| **id != mux.caller) {
        if let Err(e) = mux.send(id, escrow_id, finished.clone()).await {
            warn!("could not send the result to {id:?}: {e}");
        }
    }

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
/// The clocks of the arbiters have to be in sync.
#[allow(clippy::too_many_arguments)]
pub async fn sign_with_failover<T: SigningTransport + 'static>(
    mux: &SigningMux<T>,
    key_package: &KeyPackage,
    pubkey_package: &PublicKeyPackage,
    escrow_id: EscrowId,
    my_outcome: Outcome,
    decision_hash_for: impl Fn(Outcome) -> [u8; 32],
    slot: Duration,
    timeout: Duration,
) -> Result<(Outcome, schnorr::Signature), SigningError> {
    if !mux.active_escrows.lock().unwrap().insert(escrow_id.0) {
        return Err(SigningError::AlreadyInProgress);
    }
    let _active_escrow = ActiveEscrow {
        active_escrows: mux.active_escrows.clone(),
        escrow_id,
    };

    let slot_secs = slot.as_secs().max(1);
    let deadline = now().checked_add(timeout).ok_or(SigningError::Timeout)?;

    loop {
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
                    my_outcome,
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
                    my_outcome,
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

        if now() >= deadline {
            return Err(SigningError::Timeout);
        }
        sleep(Duration::from_secs(
            (slot_end + 1).saturating_sub(duration_since_epoch().as_secs()),
        ))
        .await;
        if now() >= deadline {
            return Err(SigningError::Timeout);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type Frame = (Identifier, Vec<u8>);

    struct Loopback {
        peers: Arc<HashMap<Identifier, tokio::sync::mpsc::UnboundedSender<Frame>>>,
        rx: tokio::sync::Mutex<tokio::sync::mpsc::UnboundedReceiver<Frame>>,
    }

    #[async_trait::async_trait]
    impl SigningTransport for Loopback {
        async fn send(
            &self,
            s: &Identifier,
            r: &Identifier,
            p: Vec<u8>,
        ) -> Result<(), TransportError> {
            self.peers
                .get(r)
                .ok_or(TransportError::InvalidReceiver)?
                .send((*s, p))
                .map_err(|_| TransportError::InvalidReceiver)
        }
        async fn recv(&self, _: &Identifier, d: Duration) -> Result<Frame, TransportError> {
            match tokio::time::timeout(d, self.rx.lock().await.recv()).await {
                Ok(Some(f)) => Ok(f),
                _ => Err(TransportError::TimeoutError),
            }
        }
    }

    struct Cluster {
        ids: Vec<Identifier>,
        key_packages: Vec<KeyPackage>,
        pubkey_package: PublicKeyPackage,
        muxes: Vec<Arc<SigningMux<Loopback>>>,
    }

    fn cluster() -> Cluster {
        let (shares, pubkey_package) =
            frost::keys::generate_with_dealer(4, 3, frost::keys::IdentifierList::Default, OsRng)
                .unwrap();
        let ids: Vec<Identifier> = shares.keys().copied().collect();
        let (mut senders, mut receivers) = (HashMap::new(), HashMap::new());
        for id in &ids {
            let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
            senders.insert(*id, tx);
            receivers.insert(*id, rx);
        }
        let peers = Arc::new(senders);
        let participants: Vec<_> = ids
            .iter()
            .map(|id| FrostParticipant { identifier: *id })
            .collect();
        let muxes = participants
            .iter()
            .map(|me| {
                let transport = Arc::new(Loopback {
                    peers: peers.clone(),
                    rx: tokio::sync::Mutex::new(receivers.remove(&me.identifier).unwrap()),
                });
                SigningMux::start(transport, me, &participants)
            })
            .collect();
        let key_packages = ids
            .iter()
            .map(|id| KeyPackage::try_from(shares[id].clone()).unwrap())
            .collect();
        Cluster {
            ids,
            key_packages,
            pubkey_package,
            muxes,
        }
    }

    fn decision_hash_for(outcome: Outcome) -> [u8; 32] {
        let mut hash = [0u8; 32];
        hash[0] = match outcome {
            Outcome::Release => 1,
            Outcome::Refund => 2,
            Outcome::Split { .. } => 3,
        };
        hash
    }

    const TIMEOUT: Duration = Duration::from_secs(5);
    const ESCROW: EscrowId = EscrowId([7; 32]);

    #[tokio::test]
    async fn majority_outcome_is_signed_and_everyone_gets_the_result() {
        let c = cluster();
        let mut signers = vec![];
        for i in 1..4 {
            let (mux, key_package, coordinator) =
                (c.muxes[i].clone(), c.key_packages[i].clone(), c.ids[0]);
            // the last arbiter disagrees
            let vote = if i == 3 {
                Outcome::Refund
            } else {
                Outcome::Release
            };
            signers.push(spawn("sign_as_signer", async move {
                sign_as_signer(
                    &mux,
                    &coordinator,
                    &key_package,
                    ESCROW,
                    vote,
                    decision_hash_for,
                    TIMEOUT,
                )
                .await
            }));
        }
        let (outcome, signature) = sign_as_coordinator(
            &c.muxes[0],
            &c.key_packages[0],
            &c.pubkey_package,
            ESCROW,
            Outcome::Release,
            decision_hash_for,
            TIMEOUT,
        )
        .await
        .unwrap();
        assert_eq!(outcome, Outcome::Release);

        for signer in signers {
            match signer.await.unwrap().unwrap() {
                SignerOutcome::Final {
                    outcome,
                    signature: received,
                } => {
                    assert_eq!(outcome, Outcome::Release);
                    assert_eq!(received, signature);
                }
                SignerOutcome::ShareSent => panic!("expected the final result"),
            }
        }
    }

    #[tokio::test]
    async fn no_outcome_with_enough_votes() {
        let c = cluster();
        let short = Duration::from_secs(2);
        for i in 1..4 {
            let (mux, key_package, coordinator) =
                (c.muxes[i].clone(), c.key_packages[i].clone(), c.ids[0]);
            let vote = if i == 1 {
                Outcome::Release
            } else {
                Outcome::Refund
            };
            spawn("sign_as_signer", async move {
                sign_as_signer(
                    &mux,
                    &coordinator,
                    &key_package,
                    ESCROW,
                    vote,
                    decision_hash_for,
                    short,
                )
                .await
            });
        }
        let result = sign_as_coordinator(
            &c.muxes[0],
            &c.key_packages[0],
            &c.pubkey_package,
            ESCROW,
            Outcome::Release,
            decision_hash_for,
            short,
        )
        .await;
        assert!(matches!(result, Err(SigningError::NoQuorum)));
    }

    #[tokio::test]
    async fn signer_does_not_sign_what_it_did_not_vote_for() {
        let c = cluster();
        let mut signers = vec![];
        for i in 1..4 {
            let (mux, key_package, coordinator) =
                (c.muxes[i].clone(), c.key_packages[i].clone(), c.ids[0]);
            signers.push(spawn("sign_as_sign", async move {
                sign_as_signer(
                    &mux,
                    &coordinator,
                    &key_package,
                    ESCROW,
                    Outcome::Release,
                    decision_hash_for,
                    Duration::from_secs(3),
                )
                .await
            }));
        }
        // a coordinator with another view of the contract
        let result = sign_as_coordinator(
            &c.muxes[0],
            &c.key_packages[0],
            &c.pubkey_package,
            ESCROW,
            Outcome::Release,
            |_| [0xEE; 32],
            Duration::from_secs(3),
        )
        .await;
        assert!(matches!(result, Err(SigningError::MissingShares(_))));
        let mut mismatches = 0;
        for signer in signers {
            if matches!(signer.await.unwrap(), Err(SigningError::MessageMismatch)) {
                mismatches += 1;
            }
        }
        assert!(mismatches >= 2);
    }

    #[tokio::test]
    async fn split_that_does_not_add_up_is_refused() {
        let c = cluster();
        let bad_split = Outcome::Split {
            funder_split_bps: 9_000,
            recipient_split_bps: 2_000,
        };
        let result = sign_as_signer(
            &c.muxes[1],
            &c.ids[0],
            &c.key_packages[1],
            ESCROW,
            bad_split,
            decision_hash_for,
            TIMEOUT,
        )
        .await;
        assert!(matches!(result, Err(SigningError::InvalidOutcome)));
    }

    #[tokio::test]
    async fn two_escrows_are_signed_at_the_same_time() {
        let c = cluster();
        let other_escrow = EscrowId([8; 32]);
        for escrow_id in [ESCROW, other_escrow] {
            for i in 1..4 {
                let (mux, key_package, coordinator) =
                    (c.muxes[i].clone(), c.key_packages[i].clone(), c.ids[0]);
                spawn("sign_as_signer", async move {
                    sign_as_signer(
                        &mux,
                        &coordinator,
                        &key_package,
                        escrow_id,
                        Outcome::Release,
                        decision_hash_for,
                        TIMEOUT,
                    )
                    .await
                });
            }
        }
        let (first, second) = tokio::join!(
            sign_as_coordinator(
                &c.muxes[0],
                &c.key_packages[0],
                &c.pubkey_package,
                ESCROW,
                Outcome::Release,
                decision_hash_for,
                TIMEOUT
            ),
            sign_as_coordinator(
                &c.muxes[0],
                &c.key_packages[0],
                &c.pubkey_package,
                other_escrow,
                Outcome::Release,
                decision_hash_for,
                TIMEOUT
            ),
        );
        first.unwrap();
        second.unwrap();
    }

    #[tokio::test]
    async fn every_arbiter_makes_the_same_call() {
        let c = cluster();
        let mut arbiters = vec![];
        for i in 0..4 {
            let (mux, key_package, pubkey_package) = (
                c.muxes[i].clone(),
                c.key_packages[i].clone(),
                c.pubkey_package.clone(),
            );
            arbiters.push(spawn("sign_with_failover", async move {
                sign_with_failover(
                    &mux,
                    &key_package,
                    &pubkey_package,
                    ESCROW,
                    Outcome::Release,
                    decision_hash_for,
                    Duration::from_secs(8),
                    Duration::from_secs(40),
                )
                .await
            }));
        }
        let mut signatures = vec![];
        for arbiter in arbiters {
            let (outcome, signature) = arbiter.await.unwrap().unwrap();
            assert_eq!(outcome, Outcome::Release);
            signatures.push(signature);
        }
        assert!(signatures.windows(2).all(|pair| pair[0] == pair[1]));
    }

    /// An arbiter that never shows up costs at most one slot
    #[tokio::test]
    async fn one_arbiter_offline() {
        let c = cluster();
        let mut arbiters = vec![];
        for i in 1..4 {
            let (mux, key_package, pubkey_package) = (
                c.muxes[i].clone(),
                c.key_packages[i].clone(),
                c.pubkey_package.clone(),
            );
            arbiters.push(spawn("sign_with_failover", async move {
                sign_with_failover(
                    &mux,
                    &key_package,
                    &pubkey_package,
                    ESCROW,
                    Outcome::Release,
                    decision_hash_for,
                    Duration::from_secs(6),
                    Duration::from_secs(60),
                )
                .await
            }));
        }
        for arbiter in arbiters {
            arbiter.await.unwrap().unwrap();
        }
    }

    #[tokio::test]
    async fn the_same_escrow_is_not_signed_twice_on_one_node() {
        let c = cluster();
        let (mux, key_package, pubkey_package) = (
            c.muxes[1].clone(),
            c.key_packages[1].clone(),
            c.pubkey_package.clone(),
        );
        let first = spawn("sign_with_failover", {
            let (mux, key_package, pubkey_package) =
                (mux.clone(), key_package.clone(), pubkey_package.clone());
            async move {
                sign_with_failover(
                    &mux,
                    &key_package,
                    &pubkey_package,
                    ESCROW,
                    Outcome::Release,
                    decision_hash_for,
                    Duration::from_secs(6),
                    Duration::from_secs(20),
                )
                .await
            }
        });
        sleep(Duration::from_millis(200)).await;
        let second = sign_with_failover(
            &mux,
            &key_package,
            &pubkey_package,
            ESCROW,
            Outcome::Release,
            decision_hash_for,
            Duration::from_secs(6),
            Duration::from_secs(20),
        )
        .await;
        assert!(matches!(second, Err(SigningError::AlreadyInProgress)));

        // cancelling the first signing frees the escrow again
        first.abort();
        let _ = first.await;
        assert!(mux.active_escrows.lock().unwrap().is_empty());
    }
}
