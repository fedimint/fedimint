mod tweak;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{LazyLock, Mutex};
use std::time::SystemTime;

use anyhow::{anyhow, ensure};
use bip445::{
    PublicNonce, SecretNonce, aggregate_signature_shares, derive_nonce, derive_public_nonce,
    sign_share, verify, verify_signature_share,
};
use bitcoin::Txid;
use bitcoin::hashes::{Hash, sha256};
use bitcoin::sighash::{Prevouts, SighashCache};
use fedimint_core::db::{Database, DatabaseTransaction, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::envs::is_running_in_test_env;
use fedimint_core::task::TaskGroup;
use fedimint_core::util::FmtCompact as _;
use fedimint_core::{NumPeersExt, PeerId};
use fedimint_logging::LOG_MODULE_WALLETV2;
use fedimint_server_core::config::scalar_secp;
use fedimint_walletv2_common::WalletConsensusItem;
use fedimint_walletv2_common::config::WalletDescriptor;
use fedimint_walletv2_common::taproot::descriptor_tr;
use fedimint_walletv2_common::taproot::frost::{
    FrostFinalizationStat, FrostPolynomial, FrostSignatureShares, FrostSigningCommitments,
};
use futures::StreamExt;
use rand::rngs::OsRng;
use rand::seq::SliceRandom;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha8Rng;
use secp256k1::{Scalar, SecretKey};
use serde::Serialize;
use tweak::FrostTweak;

use crate::db::{
    FrostAdvanceVoteAttemptPrefix, FrostAdvanceVoteKey, FrostAdvanceVoteTxidPrefix,
    FrostConsumedCommitmentKey, FrostFinalizationStatKey, FrostSignatureShareAttemptPrefix,
    FrostSignatureShareKey, FrostSignatureShareTxidPrefix, FrostSigningAttempt,
    FrostSigningAttemptKey, FrostSigningAttemptTxidPrefix, FrostSigningCommitmentsKey,
    FrostSigningCommitmentsPeerPrefix, FrostSigningNoncesKey, FrostSigningNoncesPrefix,
    FrostSigningPackagesKey, FrostSigningPackagesTxidPrefix, LocalFrostSignatureShareKey,
    LocalFrostSignatureShareTxidPrefix, UnsignedTxKey, UnsignedTxPrefix,
};
use crate::envs::{
    FM_WALLETV2_FROST_NONCE_BUFFER_TARGET_ENV, FM_WALLETV2_FROST_TEST_FORCE_SIGNER_ENV,
};
use crate::taproot::attach_key_path_witnesses;
use crate::{FederationTx, Wallet};

/// Target number of unused FROST signing nonces each peer keeps on disk.
/// `consume_our_nonce` replaces every nonce it uses, so the buffer only has to
/// cover the commitments a burst of signing sessions draws before those
/// replacements reach consensus: a walletv2 transaction spends at most two
/// inputs, so this covers four transactions starting at once. A session that
/// finds too few commitments waits for the replacements rather than failing.
///
/// Kept small because a guardian that loses its database leaves this many
/// unusable commitments in the pool, and every signing attempt that draws one
/// fails after [`LOCAL_ADVANCE_TIMEOUT`] before the next one can start.
const DEFAULT_FROST_NONCE_BUFFER_TARGET: usize = 8;

/// Smallest usable local FROST nonce buffer: a peer is only picked into a
/// signing session if it has one commitment per input, and a peg-in spends
/// two. Below this the guardian would never be viable — and since the buffer
/// is only topped up at startup (`consume_our_nonce` refills 1:1
/// thereafter), a target of `0` would leave it with no commitments forever.
const MIN_FROST_NONCE_BUFFER_TARGET: usize = 2;

/// Upper bound on the number of unused commitments any single peer may hold
/// in the replicated pool. Without a cap, a malicious or misconfigured
/// guardian could broadcast endless unique commitments and grow every
/// guardian's DB without bound.
///
/// Consensus-critical: every guardian must reach the same accept/reject
/// decision for every commitment item, so this must stay a hard constant —
/// never derive it from the per-guardian
/// [`FM_WALLETV2_FROST_NONCE_BUFFER_TARGET_ENV`] setting. It is instead the
/// upper bound that [`frost_nonce_buffer_target`] clamps that setting to.
const MAX_PEER_COMMITMENT_POOL: usize = 1024;

/// How often a peer re-broadcasts its FROST signature share (or
/// commitment) when the previous broadcast hasn't yet been delivered
/// through consensus. `AlephBFT` can drop a unit when its broadcast lands
/// close to a session boundary — most likely with larger federations
/// where each peer commands a smaller fraction of the per-round byte
/// budget. Picking a value comparable to the typical `AlephBFT` session
/// duration (~20–30 s) keeps re-broadcasts to ~1 per session per item
/// instead of ~10/sec.
const FROST_REBROADCAST_INTERVAL: std::time::Duration = std::time::Duration::from_secs(15);

/// Local wall-clock window each peer waits before broadcasting a
/// `FrostAdvanceVote` for a stuck signing session. Per-peer (not
/// consensus) — peers' clocks may differ, but the consensus is on the
/// *vote count*, not the timing. Held at 30s in every environment
/// (including devimint) so that one-input txs get a fair chance to
/// finish on the original `signing_session` before peers start firing
/// advance votes — premature advance creates a swarm of new attempts,
/// which inflates consensus-item volume and can push `AlephBFT` past its
/// per-instance byte budget at different boundaries on different peers.
const LOCAL_ADVANCE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Target size of the local FROST nonce buffer (see
/// [`spawn_initial_nonce_backfill`]).
/// Reads [`FM_WALLETV2_FROST_NONCE_BUFFER_TARGET_ENV`] once on first use,
/// falling back to [`DEFAULT_FROST_NONCE_BUFFER_TARGET`] when unset or
/// unparsable, and clamped to
/// `MIN_FROST_NONCE_BUFFER_TARGET..=MAX_PEER_COMMITMENT_POOL` — commitments
/// above the cap are rejected federation-wide and re-proposed forever.
fn frost_nonce_buffer_target() -> usize {
    static TARGET: LazyLock<usize> = LazyLock::new(|| {
        let configured = std::env::var(FM_WALLETV2_FROST_NONCE_BUFFER_TARGET_ENV)
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(DEFAULT_FROST_NONCE_BUFFER_TARGET);

        let clamped = configured.clamp(MIN_FROST_NONCE_BUFFER_TARGET, MAX_PEER_COMMITMENT_POOL);

        if clamped != configured {
            tracing::warn!(
                target: LOG_MODULE_WALLETV2,
                configured,
                clamped_to = clamped,
                env = FM_WALLETV2_FROST_NONCE_BUFFER_TARGET_ENV,
                "FROST nonce buffer target out of range; clamping"
            );
        }

        clamped
    });

    *TARGET
}

/// Test hook: the peer [`pick_signing_session`] seats first in attempt `0`,
/// read once from [`FM_WALLETV2_FROST_TEST_FORCE_SIGNER_ENV`]. Always `None`
/// outside test environments. Signing sessions must be identical on every
/// guardian, so all guardians of a federation must set the same value.
fn frost_test_forced_signer() -> Option<PeerId> {
    static FORCED: LazyLock<Option<PeerId>> = LazyLock::new(|| {
        if !is_running_in_test_env() {
            return None;
        }

        std::env::var(FM_WALLETV2_FROST_TEST_FORCE_SIGNER_ENV)
            .ok()
            .map(|value| {
                value
                    .parse::<PeerId>()
                    .expect("FM_WALLETV2_FROST_TEST_FORCE_SIGNER must be a peer id")
            })
    });

    *FORCED
}

/// The random seed of one of our secret nonces, stored in place of the nonce
/// itself since bip445 deliberately keeps `SecretNonce` unserializable. The
/// nonce is derived from the seed only when it is consumed, and the seed is
/// deleted in the same transaction.
#[derive(Clone, Encodable, Decodable)]
pub struct FrostNonceSeed(pub [u8; 32]);

impl FrostNonceSeed {
    /// A fresh random seed and the public nonce of the secret nonce it
    /// derives.
    pub(crate) fn generate() -> (Self, FrostSigningCommitments) {
        let mut seed = [0; 32];

        OsRng.fill_bytes(&mut seed);

        let public_nonce = derive_public_nonce(&derive_nonce(&seed));

        (Self(seed), FrostSigningCommitments(public_nonce))
    }
}

/// Placeholder emitted in place of the seed by the `Debug` and `Serialize`
/// impls of [`FrostNonceSeed`].
const REDACTED_NONCE: &str = "<redacted>";

/// A dump captured while a nonce seed is still buffered, combined with the
/// signature share later broadcast with its nonce, reveals the guardian's
/// long-lived FROST key share, so the seed is never printed. The public
/// nonce is the DB key.
impl std::fmt::Debug for FrostNonceSeed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("FrostNonceSeed")
            .field(&REDACTED_NONCE)
            .finish()
    }
}

/// Diagnostic (`dump_database`) serialization only, redacted like `Debug`.
impl Serialize for FrostNonceSeed {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(REDACTED_NONCE)
    }
}

/// The signing session of one input: the message and the public nonce of
/// every signer. Cached in the DB at `FrostSigningPackagesKey(txid)` so that
/// any peer (including non-session peers) can verify and aggregate
/// `FrostSignatureShare` consensus items without the package being re-sent
/// over the wire by every signer.
#[derive(Debug, Clone, Encodable, Decodable, Serialize)]
pub struct FrostSigningPackage {
    pub message: [u8; 32],
    pub nonces: BTreeMap<PeerId, PublicNonce>,
}

impl FrostSigningPackage {
    /// The signers' public nonces keyed by their bip445 identity.
    fn signer_nonces(&self) -> BTreeMap<u64, PublicNonce> {
        self.nonces
            .iter()
            .map(|(peer, nonce)| (signer_id(*peer), *nonce))
            .collect()
    }
}

/// Broadcast pacing for consensus items we've handed to a
/// `consensus_proposal` but haven't yet seen come back through
/// `process_consensus_item`, keyed by item with the wall-clock timestamp of
/// the last broadcast attempt.
///
/// A DB-only filter is racy: at 100ms proposal cadence, the same item can be
/// re-submitted several times before `AlephBFT` finalizes the first copy —
/// the in-flight entry makes the filter exact. Entries older than
/// [`FROST_REBROADCAST_INTERVAL`] become eligible for re-broadcast, because
/// `AlephBFT` can silently drop a unit when its broadcast lands close to a
/// session boundary (more likely in larger federations where each peer
/// commands a smaller fraction of the per-round byte budget).
///
/// Local-only state, never read from or written to `dbtx` — no consensus
/// implications.
#[derive(Debug)]
pub(crate) struct InFlight<K>(Mutex<BTreeMap<K, SystemTime>>);

// Manual impl: `derive(Default)` would needlessly require `K: Default`.
impl<K> Default for InFlight<K> {
    fn default() -> Self {
        Self(Mutex::new(BTreeMap::new()))
    }
}

impl<K: Ord> InFlight<K> {
    /// Record `now` as the latest broadcast attempt for `key` and return
    /// `true` if the item should be proposed: either it has no pending
    /// attempt, or the last attempt is at least
    /// [`FROST_REBROADCAST_INTERVAL`] old. Returns `false` (and records
    /// nothing) while a recent attempt is still pending.
    fn try_claim(&self, key: K, now: SystemTime) -> bool {
        let mut map = self.0.lock().expect("InFlight mutex poisoned");
        match map.get(&key) {
            Some(last)
                if now.duration_since(*last).unwrap_or_default() < FROST_REBROADCAST_INTERVAL =>
            {
                false
            }
            _ => {
                map.insert(key, now);
                true
            }
        }
    }

    /// Drop the entry for `key` — its broadcast has been delivered through
    /// consensus, or is no longer needed.
    fn clear(&self, key: &K) {
        self.0.lock().expect("InFlight mutex poisoned").remove(key);
    }

    /// Retain only the entries whose key satisfies `keep`.
    fn retain(&self, mut keep: impl FnMut(&K) -> bool) {
        self.0
            .lock()
            .expect("InFlight mutex poisoned")
            .retain(|key, _| keep(key));
    }
}

/// In-memory FROST tracking state. Every entry is local — never read
/// from or written to `dbtx` — so it doesn't influence consensus.
#[derive(Debug, Default)]
pub(crate) struct FrostRuntime {
    /// Pacing for our nonce commitments; cleared when our own commitment
    /// comes back through `process_consensus_item`.
    pub(crate) in_flight_commitments: InFlight<FrostSigningCommitments>,
    /// Wall-clock timestamp of when we first observed each `(txid, attempt)`
    /// locally. Used to fire a per-peer advance vote when the session has
    /// been waiting longer than `LOCAL_ADVANCE_TIMEOUT`. Per-peer state;
    /// not consensus.
    pub(crate) tx_attempt_first_seen: Mutex<BTreeMap<(Txid, u32), SystemTime>>,
    /// Pacing for our advance votes; cleared when our own vote comes back
    /// through `process_consensus_item` or the tx finalizes. The
    /// `FrostAdvanceVoteKey` entry written on delivery keeps a cleared
    /// vote from ever being proposed again.
    pub(crate) in_flight_advance_votes: InFlight<(Txid, u32)>,
    /// Pacing for our signature shares; cleared when our share is
    /// delivered through consensus or the tx finalizes.
    pub(crate) broadcast_signature_shares: InFlight<(Txid, u32)>,
}

impl Wallet {
    /// Compute the BIP-341 key-path sighash for every input of
    /// `unsigned_tx`, all derived from a single `SighashCache` over the
    /// shared prevouts. These are the messages the FROST signers
    /// collectively sign — one per input.
    pub(crate) fn build_frost_key_spend_messages(
        &self,
        unsigned_tx: &FederationTx,
    ) -> Vec<[u8; 32]> {
        let prevouts = self.build_prevouts(unsigned_tx);
        let mut sighash_cache = SighashCache::new(unsigned_tx.tx.clone());

        // Invariant: `FederationTx` is only ever built locally (`process_input`
        // / `process_output`) with one `spent_tx_out` per input, never decoded
        // from the wire — so the index is in range and `Prevouts::All` matches.
        (0..unsigned_tx.tx.input.len())
            .map(|input_index| {
                sighash_cache
                    .taproot_key_spend_signature_hash(
                        input_index,
                        &Prevouts::All(&prevouts),
                        bitcoin::TapSighashType::Default,
                    )
                    .expect("Failed to compute taproot key spend sighash")
                    .to_byte_array()
            })
            .collect()
    }

    /// Build and persist the FROST `SigningPackage` for each input of
    /// `unsigned_tx`. Every peer (signer or not) runs this so the package is
    /// available later for verifying and aggregating shares without it
    /// having to ride along with each `FrostSignatureShare` consensus item.
    /// Signing-session peers additionally consume their per-input nonce and
    /// produce their `SignatureShare`s, stored under their own `peer_id` for
    /// the next `consensus_proposal` to broadcast.
    ///
    /// Two phases, strictly in this order:
    /// 1. Replicated: pick the session, consume the commitments, persist the
    ///    signing packages and the attempt record. This touches only
    ///    consensus-replicated state, so every guardian ends up with the same
    ///    DB. Its one failure — no viable session — is deterministic and
    ///    happens before any write; it is the `Err` callers retry on.
    /// 2. Local: if we're in the session, sign (`sign_attempt`). A failure here
    ///    (e.g. a nonce lost to a DB restore) is this guardian's problem alone:
    ///    it's logged, no share is stashed, and the federation advances past
    ///    us. It never reaches replicated state or the returned `Err`, which
    ///    would otherwise split consensus.
    ///
    /// `attempt` is `0` when this runs from `process_input` /
    /// `process_output` (initial signing), and `prev.attempt + 1` when
    /// triggered from a successful advance vote — same body, different
    /// hash-shuffle seed.
    pub(crate) async fn compute_and_store_frost_signature_shares(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        unsigned_tx: &FederationTx,
        attempt: u32,
    ) -> anyhow::Result<()> {
        let txid = unsigned_tx.tx.compute_txid();
        let all_peers: Vec<PeerId> = self.cfg.consensus.bitcoin_pks.keys().copied().collect();
        let threshold = self.cfg.consensus.bitcoin_pks.to_num_peers().threshold();

        // Compute suspects: peers who were assigned to a prior attempt of
        // this tx but didn't broadcast their share. Drawn entirely from
        // consensus-replicated DB state — every peer computes the same set,
        // so the resulting signing_session selection is deterministic.
        // Empty for the initial attempt (no prior attempts) and grows as
        // advances accumulate.
        let prior_attempts = dbtx
            .find_by_prefix(&FrostSigningAttemptTxidPrefix(txid))
            .await
            .collect::<Vec<_>>()
            .await;
        let mut suspects = BTreeSet::new();
        for (key, attempt_record) in prior_attempts {
            for peer in &attempt_record.signing_session {
                let broadcast = dbtx
                    .get_value(&FrostSignatureShareKey {
                        txid,
                        attempt: key.attempt,
                        peer_id: *peer,
                    })
                    .await
                    .is_some();
                if !broadcast {
                    suspects.insert(*peer);
                }
            }
        }

        // Each input consumes one commitment per signing-session peer, so a
        // peer is only viable if it has at least n_inputs commitments
        // available right now. Skipping under-buffered peers here means the
        // per-input `consume_session_commitments` calls below can't fail
        // halfway through.
        let signing_session = pick_signing_session(
            dbtx,
            &all_peers,
            threshold,
            txid,
            attempt,
            unsigned_tx.tx.input.len(),
            &suspects,
            frost_test_forced_signer(),
        )
        .await
        .ok_or_else(|| {
            anyhow!("Insufficient FROST commitment buffer across federation for tx {txid}")
        })?;

        // --- Phase 1: replicated ---------------------------------------
        let messages = self.build_frost_key_spend_messages(unsigned_tx);
        let mut signing_packages: Vec<FrostSigningPackage> = Vec::with_capacity(messages.len());
        for message in &messages {
            // Can't fail after `pick_signing_session`, which only selects
            // peers holding one commitment per input — and if it somehow
            // did, it would fail identically on every guardian.
            let nonces = self
                .consume_session_commitments(dbtx, &signing_session)
                .await?;
            signing_packages.push(FrostSigningPackage {
                message: *message,
                nonces,
            });
        }

        dbtx.insert_new_entry(
            &FrostSigningPackagesKey { txid, attempt },
            &signing_packages,
        )
        .await;

        // Persist which signing session this attempt is using so peers'
        // FrostSignatureShare consensus items can be cross-checked
        // against the right session, and consensus_proposal can broadcast
        // our share without re-deriving the session. Each attempt has
        // its own record — advance creates a new (txid, attempt + 1)
        // entry rather than overwriting.
        dbtx.insert_new_entry(
            &FrostSigningAttemptKey { txid, attempt },
            &FrostSigningAttempt {
                signing_session: signing_session.clone(),
            },
        )
        .await;

        // --- Phase 2: local --------------------------------------------
        if signing_session.contains(&self.our_peer_id) {
            match self
                .sign_attempt(dbtx, unsigned_tx, &signing_packages)
                .await
            {
                Ok(signature_shares) => {
                    // Local-only stash. The canonical, consensus-replicated
                    // `FrostSignatureShareKey` entry is written when our
                    // broadcast comes back through AlephBFT. Splitting these
                    // keeps `pick_signing_session`'s suspects (which reads
                    // `FrostSignatureShareKey`) a pure function of consensus
                    // state — every guardian agrees on it at every item
                    // boundary.
                    dbtx.insert_new_entry(
                        &LocalFrostSignatureShareKey { txid, attempt },
                        &signature_shares,
                    )
                    .await;
                }
                Err(err) => {
                    tracing::warn!(
                        target: LOG_MODULE_WALLETV2,
                        ?txid,
                        attempt,
                        err = %err.fmt_compact(),
                        "Couldn't produce our FROST signature share; the federation will advance past us"
                    );
                }
            }
        }

        Ok(())
    }

    /// The local half of attempt creation: consume our nonce for every
    /// input's signing package and produce our per-input signature shares.
    ///
    /// All nonces are taken out of the buffer before any signing happens: a
    /// commitment that has entered a (replicated) signing package must never
    /// be signed with again, whether or not this attempt yields our share.
    /// Errors are local faults — a nonce lost to a DB restore, a
    /// package/nonce mismatch — and are contained by the caller.
    async fn sign_attempt(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        unsigned_tx: &FederationTx,
        signing_packages: &[FrostSigningPackage],
    ) -> anyhow::Result<FrostSignatureShares> {
        let mut nonces = Vec::with_capacity(signing_packages.len());
        for signing_package in signing_packages {
            nonces.push(self.consume_our_nonce(dbtx, signing_package).await);
        }
        let nonces = nonces.into_iter().collect::<anyhow::Result<Vec<_>>>()?;

        let polynomial = self.frost_polynomial()?;

        let secret_share = self
            .cfg
            .private
            .frost_secret_share
            .expect("The FROST secret share is checked at startup");

        let mut signature_shares = Vec::with_capacity(signing_packages.len());
        for ((signing_package, nonce), utxo) in signing_packages
            .iter()
            .zip(nonces)
            .zip(&unsigned_tx.spent_tx_outs)
        {
            let tweak = self.frost_tweak(polynomial, &utxo.tweak);

            signature_shares.push(sign_share(
                signing_package.message,
                &tweak.secret_share(secret_share),
                nonce,
                &signing_package.signer_nonces(),
                signer_id(self.our_peer_id),
                tweak.aggregate(),
            ));
        }

        tracing::info!(
            target: LOG_MODULE_WALLETV2,
            inputs = signature_shares.len(),
            "Generated FROST signature shares"
        );

        Ok(FrostSignatureShares { signature_shares })
    }

    /// Take the first available `FrostSigningCommitments` for each peer in
    /// `signing_session` and remove them from the DB. Called by every peer
    /// (including non-session peers) so that DB state — and therefore the
    /// derived `SigningPackage` — stays in sync across the federation.
    pub(crate) async fn consume_session_commitments(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        signing_session: &[PeerId],
    ) -> anyhow::Result<BTreeMap<PeerId, PublicNonce>> {
        let mut commitments_map = BTreeMap::new();
        for peer_id in signing_session {
            let commitment = dbtx
                .find_by_prefix(&FrostSigningCommitmentsPeerPrefix(*peer_id))
                .await
                .next()
                .await
                .ok_or_else(|| anyhow!("No FROST commitments available for peer {peer_id}"))?;
            commitments_map.insert(*peer_id, commitment.0.frost_commitments.0);
            dbtx.remove_entry(&commitment.0).await;
            // Remember it for good: the pool entry is gone and its owner's
            // nonce is spent, so a delayed retransmit of this commitment
            // must not pass for a new one — see `process_frost_commitments`.
            dbtx.insert_new_entry(
                &FrostConsumedCommitmentKey {
                    peer_id: *peer_id,
                    frost_commitments: commitment.0.frost_commitments,
                },
                &(),
            )
            .await;
        }
        Ok(commitments_map)
    }

    /// Take the seed of our nonce in `signing_package` out of the local buffer,
    /// derive the nonce from it and mint a replacement. Only signing-session
    /// peers should call this — for non-session peers we're not in the
    /// package.
    pub(crate) async fn consume_our_nonce(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        signing_package: &FrostSigningPackage,
    ) -> anyhow::Result<SecretNonce> {
        let our_commitment = *signing_package
            .nonces
            .get(&self.our_peer_id)
            .ok_or_else(|| anyhow!("Our peer is not in the signing session"))?;

        let seed = dbtx
            .remove_entry(&FrostSigningNoncesKey(FrostSigningCommitments(
                our_commitment,
            )))
            .await
            .ok_or_else(|| {
                anyhow!("FROST nonce for our own commitment is missing — DB inconsistency")
            })?;

        let nonce = derive_nonce(&seed.0);

        ensure!(
            derive_public_nonce(&nonce) == our_commitment,
            "FROST nonce seed does not derive its commitment — DB inconsistency"
        );

        // Inline 1:1 replacement: keep our local nonce buffer at
        // `frost_nonce_buffer_target()` invariantly. Local-only state, no
        // consensus implications.
        let (new_seed, new_commitment) = FrostNonceSeed::generate();
        dbtx.insert_new_entry(&FrostSigningNoncesKey(new_commitment), &new_seed)
            .await;

        Ok(nonce)
    }

    /// Walk all unsigned txs and (re)try to start signing wherever we
    /// previously couldn't because of a thin commitment buffer:
    ///
    /// - Tx with no attempt at all → try `compute_and_store(.., 0)` to create
    ///   attempt 0. This is the "sign-later" path for an `UnsignedTx` that was
    ///   created in `process_input` / `process_output` while commitments were
    ///   drained.
    /// - Tx whose latest attempt has reached the advance vote threshold but
    ///   doesn't yet have an `attempt + 1` record → try `compute_and_store(..,
    ///   latest + 1)`. This catches the case where the advance handler had to
    ///   defer attempt creation.
    ///
    /// Errors are logged at trace level — the next call (typically the
    /// next `FrostSigningCommitments` processing) will retry, so we don't
    /// want to spam logs while waiting for buffers to refill.
    pub(crate) async fn try_progress_pending_signings(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
    ) -> anyhow::Result<()> {
        let unsigned_txs: Vec<(Txid, FederationTx)> = dbtx
            .find_by_prefix(&UnsignedTxPrefix)
            .await
            .map(|(k, v)| (k.0, v))
            .collect()
            .await;

        let advance_threshold = self.cfg.consensus.bitcoin_pks.to_num_peers().max_evil() + 1;

        for (txid, unsigned_tx) in unsigned_txs {
            let latest_attempt: Option<u32> = dbtx
                .find_by_prefix(&FrostSigningAttemptTxidPrefix(txid))
                .await
                .map(|(k, _)| k.attempt)
                .collect::<Vec<_>>()
                .await
                .into_iter()
                .max();

            let target_attempt = match latest_attempt {
                None => Some(0),
                Some(latest) => {
                    let vote_count = dbtx
                        .find_by_prefix(&FrostAdvanceVoteAttemptPrefix {
                            txid,
                            attempt: latest,
                        })
                        .await
                        .count()
                        .await;
                    if vote_count >= advance_threshold {
                        Some(latest + 1)
                    } else {
                        None
                    }
                }
            };

            if let Some(target) = target_attempt
                && let Err(err) = self
                    .compute_and_store_frost_signature_shares(dbtx, &unsigned_tx, target)
                    .await
            {
                tracing::trace!(
                    target: LOG_MODULE_WALLETV2,
                    ?txid,
                    target_attempt = target,
                    err = %err.fmt_compact(),
                    "Couldn't progress FROST signing for tx; will retry on next commitment"
                );
            }
        }

        Ok(())
    }

    /// Build the FROST-specific items this peer wants to propose for the
    /// next `AlephBFT` round:
    ///
    /// - any unbroadcasted commitments from our local nonce buffer,
    /// - an advance vote for any tx whose latest attempt has been waiting
    ///   longer than `LOCAL_ADVANCE_TIMEOUT`,
    /// - our pre-computed signature share for every attempt of each unsigned tx
    ///   that includes us in its signing session and whose broadcast hasn't yet
    ///   landed in `FrostSignatureShareKey` — not just the latest attempt,
    ///   since a late share clears us from the suspect set.
    ///
    /// Re-broadcasts are gated by `FROST_REBROADCAST_INTERVAL` to recover
    /// from `AlephBFT` silently dropping a unit (more likely with larger
    /// federations near session boundaries) without spamming every
    /// proposal cycle.
    pub(crate) async fn frost_consensus_proposal(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
    ) -> Vec<WalletConsensusItem> {
        let now = fedimint_core::time::now();
        let mut items = self.propose_commitments(dbtx, now).await;

        // Per unsigned tx: an advance vote if its latest attempt is stuck,
        // and our signature share for every attempt whose signing session
        // we're in. The signing_session is read from FrostSigningAttemptKey
        // (set when the attempt was created), so the choice of signers is a
        // per-tx fact, not a global constant.
        let txids = dbtx
            .find_by_prefix(&UnsignedTxPrefix)
            .await
            .map(|(key, _)| key.0)
            .collect::<Vec<_>>()
            .await;
        for txid in txids {
            // Every attempt of this tx. Attempts are append-only, so the
            // highest number is the current one. Empty means the tx hasn't
            // reached the FROST signing path yet (e.g. first peg-in, which
            // only inserts the FederationWalletKey).
            let attempts = dbtx
                .find_by_prefix(&FrostSigningAttemptTxidPrefix(txid))
                .await
                .map(|(k, v)| (k.attempt, v))
                .collect::<Vec<_>>()
                .await;

            // Only the latest attempt can be advanced past.
            if let Some(latest_attempt) = attempts.iter().map(|(attempt, _)| *attempt).max() {
                items.extend(
                    self.propose_advance_vote(dbtx, txid, latest_attempt, now)
                        .await,
                );
            }

            // But every attempt we signed for keeps its share on offer until
            // it's delivered. A share that lands late clears us from the
            // suspect set (see `compute_and_store_frost_signature_shares`),
            // so later attempts pick us ahead of the remaining suspects again.
            for (attempt, record) in &attempts {
                if record.signing_session.contains(&self.our_peer_id) {
                    items.extend(
                        self.propose_signature_share(dbtx, txid, *attempt, now)
                            .await,
                    );
                }
            }
        }

        items
    }

    /// Propose every nonce commitment from our local buffer that hasn't
    /// been delivered through consensus yet (per the consensus-replicated
    /// `FrostSigningCommitmentsKey` state) and isn't recently in flight
    /// (see [`InFlight`] for the pacing rationale).
    async fn propose_commitments(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        now: SystemTime,
    ) -> Vec<WalletConsensusItem> {
        let my_commitments = dbtx
            .find_by_prefix(&FrostSigningCommitmentsPeerPrefix(self.our_peer_id))
            .await
            .map(|c| c.0.frost_commitments)
            .collect::<BTreeSet<_>>()
            .await;

        let my_nonces = dbtx
            .find_by_prefix(&FrostSigningNoncesPrefix)
            .await
            .collect::<Vec<_>>()
            .await;

        let new_commitments: Vec<FrostSigningCommitments> = my_nonces
            .into_iter()
            .map(|(key, _)| key.0)
            .filter(|c| !my_commitments.contains(c))
            .filter(|c| self.frost.in_flight_commitments.try_claim(c.clone(), now))
            .collect();

        if !new_commitments.is_empty() {
            tracing::info!(
                target: LOG_MODULE_WALLETV2,
                commitment_len = %new_commitments.len(),
                "Added commitments to be broadcasted"
            );
        }

        new_commitments
            .into_iter()
            .map(|c| WalletConsensusItem::FrostSigningCommitments(Box::new(c)))
            .collect()
    }

    /// Broadcast a vote to start a fresh signing attempt once `(txid,
    /// latest_attempt)` has been waiting longer than
    /// `LOCAL_ADVANCE_TIMEOUT`. Any peer can vote, including non-session
    /// observers — they can see whose share is missing from their own DB.
    /// Returns `None` while the timer hasn't expired, we've already voted
    /// (consensus DB state), or a recent broadcast is still in flight.
    async fn propose_advance_vote(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        txid: Txid,
        latest_attempt: u32,
        now: SystemTime,
    ) -> Option<WalletConsensusItem> {
        let timer_expired = {
            let mut map = self
                .frost
                .tx_attempt_first_seen
                .lock()
                .expect("tx_attempt_first_seen mutex poisoned");
            let first_seen = map
                .entry((txid, latest_attempt))
                .or_insert_with(fedimint_core::time::now);
            fedimint_core::time::now()
                .duration_since(*first_seen)
                .unwrap_or_default()
                > LOCAL_ADVANCE_TIMEOUT
        };
        if !timer_expired {
            return None;
        }

        let already_voted = dbtx
            .get_value(&FrostAdvanceVoteKey {
                txid,
                attempt: latest_attempt,
                voter: self.our_peer_id,
            })
            .await
            .is_some();
        if already_voted
            || !self
                .frost
                .in_flight_advance_votes
                .try_claim((txid, latest_attempt), now)
        {
            return None;
        }

        tracing::info!(
            target: LOG_MODULE_WALLETV2,
            ?txid,
            attempt = latest_attempt,
            "Broadcasting FROST advance vote for stuck signing session"
        );
        Some(WalletConsensusItem::FrostAdvanceVote(txid, latest_attempt))
    }

    /// Broadcast our pre-computed signature share for `(txid, attempt)`.
    /// The share was computed when the attempt was created (see
    /// `compute_and_store_frost_signature_shares`) and stashed under
    /// `LocalFrostSignatureShareKey`; here we surface it so the other
    /// signers can aggregate. Receivers look up the (deterministic)
    /// `SigningPackage` and the `FederationTx` in their own DB by txid.
    /// Returns `None` when our share has already been delivered through
    /// consensus (also clears the pacing entry), when no share is stashed
    /// for this attempt, or while a recent broadcast is still in flight.
    async fn propose_signature_share(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        txid: Txid,
        attempt: u32,
        now: SystemTime,
    ) -> Option<WalletConsensusItem> {
        // Skip if our share has already been delivered through
        // consensus — no need to re-broadcast.
        let already_delivered = dbtx
            .get_value(&FrostSignatureShareKey {
                txid,
                attempt,
                peer_id: self.our_peer_id,
            })
            .await
            .is_some();
        if already_delivered {
            self.frost
                .broadcast_signature_shares
                .clear(&(txid, attempt));
            return None;
        }

        let shares = dbtx
            .get_value(&LocalFrostSignatureShareKey { txid, attempt })
            .await?;

        // Broadcast at most once per `FROST_REBROADCAST_INTERVAL`
        // (see [`InFlight`]).
        if !self
            .frost
            .broadcast_signature_shares
            .try_claim((txid, attempt), now)
        {
            return None;
        }

        tracing::info!(
            target: LOG_MODULE_WALLETV2,
            "Broadcasting our FROST signature share"
        );
        Some(WalletConsensusItem::FrostSignatureShare(
            txid, attempt, shares,
        ))
    }

    /// Reject FROST consensus items on federations whose descriptor isn't
    /// [`WalletDescriptor::Frost`]. Called by `process_consensus_item` for
    /// every `Frost*` item so malicious peers can't create FROST state on
    /// non-FROST federations. The descriptor is consensus config, so every
    /// guardian makes the same accept/reject decision.
    pub(crate) fn ensure_frost_federation(&self) -> anyhow::Result<()> {
        ensure!(
            matches!(self.cfg.consensus.descriptor, WalletDescriptor::Frost(_)),
            "Received FROST consensus item on a non-FROST federation"
        );
        Ok(())
    }

    /// This federation's FROST polynomial. Errors on any descriptor other
    /// than [`WalletDescriptor::Frost`], which callers already rule out via
    /// [`Self::ensure_frost_federation`].
    fn frost_polynomial(&self) -> anyhow::Result<&FrostPolynomial> {
        match &self.cfg.consensus.descriptor {
            WalletDescriptor::Frost(polynomial) => Ok(polynomial),
            _ => Err(anyhow!("Not a FROST federation")),
        }
    }

    /// The tweak of the FROST key for the UTXO with tweak `utxo_tweak`, taken
    /// from the same descriptor its address is derived from.
    fn frost_tweak(&self, polynomial: &FrostPolynomial, utxo_tweak: &sha256::Hash) -> FrostTweak {
        let tr = descriptor_tr(
            &self.cfg.consensus.bitcoin_pks,
            utxo_tweak,
            polynomial.internal_key(),
        );

        FrostTweak::new(polynomial.aggregate_key(), utxo_tweak, &tr)
    }

    /// Handle a `WalletConsensusItem::FrostSigningCommitments` from `peer`:
    /// store under `FrostSigningCommitmentsKey`, drop the corresponding
    /// in-flight entry if it's our own broadcast coming back, and run
    /// `try_progress_pending_signings` to opportunistically advance any
    /// tx that was waiting on commitment-buffer availability. Duplicates
    /// and retransmits of already-consumed commitments are rejected so
    /// they don't pollute `AcceptedItemKey` on recovery, and so the pool
    /// never holds a commitment its owner can no longer sign with.
    pub(crate) async fn process_frost_commitments(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        peer: PeerId,
        commitments: FrostSigningCommitments,
    ) -> anyhow::Result<()> {
        // Bound the sender's replicated commitment pool. The cap is a
        // hard constant rather than a multiple of the (per-guardian
        // configurable) nonce buffer target so that every guardian
        // reaches the same accept/reject decision — see
        // [`MAX_PEER_COMMITMENT_POOL`].
        let commitment_count = dbtx
            .find_by_prefix(&FrostSigningCommitmentsPeerPrefix(peer))
            .await
            .count()
            .await;
        ensure!(
            commitment_count < MAX_PEER_COMMITMENT_POOL,
            "FROST commitment pool for peer {peer} is full"
        );

        // A consumed commitment has left the pool, so the redundancy check
        // below can't recognise a delayed retransmit of it — yet its owner's
        // nonce is spent, so accepting it again would plant a commitment
        // nobody can sign with, stalling every attempt that selects it. The
        // tombstone written on consumption is replicated, so all guardians
        // reject it alike.
        ensure!(
            dbtx.get_value(&FrostConsumedCommitmentKey {
                peer_id: peer,
                frost_commitments: commitments.clone(),
            })
            .await
            .is_none(),
            "FROST signing commitment from peer {peer} was already consumed"
        );

        // Reject duplicates so they're not stored in `AcceptedItemKey`
        // and replayed on recovery. Mirrors the `Feerate` redundancy
        // handling.
        let was_present = dbtx
            .insert_entry(
                &FrostSigningCommitmentsKey {
                    peer_id: peer,
                    frost_commitments: commitments.clone(),
                },
                &(),
            )
            .await
            .is_some();

        if was_present {
            return Err(anyhow!("FROST signing commitment is redundant"));
        }

        tracing::info!(
            target: LOG_MODULE_WALLETV2,
            ?peer,
            commitment_count = commitment_count + 1,
            target = frost_nonce_buffer_target(),
            "Stored FROST signing commitment"
        );

        // Our own commitment has now been finalized — drop it from
        // the in-flight set so the next `consensus_proposal` can
        // freely propose new commitments without the race window.
        if peer == self.our_peer_id {
            self.frost.in_flight_commitments.clear(&commitments);
        }

        // A fresh commitment may have unblocked a tx that was
        // waiting on commitment-buffer availability. Retry any
        // pending signings.
        self.try_progress_pending_signings(dbtx).await?;

        Ok(())
    }

    /// Handle a `WalletConsensusItem::FrostSignatureShare` from `peer`:
    /// verify each per-input share against the stored signing packages
    /// and the peer's tweaked public key share, store under
    /// `FrostSignatureShareKey`, and — once the per-attempt share count
    /// hits `threshold` — aggregate into the final tap-key signatures,
    /// attach the witnesses, move the tx to `UnconfirmedTxKey`, broadcast
    /// it to bitcoind, and clean up all per-attempt state for this txid.
    /// Returns `Ok(())` for already-finalized txs (late share) and
    /// `Err` only for genuinely invalid shares (bad sig, wrong attempt,
    /// peer not in signing session, duplicate).
    pub(crate) async fn process_frost_signature_share(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        peer: PeerId,
        txid: Txid,
        attempt: u32,
        signature_shares: FrostSignatureShares,
    ) -> anyhow::Result<()> {
        tracing::info!(
            target: LOG_MODULE_WALLETV2,
            ?peer,
            attempt,
            "Received signature shares for tx from peer"
        );

        let Some(unsigned_tx) = dbtx.get_value(&UnsignedTxKey(txid)).await else {
            tracing::info!(
                target: LOG_MODULE_WALLETV2,
                "Tx already finalized, skipping signature share..."
            );
            return Ok(());
        };

        // The wire `attempt` identifies which attempt this share
        // is for. Multiple attempts can coexist; we just need a
        // record for *this* one. No staleness check is needed —
        // late shares for old attempts are still mathematically
        // valid against the old attempt's stored signing_packages,
        // and any attempt reaching threshold finalizes the tx.
        let stored_attempt = dbtx
            .get_value(&FrostSigningAttemptKey { txid, attempt })
            .await
            .ok_or_else(|| {
                anyhow!(
                    "FROST signature share references a nonexistent attempt {attempt} of tx {txid}"
                )
            })?;
        ensure!(
            stored_attempt.signing_session.contains(&peer),
            "Peer {peer} broadcast a signature share but is not in the \
             signing session for tx {txid} attempt {attempt}",
        );

        // Verify each per-input share before storing. Catches a malicious
        // or buggy peer here (where we can reject just their consensus
        // item) instead of at aggregation time, where one bad share
        // would otherwise blow up the whole session.
        let polynomial = self.frost_polynomial()?;
        let public_share = *self
            .frost_public_shares
            .get(&peer)
            .expect("Signing session peers are guardians");
        ensure!(
            signature_shares.signature_shares.len() == unsigned_tx.tx.input.len(),
            "Wrong number of FROST signature shares from peer {peer}",
        );

        let signing_packages = dbtx
            .get_value(&FrostSigningPackagesKey { txid, attempt })
            .await
            .ok_or_else(|| {
                anyhow!(
                    "Missing FROST signing packages for tx {txid} attempt {attempt} \
                     — DB inconsistency"
                )
            })?;
        ensure!(
            signing_packages.len() == unsigned_tx.tx.input.len(),
            "Stored FROST signing packages count mismatch for tx {txid} attempt {attempt}",
        );

        for (input_index, share) in signature_shares.signature_shares.iter().enumerate() {
            let tweak = self.frost_tweak(polynomial, &unsigned_tx.spent_tx_outs[input_index].tweak);
            let signing_package = &signing_packages[input_index];

            ensure!(
                verify_signature_share(
                    signing_package.message,
                    signer_id(peer),
                    &tweak.public_share(public_share),
                    share,
                    &signing_package.signer_nonces(),
                    tweak.aggregate(),
                ),
                "FROST signature share from peer {peer} for input {input_index} is invalid"
            );
        }

        // Reject duplicate broadcasts symmetrically across all
        // peers — including our own. The local-self-precompute
        // path stashes our share in `LocalFrostSignatureShareKey`
        // (separate key), so when our own broadcast comes back
        // through here it's a *first* write to
        // `FrostSignatureShareKey` and `was_present` is `false`,
        // exactly as for any other peer's first broadcast. Every
        // guardian therefore reaches the same Ok/Err decision on
        // every share item — `FrostSignatureShareKey` is a pure
        // function of consensus state.
        let was_present = dbtx
            .insert_entry(
                &FrostSignatureShareKey {
                    txid,
                    attempt,
                    peer_id: peer,
                },
                &signature_shares,
            )
            .await
            .is_some();
        if was_present {
            return Err(anyhow!(
                "FROST signature share from peer {peer} for tx {txid} attempt {attempt} \
                 is redundant"
            ));
        }

        // Lookup all signature shares for *this attempt only* — old
        // attempts' shares are still in the DB but live under a
        // different prefix and don't pollute the count.
        let shares = dbtx
            .find_by_prefix(&FrostSignatureShareAttemptPrefix { txid, attempt })
            .await
            .collect::<Vec<_>>()
            .await;
        let threshold = self.cfg.consensus.bitcoin_pks.to_num_peers().threshold();
        if shares.len() == threshold {
            let mut final_sigs = Vec::with_capacity(unsigned_tx.tx.input.len());
            for (input_index, signing_package) in signing_packages.iter().enumerate() {
                let tweak =
                    self.frost_tweak(polynomial, &unsigned_tx.spent_tx_outs[input_index].tweak);

                let shares_for_input = shares
                    .iter()
                    .map(|(k, v)| (signer_id(k.peer_id), v.signature_shares[input_index]))
                    .collect::<BTreeMap<_, _>>();

                let final_sig = aggregate_signature_shares(
                    signing_package.message,
                    &signing_package.signer_nonces(),
                    &shares_for_input,
                    tweak.aggregate(),
                );

                // Every share was verified against the session before it was
                // stored, so their aggregate is a valid signature.
                assert!(
                    verify(signing_package.message, &final_sig, tweak.aggregate()),
                    "The aggregate of verified FROST signature shares must verify"
                );

                tracing::info!(
                    target: LOG_MODULE_WALLETV2,
                    input_index,
                    "Aggregated FROST signature for input"
                );

                final_sigs.push(final_sig);
            }

            // Attach key-path witnesses, move tx unsigned → unconfirmed,
            // clean up the per-peer share entries + cached signing
            // packages + signing-attempt record + advance votes
            // (across all attempts), and broadcast.
            let mut unsigned = unsigned_tx;
            attach_key_path_witnesses(
                &mut unsigned,
                final_sigs.iter().map(|sig| sig.serialize().to_vec()),
            );

            // Capture this guardian's local finalization-latency stat before
            // the cleanup below removes the attempt / advance-vote records and
            // the first-seen timestamp it's derived from.
            self.record_finalization_stat(dbtx, txid).await;

            // All per-attempt state for this tx — across every
            // attempt that ever ran — gets cleaned up here, since
            // shares, packages, and attempt records are all keyed
            // by `(txid, attempt)`.
            dbtx.remove_by_prefix(&FrostSignatureShareTxidPrefix(txid))
                .await;
            dbtx.remove_by_prefix(&LocalFrostSignatureShareTxidPrefix(txid))
                .await;
            dbtx.remove_by_prefix(&FrostSigningPackagesTxidPrefix(txid))
                .await;
            dbtx.remove_by_prefix(&FrostSigningAttemptTxidPrefix(txid))
                .await;
            dbtx.remove_by_prefix(&FrostAdvanceVoteTxidPrefix(txid))
                .await;
            // Drop in-memory broadcast guards for this tx — no more
            // shares to broadcast and no more votes to file.
            self.frost
                .broadcast_signature_shares
                .retain(|(t, _)| *t != txid);
            self.frost
                .in_flight_advance_votes
                .retain(|(t, _)| *t != txid);
            self.frost
                .tx_attempt_first_seen
                .lock()
                .expect("tx_attempt_first_seen mutex poisoned")
                .retain(|(t, _), _| *t != txid);

            self.finalize_and_broadcast(dbtx, txid, unsigned).await;
        } else {
            tracing::info!(
                target: LOG_MODULE_WALLETV2,
                ?peer,
                len = %shares.len(),
                "Not enough shares for this transaction yet."
            );
        }

        // A late share's arrival is the signal that this peer is no
        // longer a suspect — the next pick_signing_session call will
        // see a smaller suspect set. Re-run the retry loop now so a
        // previously failing advance can succeed without waiting on a
        // commitment broadcast or a new transaction.
        self.try_progress_pending_signings(dbtx).await?;

        Ok(())
    }

    /// Record a local finalization-latency record for `txid` under
    /// [`FrostFinalizationStatKey`]. Must be called from the finalize branch
    /// *before* it removes the attempt and advance-vote records (whose counts
    /// are read here) and *before* `tx_attempt_first_seen` is cleared (the
    /// earliest attempt's first-seen timestamp is the measurement start).
    ///
    /// `attempts` and `advance_votes` are read from the consensus DB, so they
    /// are identical on every guardian; `duration_millis` is derived from a
    /// local wall-clock `now()` and is therefore per-peer state. It's written
    /// to `dbtx` purely as diagnostics and is never read back during consensus,
    /// so — like the per-guardian FROST nonces — the divergence has no
    /// consensus implications.
    async fn record_finalization_stat(&self, dbtx: &mut DatabaseTransaction<'_>, txid: Txid) {
        let attempts = dbtx
            .find_by_prefix(&FrostSigningAttemptTxidPrefix(txid))
            .await
            .count()
            .await as u32;
        let advance_votes = dbtx
            .find_by_prefix(&FrostAdvanceVoteTxidPrefix(txid))
            .await
            .count()
            .await as u64;

        // Start = when we first observed the earliest attempt of this tx (the
        // smallest attempt entry we still hold). Absent only in the
        // pathological case where we process the threshold share before our
        // own `consensus_proposal` ever logged the tx — skip recording then
        // rather than report a bogus duration.
        let first_seen = {
            let map = self
                .frost
                .tx_attempt_first_seen
                .lock()
                .expect("tx_attempt_first_seen mutex poisoned");
            map.iter()
                .filter(|((t, _), _)| *t == txid)
                .min_by_key(|((_, attempt), _)| *attempt)
                .map(|(_, seen)| *seen)
        };
        let Some(first_seen) = first_seen else {
            tracing::debug!(
                target: LOG_MODULE_WALLETV2,
                ?txid,
                "No first-seen timestamp for finalized tx; skipping finalization stat"
            );
            return;
        };

        let duration_millis = fedimint_core::time::now()
            .duration_since(first_seen)
            .unwrap_or_default()
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX);

        dbtx.insert_entry(
            &FrostFinalizationStatKey(txid),
            &FrostFinalizationStat {
                txid,
                duration_millis,
                attempts,
                advance_votes,
            },
        )
        .await;
    }

    /// This guardian's locally-measured FROST finalization-latency record for
    /// `txid`, or `None` if this guardian hasn't finalized that tx. Backs the
    /// authenticated `FROST_FINALIZATION_STATS_ENDPOINT`.
    pub(crate) async fn finalization_stat(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        txid: Txid,
    ) -> Option<FrostFinalizationStat> {
        dbtx.get_value(&FrostFinalizationStatKey(txid)).await
    }

    /// Handle a `WalletConsensusItem::FrostAdvanceVote` from `peer`:
    /// record under `FrostAdvanceVoteKey`, then if the per-(txid, attempt)
    /// vote count crosses `f+1` and `attempt + 1` doesn't already exist,
    /// build the next attempt by calling
    /// `compute_and_store_frost_signature_shares(.., attempt + 1)`.
    /// Errors building the next attempt (e.g., thin commitment buffer)
    /// are swallowed — the vote is still recorded, and
    /// `try_progress_pending_signings` will retry on the next
    /// commitment.
    pub(crate) async fn process_frost_advance_vote(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        peer: PeerId,
        txid: Txid,
        attempt: u32,
    ) -> anyhow::Result<()> {
        // Validate the wire `attempt` corresponds to a real attempt
        // in our DB. We don't reject votes for older attempts —
        // those are still real attempts whose data is preserved;
        // we just won't re-advance past the next one (see below).
        ensure!(
            dbtx.get_value(&FrostSigningAttemptKey { txid, attempt })
                .await
                .is_some(),
            "FROST advance vote references a nonexistent attempt {attempt} of tx {txid}",
        );

        // Dedup: each peer votes at most once per (txid, attempt).
        let was_present = dbtx
            .insert_entry(
                &FrostAdvanceVoteKey {
                    txid,
                    attempt,
                    voter: peer,
                },
                &(),
            )
            .await
            .is_some();
        if was_present {
            return Err(anyhow!("Duplicate FROST advance vote from peer {peer}"));
        }

        if peer == self.our_peer_id {
            self.frost.in_flight_advance_votes.clear(&(txid, attempt));
        }

        tracing::info!(
            target: LOG_MODULE_WALLETV2,
            ?peer,
            ?txid,
            attempt,
            "Recorded FROST advance vote"
        );

        // Tally votes for this (txid, attempt). Advance once `f+1`
        // distinct voters agree the session is stuck — that's the
        // smallest threshold at which Byzantine peers can't trigger
        // advance alone.
        let vote_count = dbtx
            .find_by_prefix(&FrostAdvanceVoteAttemptPrefix { txid, attempt })
            .await
            .count()
            .await;
        let advance_threshold = self.cfg.consensus.bitcoin_pks.to_num_peers().max_evil() + 1;
        if vote_count < advance_threshold {
            return Ok(());
        }

        // Idempotent advance: if `(txid, attempt + 1)` already
        // exists, the federation has already advanced — extra
        // votes for `attempt` are recorded for posterity but
        // don't trigger another advance. No teardown needed:
        // attempts are append-only and old data lives at its own
        // per-attempt prefix until tx finalization.
        let next_attempt = attempt + 1;
        let next_already_exists = dbtx
            .get_value(&FrostSigningAttemptKey {
                txid,
                attempt: next_attempt,
            })
            .await
            .is_some();
        if next_already_exists {
            tracing::info!(
                target: LOG_MODULE_WALLETV2,
                ?txid,
                attempt,
                next_attempt,
                "FROST advance threshold reached, but next attempt already exists"
            );
            return Ok(());
        }

        // Invariant: the `ensure!` above requires an attempt record for this
        // tx, and finalization removes the attempt records and `UnsignedTxKey`
        // in the same dbtx — so an attempt record implies the tx is unsigned.
        let unsigned_tx = dbtx
            .get_value(&UnsignedTxKey(txid))
            .await
            .expect("active attempt implies UnsignedTxKey exists");

        // Append a new attempt at `attempt + 1`. Old attempt N's
        // shares, packages, and attempt record stay in their
        // per-attempt slots. Late shares for attempt N can still
        // arrive and contribute toward attempt N's threshold —
        // and any attempt that reaches threshold finalizes the
        // tx. Cleanup happens at finalization.
        //
        // If `compute_and_store` fails (typically because the
        // federation's commitment buffer is too thin to form a
        // viable session right now), don't propagate the error —
        // the vote was already recorded above. The next
        // FrostSigningCommitments processing will retry via
        // try_progress_pending_signings once buffers refill.
        match self
            .compute_and_store_frost_signature_shares(dbtx, &unsigned_tx, next_attempt)
            .await
        {
            Ok(()) => {
                let next_attempt_record = dbtx
                    .get_value(&FrostSigningAttemptKey {
                        txid,
                        attempt: next_attempt,
                    })
                    .await
                    .expect("compute_and_store just persisted this attempt");

                tracing::info!(
                    target: LOG_MODULE_WALLETV2,
                    ?txid,
                    attempt,
                    next_attempt,
                    vote_count,
                    advance_threshold,
                    next_signing_session = ?next_attempt_record.signing_session,
                    "FROST advance threshold reached; built next attempt"
                );
            }
            Err(err) => {
                tracing::warn!(
                    target: LOG_MODULE_WALLETV2,
                    ?txid,
                    attempt,
                    next_attempt,
                    err = %err.fmt_compact(),
                    "FROST advance threshold reached but couldn't build next attempt; will retry when commitments replenish"
                );
            }
        }

        Ok(())
    }

    /// Kick off the initial FROST signing attempt (`attempt = 0`) for a
    /// freshly created `unsigned_tx`. No-op when the federation isn't
    /// FROST. Errors building the attempt (typically a thin commitment
    /// buffer) are logged at `warn` level rather than propagated — the
    /// next `FrostSigningCommitments` processing will retry via
    /// `try_progress_pending_signings`.
    pub(crate) async fn start_initial_frost_signing(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        unsigned: &FederationTx,
        txid: Txid,
    ) {
        if !matches!(self.cfg.consensus.descriptor, WalletDescriptor::Frost(_)) {
            return;
        }
        if let Err(err) = self
            .compute_and_store_frost_signature_shares(dbtx, unsigned, 0)
            .await
        {
            // Tx is created without an attempt; the next
            // FrostSigningCommitments processing will retry via
            // try_progress_pending_signings once buffers refill.
            tracing::warn!(
                target: LOG_MODULE_WALLETV2,
                ?txid,
                err = %err.fmt_compact(),
                "Couldn't start initial FROST signing attempt; will retry when commitments replenish"
            );
        }
    }
}

/// One-shot startup backfill: top the local FROST nonce buffer up to
/// [`frost_nonce_buffer_target()`] and exit. After this, the buffer is
/// maintained 1:1 by `consume_our_nonce`, which generates a replacement
/// nonce inline every time it consumes one. So this only ever generates
/// nonces on cold start, restart, or recovery — anything that produces
/// a buffer below target.
///
/// `consensus_proposal` broadcasts the matching commitments via
/// `WalletConsensusItem::FrostSigningCommitments` so other guardians can
/// build a `SigningPackage` for us when needed. Each nonce is consumed
/// once (`consume_our_nonce` removes it after use) — FROST nonces must
/// never be reused, or the long-lived signing share is leaked.
pub(crate) fn spawn_initial_nonce_backfill(db: Database, task_group: &TaskGroup) {
    task_group.spawn_cancellable("frost initial nonce backfill", async move {
        let mut dbtx = db.begin_transaction().await;
        let count = dbtx
            .find_by_prefix(&FrostSigningNoncesPrefix)
            .await
            .count()
            .await;
        for _ in 0..frost_nonce_buffer_target().saturating_sub(count) {
            let (seed, commitment) = FrostNonceSeed::generate();

            dbtx.insert_new_entry(&FrostSigningNoncesKey(commitment), &seed)
                .await;
        }
        dbtx.commit_tx().await;
    });
}

/// The bip445 identity of a peer. bip445 evaluates the key polynomial at
/// `identity + 1`, the same point as [`scalar_secp`], so it is the peer id
/// itself.
fn signer_id(peer: PeerId) -> u64 {
    peer.to_usize() as u64
}

/// Deterministically pick a `threshold`-sized signing session for `(txid,
/// attempt)`. Walks a shuffle of `all_peers` seeded by `(txid, attempt)`,
/// skipping peers whose `FrostSigningCommitments` pool is shorter than
/// `required_commitments` (one commitment per input is consumed per session
/// peer). Non-suspects fill the session first; suspects only fill the seats
/// left over, in shuffle order. Returns `None` only if fewer than
/// `threshold` peers are viable at all.
///
/// All inputs (commitment counts, suspects) are derived from
/// consensus-replicated DB state, so every peer computes the same answer.
///
/// With at most `f` faulty peers, at least `threshold` peers never become
/// suspects, so suspects are never selected and the tx signs within `f + 1`
/// attempts. Suspects are only drafted back in beyond that, which is what
/// keeps an honest peer that can never clear its suspicion from stalling the
/// tx: one that lost the nonces behind its replicated commitments (a DB
/// restore or wipe) can't produce a late share for the attempt it failed.
/// Each attempt it is drafted into consumes and tombstones some of those
/// unusable commitments, so it signs again once they are used up.
///
/// `forced_signer` is a test hook (see [`frost_test_forced_signer`]): if it is
/// viable, it takes the first seat in attempt `0`, and the others keep their
/// shuffle order.
#[allow(clippy::too_many_arguments)]
async fn pick_signing_session(
    dbtx: &mut DatabaseTransaction<'_>,
    all_peers: &[PeerId],
    threshold: usize,
    txid: Txid,
    attempt: u32,
    required_commitments: usize,
    suspects: &BTreeSet<PeerId>,
    forced_signer: Option<PeerId>,
) -> Option<Vec<PeerId>> {
    let mut commitment_counts: BTreeMap<PeerId, usize> = BTreeMap::new();
    for &peer in all_peers {
        let count = dbtx
            .find_by_prefix(&FrostSigningCommitmentsPeerPrefix(peer))
            .await
            .count()
            .await;
        commitment_counts.insert(peer, count);
    }
    let viable =
        |peer: &PeerId| commitment_counts.get(peer).copied().unwrap_or(0) >= required_commitments;

    let seed: [u8; 32] = (txid, attempt)
        .consensus_hash::<sha256::Hash>()
        .to_byte_array();
    let mut rng = ChaCha8Rng::from_seed(seed);
    let mut shuffled = all_peers.to_vec();
    shuffled.shuffle(&mut rng);

    if attempt == 0
        && let Some(forced_signer) = forced_signer
        && let Some(position) = shuffled.iter().position(|peer| *peer == forced_signer)
    {
        // Move it to the front, keeping the others in shuffle order.
        shuffled[..=position].rotate_right(1);
    }

    let (non_suspects, drafted_suspects): (Vec<PeerId>, Vec<PeerId>) = shuffled
        .into_iter()
        .filter(viable)
        .partition(|peer| !suspects.contains(peer));
    let session: Vec<PeerId> = non_suspects
        .into_iter()
        .chain(drafted_suspects)
        .take(threshold)
        .collect();
    if session.len() == threshold {
        return Some(session);
    }
    None
}

/// Generate FROST key material centrally via a trusted dealer for
/// `peers`. Used by `trusted_dealer_gen` (the test / scripted path
/// that doesn't run a real DKG). Produces the commitment to a random
/// polynomial of degree `threshold - 1`, stored as `WalletDescriptor::Frost`
/// on every peer, and every peer's secret share, its evaluation at the peer's
/// evaluation point. Each peer receives only its own share.
///
/// The dealer holds every share momentarily and so must be trusted; real
/// federations run the secp256k1 DKG instead. Skipped entirely when
/// `peers.len() == 1` (caller collapses to `WalletDescriptor::SinglePeer`).
pub(crate) fn trusted_setup(peers: &[PeerId]) -> (FrostPolynomial, BTreeMap<PeerId, SecretKey>) {
    let coefficients = (0..peers.to_num_peers().threshold())
        .map(|_| SecretKey::new(&mut OsRng))
        .collect::<Vec<SecretKey>>();

    let polynomial = FrostPolynomial(
        coefficients
            .iter()
            .map(|coefficient| coefficient.public_key(secp256k1::SECP256K1))
            .collect(),
    );

    let shares = peers
        .iter()
        .map(|peer| {
            let x = scalar_secp(peer);

            let share = coefficients
                .iter()
                .copied()
                .rev()
                .reduce(|accumulator, coefficient| {
                    accumulator
                        .mul_tweak(&x)
                        .expect("The evaluation point is nonzero")
                        .add_tweak(&Scalar::from(coefficient))
                        .expect("A random polynomial evaluates to zero with negligible probability")
                })
                .expect("The polynomial has at least one coefficient");

            (*peer, share)
        })
        .collect();

    (polynomial, shares)
}

#[cfg(test)]
mod tests;
