use std::collections::{BTreeMap, BTreeSet};
use std::sync::{LazyLock, Mutex};
use std::time::SystemTime;

use anyhow::{anyhow, ensure};
use bitcoin::hashes::{Hash, sha256};
use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin::{Txid, XOnlyPublicKey};
use fedimint_core::db::{Database, DatabaseTransaction, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::encoding::{Decodable, DecodeError, Encodable};
use fedimint_core::envs::FM_WALLETV2_FROST_NONCE_BUFFER_TARGET_ENV;
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::task::TaskGroup;
use fedimint_core::util::FmtCompactAnyhow as _;
use fedimint_core::{NumPeersExt, PeerId};
use fedimint_logging::LOG_MODULE_WALLETV2;
use fedimint_server_core::config::{PeerHandleOps, PeerHandleOpsExt};
use fedimint_walletv2_common::WalletConsensusItem;
use fedimint_walletv2_common::config::WalletDescriptor;
use fedimint_walletv2_common::taproot::frost::{
    FrostFinalizationStat, FrostSignatureShares, FrostSigningCommitments,
};
use frost_secp256k1_tr as frost;
use frost_secp256k1_tr::keys::{
    EvenY, KeyPackage, PublicKeyPackage, SigningShare, Tweak, VerifyingShare,
};
use frost_secp256k1_tr::round2::SignatureShare;
use frost_secp256k1_tr::{Identifier, SigningPackage, VerifyingKey};
use futures::StreamExt;
use rand::SeedableRng;
use rand::rngs::OsRng;
use rand::seq::SliceRandom;
use rand_chacha::ChaCha8Rng;
use secp256k1::{PublicKey, Scalar};

use crate::db::{
    FrostAdvanceVoteAttemptPrefix, FrostAdvanceVoteKey, FrostAdvanceVoteTxidPrefix,
    FrostFinalizationStatKey, FrostSignatureShareAttemptPrefix, FrostSignatureShareKey,
    FrostSignatureShareTxidPrefix, FrostSigningAttempt, FrostSigningAttemptKey,
    FrostSigningAttemptTxidPrefix, FrostSigningCommitmentsKey, FrostSigningCommitmentsPeerPrefix,
    FrostSigningNoncesKey, FrostSigningNoncesPrefix, FrostSigningPackagesKey,
    FrostSigningPackagesTxidPrefix, LocalFrostSignatureShareKey,
    LocalFrostSignatureShareTxidPrefix, UnconfirmedTxKey, UnsignedTxKey, UnsignedTxPrefix,
};
use crate::{FederationTx, Wallet};

/// In-memory FROST tracking state. Every entry is local — never read
/// from or written to `dbtx` — so it doesn't influence consensus.
#[derive(Debug, Default)]
pub(crate) struct FrostRuntime {
    /// FROST commitments we've put into a `consensus_proposal` output but
    /// haven't yet seen come back through `process_consensus_item`,
    /// keyed by commitment with the wall-clock timestamp of the last
    /// broadcast attempt. The DB filter on its own is racy: at 100ms
    /// proposal cadence, the same commitment can be re-submitted several
    /// times before `AlephBFT` finalizes the first copy — the timestamp
    /// makes the filter exact. Entries older than
    /// `FROST_REBROADCAST_INTERVAL` are eligible for re-broadcast in
    /// case `AlephBFT` silently dropped the original unit (more likely in
    /// larger federations near session boundaries). Cleared when our
    /// own commitment is processed.
    pub(crate) in_flight_commitments: Mutex<BTreeMap<FrostSigningCommitments, SystemTime>>,
    /// Wall-clock timestamp of when we first observed each `(txid, attempt)`
    /// locally. Used to fire a per-peer advance vote when the session has
    /// been waiting longer than `local_advance_timeout()`. Per-peer state;
    /// not consensus.
    pub(crate) tx_attempt_first_seen: Mutex<BTreeMap<(Txid, u32), SystemTime>>,
    /// Same in-flight pattern as `in_flight_commitments`, but for advance
    /// votes. Keeps us from re-broadcasting the same vote at every
    /// `consensus_proposal` tick before the first one has been finalized.
    pub(crate) in_flight_advance_votes: Mutex<BTreeSet<(Txid, u32)>>,
    /// Wall-clock timestamp of our last broadcast attempt for each
    /// `(Txid, attempt)`. We don't blindly skip already-broadcast shares
    /// — `AlephBFT` can drop a unit when its broadcast lands close to a
    /// session boundary, especially in larger federations where each
    /// peer has a smaller fraction of the per-round byte budget. If our
    /// share hasn't been delivered through consensus by
    /// `REBROADCAST_INTERVAL` after the last try, we propose it again.
    /// Cleared when our share comes back through `process_consensus_item`
    /// (entry no longer needed) or when the tx finalizes.
    pub(crate) broadcast_signature_shares: Mutex<BTreeMap<(Txid, u32), SystemTime>>,
}

impl Wallet {
    /// Compute the BIP-341 key-path sighash for the given input of
    /// `unsigned_tx`. This is the message that the FROST signers will
    /// collectively sign.
    pub(crate) fn build_frost_key_spend_message(
        &self,
        unsigned_tx: &FederationTx,
        input_index: usize,
    ) -> [u8; 32] {
        let prevouts = self.build_prevouts(unsigned_tx);
        let mut sighash_cache = SighashCache::new(unsigned_tx.tx.clone());

        sighash_cache
            .taproot_key_spend_signature_hash(
                input_index,
                &Prevouts::All(&prevouts),
                bitcoin::TapSighashType::Default,
            )
            .expect("Failed to compute taproot key spend sighash")
            .to_byte_array()
    }

    /// Build and persist the FROST `SigningPackage` for each input of
    /// `unsigned_tx`. Every peer (signer or not) runs this so the package is
    /// available later for verifying and aggregating shares without it
    /// having to ride along with each `FrostSignatureShare` consensus item.
    /// Signing-session peers additionally consume their per-input nonce and
    /// produce their `SignatureShare`s, stored under their own `peer_id` for
    /// the next `consensus_proposal` to broadcast.
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
        )
        .await
        .ok_or_else(|| {
            anyhow!("Insufficient FROST commitment buffer across federation for tx {txid}")
        })?;
        let is_signer = signing_session.contains(&self.our_peer_id);

        let key_package = if is_signer {
            Some(
                self.cfg
                    .private
                    .frost_key_package
                    .clone()
                    .ok_or_else(|| anyhow!("FROST federation must have a frost_key_package"))?,
            )
        } else {
            None
        };

        let mut signing_packages: Vec<FrostSigningPackage> =
            Vec::with_capacity(unsigned_tx.tx.input.len());
        let mut signature_shares: Vec<SignatureShare> = Vec::new();

        for input_index in 0..unsigned_tx.tx.input.len() {
            let utxo = &unsigned_tx.spent_tx_outs[input_index];
            let message = self.build_frost_key_spend_message(unsigned_tx, input_index);

            let commitments_map = self
                .consume_session_commitments(dbtx, &signing_session)
                .await?;

            let signing_package_commitments: BTreeMap<Identifier, _> = commitments_map
                .iter()
                .map(|(id, commitment)| (*id, commitment.0))
                .collect();
            let signing_package = SigningPackage::new(signing_package_commitments, &message);

            if let Some(key_package) = &key_package {
                let nonce = self.consume_our_nonce(dbtx, &commitments_map).await?;

                let tweaked_key_package = apply_utxo_tweak_to_key_package(key_package, &utxo.tweak);
                // Single-leaf TapTree: merkle root = leaf hash.
                let merkle_root = self.tap_leaf_hash(&utxo.tweak).to_byte_array();

                let signature_share = frost::round2::sign_with_tweak(
                    &signing_package,
                    &nonce,
                    &tweaked_key_package,
                    Some(&merkle_root),
                )?;

                tracing::info!(
                    target: LOG_MODULE_WALLETV2,
                    input_index,
                    "Generated FROST signature share for input"
                );

                signature_shares.push(signature_share);
            }

            signing_packages.push(FrostSigningPackage(signing_package));
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

        if is_signer {
            // Local-only stash. The canonical, consensus-replicated
            // `FrostSignatureShareKey` entry is written when our broadcast
            // comes back through AlephBFT. Splitting these keeps
            // `pick_signing_session`'s suspects (which reads
            // `FrostSignatureShareKey`) a pure function of consensus state
            // — every guardian agrees on it at every item boundary.
            dbtx.insert_new_entry(
                &LocalFrostSignatureShareKey { txid, attempt },
                &FrostSignatureShares { signature_shares },
            )
            .await;
        }

        Ok(())
    }

    /// Take the first available `FrostSigningCommitments` for each peer in
    /// `signing_session` and remove them from the DB. Called by every peer
    /// (including non-session peers) so that DB state — and therefore the
    /// derived `SigningPackage` — stays in sync across the federation.
    pub(crate) async fn consume_session_commitments(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        signing_session: &[PeerId],
    ) -> anyhow::Result<BTreeMap<Identifier, FrostSigningCommitments>> {
        let mut commitments_map = BTreeMap::new();
        for peer_id in signing_session {
            let commitment = dbtx
                .find_by_prefix(&FrostSigningCommitmentsPeerPrefix(*peer_id))
                .await
                .next()
                .await
                .ok_or_else(|| anyhow!("No FROST commitments available for peer {peer_id}"))?;
            commitments_map.insert(
                peer_id_to_identifier(*peer_id),
                commitment.0.frost_commitments.clone(),
            );
            dbtx.remove_entry(&commitment.0).await;
        }
        Ok(commitments_map)
    }

    /// Look up our own `SigningNonces` matching our entry in
    /// `commitments_map` and remove it from the DB. Only signing-session
    /// peers should call this — for non-session peers `our_peer_id` won't be
    /// in the map.
    pub(crate) async fn consume_our_nonce(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        commitments_map: &BTreeMap<Identifier, FrostSigningCommitments>,
    ) -> anyhow::Result<frost::round1::SigningNonces> {
        let our_commitment = commitments_map
            .get(&peer_id_to_identifier(self.our_peer_id))
            .ok_or_else(|| anyhow!("Our peer is not in the signing session"))?;
        let nonce = dbtx
            .remove_entry(&FrostSigningNoncesKey(our_commitment.clone()))
            .await
            .ok_or_else(|| {
                anyhow!("FROST nonce for our own commitment is missing — DB inconsistency")
            })?
            .0;

        // Inline 1:1 replacement: keep our local nonce buffer at
        // `frost_nonce_buffer_target()` invariantly. Local-only state, no
        // consensus implications.
        let key_package = self
            .cfg
            .private
            .frost_key_package
            .as_ref()
            .expect("FROST federation must have a frost_key_package");
        let (new_nonce, new_commitment) =
            frost_secp256k1_tr::round1::commit(key_package.signing_share(), &mut OsRng);
        dbtx.insert_new_entry(
            &FrostSigningNoncesKey(FrostSigningCommitments(new_commitment)),
            &FrostSigningNonces(new_nonce),
        )
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
                {
                    tracing::trace!(
                        target: LOG_MODULE_WALLETV2,
                        ?txid,
                        target_attempt = target,
                        err = %err.fmt_compact_anyhow(),
                        "Couldn't progress FROST signing for tx; will retry on next commitment"
                    );
                }
            }
        }

        Ok(())
    }

    /// Build the FROST-specific items this peer wants to propose for the
    /// next `AlephBFT` round:
    ///
    /// - any unbroadcasted commitments from our local nonce buffer,
    /// - an advance vote for any tx whose latest attempt has been waiting
    ///   longer than `local_advance_timeout()`,
    /// - our pre-computed signature share for each unsigned tx whose latest
    ///   attempt includes us in the signing session and whose broadcast hasn't
    ///   yet landed in `FrostSignatureShareKey`.
    ///
    /// Re-broadcasts are gated by `FROST_REBROADCAST_INTERVAL` to recover
    /// from `AlephBFT` silently dropping a unit (more likely with larger
    /// federations near session boundaries) without spamming every
    /// proposal cycle.
    pub(crate) async fn frost_consensus_proposal(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
    ) -> Vec<WalletConsensusItem> {
        let mut items: Vec<WalletConsensusItem> = Vec::new();

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

        // Snapshot the in-flight set: commitments we've already pushed to
        // a previous proposal but that haven't yet been finalized through
        // AlephBFT. Without this, the DB filter alone races with the
        // proposal cadence (~100ms) vs. consensus round-trip (~150–300ms)
        // and the same commitment goes out repeatedly. Stale entries
        // (older than `FROST_REBROADCAST_INTERVAL`) are eligible for
        // re-broadcast — AlephBFT can drop a unit when its broadcast
        // lands close to a session boundary in larger federations.
        let now = fedimint_core::time::now();
        let in_flight_snapshot: BTreeSet<FrostSigningCommitments> = self
            .frost
            .in_flight_commitments
            .lock()
            .expect("in_flight_commitments mutex poisoned")
            .iter()
            .filter(|(_, t)| {
                now.duration_since(**t).unwrap_or_default() < FROST_REBROADCAST_INTERVAL
            })
            .map(|(c, _)| c.clone())
            .collect();

        let new_commitments: Vec<FrostSigningCommitments> = my_nonces
            .into_iter()
            .filter_map(|(commitment, _)| {
                let c = commitment.0;
                (!my_commitments.contains(&c) && !in_flight_snapshot.contains(&c)).then_some(c)
            })
            .collect();

        if !new_commitments.is_empty() {
            tracing::info!(
                target: LOG_MODULE_WALLETV2,
                commitment_len = %new_commitments.len(),
                "Added commitments to be broadcasted"
            );

            {
                let mut in_flight = self
                    .frost
                    .in_flight_commitments
                    .lock()
                    .expect("in_flight_commitments mutex poisoned");
                for c in &new_commitments {
                    in_flight.insert(c.clone(), now);
                }
            }

            items.extend(
                new_commitments
                    .into_iter()
                    .map(|c| WalletConsensusItem::FrostSigningCommitments(Box::new(c))),
            );
        }

        // Broadcast our pre-computed signature share for each active signing
        // session. We compute the share inline in `process_input` /
        // `process_output` when the unsigned tx is created and store it
        // locally at our own peer_id; here we surface it so the other
        // signers can aggregate. Receivers look up the (deterministic)
        // SigningPackage and the FederationTx in their own DB by txid.
        // The signing_session for each tx is read from FrostSigningAttemptKey
        // — set when the tx was created — so the choice of signers is
        // a per-tx fact, not a global constant.
        let txids = dbtx
            .find_by_prefix(&UnsignedTxPrefix)
            .await
            .map(|(key, _)| key.0)
            .collect::<Vec<_>>()
            .await;
        for txid in txids {
            // Find the latest attempt for this tx — attempts are
            // append-only, so the highest attempt number is the
            // current one. None means the tx hasn't reached the
            // FROST signing path yet (e.g. first peg-in, which only
            // inserts the FederationWalletKey).
            let Some((latest_attempt, attempt)) = dbtx
                .find_by_prefix(&FrostSigningAttemptTxidPrefix(txid))
                .await
                .map(|(k, v)| (k.attempt, v))
                .collect::<Vec<_>>()
                .await
                .into_iter()
                .max_by_key(|(att, _)| *att)
            else {
                continue;
            };

            // If the current attempt has been waiting longer than our
            // local advance timeout, broadcast a vote to abandon it.
            // Any peer can vote, including non-session observers — they
            // can see whose share is missing from their own DB.
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
                    > local_advance_timeout()
            };
            if timer_expired {
                let in_flight = self
                    .frost
                    .in_flight_advance_votes
                    .lock()
                    .expect("in_flight_advance_votes mutex poisoned")
                    .contains(&(txid, latest_attempt));
                let already_voted = dbtx
                    .get_value(&FrostAdvanceVoteKey {
                        txid,
                        attempt: latest_attempt,
                        voter: self.our_peer_id,
                    })
                    .await
                    .is_some();
                if !in_flight && !already_voted {
                    self.frost
                        .in_flight_advance_votes
                        .lock()
                        .expect("in_flight_advance_votes mutex poisoned")
                        .insert((txid, latest_attempt));
                    tracing::info!(
                        target: LOG_MODULE_WALLETV2,
                        ?txid,
                        attempt = latest_attempt,
                        "Broadcasting FROST advance vote for stuck signing session"
                    );
                    items.push(WalletConsensusItem::FrostAdvanceVote((
                        txid,
                        latest_attempt,
                    )));
                }
            }

            if !attempt.signing_session.contains(&self.our_peer_id) {
                continue;
            }
            // Skip if our share has already been delivered through
            // consensus — no need to re-broadcast.
            let already_delivered = dbtx
                .get_value(&FrostSignatureShareKey {
                    txid,
                    attempt: latest_attempt,
                    peer_id: self.our_peer_id,
                })
                .await
                .is_some();
            if already_delivered {
                self.frost
                    .broadcast_signature_shares
                    .lock()
                    .expect("broadcast_signature_shares mutex poisoned")
                    .remove(&(txid, latest_attempt));
                continue;
            }
            // Otherwise broadcast at most once per
            // `REBROADCAST_INTERVAL`. AlephBFT can drop our unit when
            // the broadcast lands close to a session boundary; the
            // retry recovers without spamming every proposal cycle.
            let now = fedimint_core::time::now();
            let should_broadcast = {
                let map = self
                    .frost
                    .broadcast_signature_shares
                    .lock()
                    .expect("broadcast_signature_shares mutex poisoned");
                match map.get(&(txid, latest_attempt)) {
                    None => true,
                    Some(last) => {
                        now.duration_since(*last).unwrap_or_default() >= FROST_REBROADCAST_INTERVAL
                    }
                }
            };
            if !should_broadcast {
                continue;
            }
            let key = LocalFrostSignatureShareKey {
                txid,
                attempt: latest_attempt,
            };
            if let Some(shares) = dbtx.get_value(&key).await {
                self.frost
                    .broadcast_signature_shares
                    .lock()
                    .expect("broadcast_signature_shares mutex poisoned")
                    .insert((txid, latest_attempt), now);
                tracing::info!(
                    target: LOG_MODULE_WALLETV2,
                    "Broadcasting our FROST signature share"
                );
                items.push(WalletConsensusItem::FrostSignatureShare((
                    txid,
                    latest_attempt,
                    shares,
                )));
            }
        }

        items
    }

    /// Handle a `WalletConsensusItem::FrostSigningCommitments` from `peer`:
    /// store under `FrostSigningCommitmentsKey`, drop the corresponding
    /// in-flight entry if it's our own broadcast coming back, and run
    /// `try_progress_pending_signings` to opportunistically advance any
    /// tx that was waiting on commitment-buffer availability. Duplicates
    /// are rejected so they don't pollute `AcceptedItemKey` on recovery.
    pub(crate) async fn process_frost_commitments(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        peer: PeerId,
        commitments: FrostSigningCommitments,
    ) -> anyhow::Result<()> {
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

        let commitment_count = dbtx
            .find_by_prefix(&FrostSigningCommitmentsPeerPrefix(peer))
            .await
            .count()
            .await;

        tracing::info!(
            target: LOG_MODULE_WALLETV2,
            ?peer,
            commitment_count,
            target = frost_nonce_buffer_target(),
            "Stored FROST signing commitment"
        );

        // Our own commitment has now been finalized — drop it from
        // the in-flight set so the next `consensus_proposal` can
        // freely propose new commitments without the race window.
        if peer == self.our_peer_id {
            self.frost
                .in_flight_commitments
                .lock()
                .expect("in_flight_commitments mutex poisoned")
                .remove(&commitments);
        }

        // A fresh commitment may have unblocked a tx that was
        // waiting on commitment-buffer availability. Retry any
        // pending signings.
        self.try_progress_pending_signings(dbtx).await?;

        Ok(())
    }

    /// Handle a `WalletConsensusItem::FrostSignatureShare` from `peer`:
    /// verify each per-input share against the stored signing packages
    /// and the FROST `pubkey_package`, store under
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
        ensure!(
            matches!(self.cfg.consensus.descriptor, WalletDescriptor::Frost(_)),
            "FrostSignatureShare on non-FROST federation",
        );
        let pubkey_package_base = self
            .cfg
            .consensus
            .frost_pubkey_package
            .as_ref()
            .expect("FROST federation must have a frost_pubkey_package")
            .0
            .clone();
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
            let utxo = &unsigned_tx.spent_tx_outs[input_index];
            let merkle_root = self.tap_leaf_hash(&utxo.tweak).to_byte_array();
            verify_signature_share(
                &pubkey_package_base,
                &utxo.tweak,
                &merkle_root,
                peer,
                &signing_packages[input_index].0,
                share,
            )?;
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
            let pubkey_package = self
                .cfg
                .consensus
                .frost_pubkey_package
                .clone()
                .ok_or_else(|| anyhow!("FROST federation must have a frost_pubkey_package"))?
                .0;

            let mut final_sigs = Vec::with_capacity(unsigned_tx.tx.input.len());
            for (input_index, signing_package) in signing_packages.iter().enumerate() {
                let utxo = &unsigned_tx.spent_tx_outs[input_index];
                let signing_package = &signing_package.0;

                let shares_for_input = shares
                    .iter()
                    .map(|(k, v)| {
                        (
                            peer_id_to_identifier(k.peer_id),
                            v.signature_shares[input_index],
                        )
                    })
                    .collect::<BTreeMap<_, _>>();

                let pubkey_package =
                    apply_utxo_tweak_to_pubkey_package(&pubkey_package, &utxo.tweak);
                let merkle_root = self.tap_leaf_hash(&utxo.tweak).to_byte_array();

                let final_sig = frost_secp256k1_tr::aggregate_with_tweak(
                    signing_package,
                    &shares_for_input,
                    &pubkey_package,
                    Some(&merkle_root),
                )?;

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
            finalize_tx_frost(&mut unsigned, &final_sigs);

            // Capture this guardian's local finalization-latency stat before
            // the cleanup below removes the attempt / advance-vote records and
            // the first-seen timestamp it's derived from.
            self.record_finalization_stat(dbtx, txid).await;

            // All per-attempt state for this tx — across every
            // attempt that ever ran — gets cleaned up here, since
            // shares, packages, and attempt records are all keyed
            // by `(txid, attempt)`.
            dbtx.remove_entry(&UnsignedTxKey(txid)).await;
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
            dbtx.insert_new_entry(&UnconfirmedTxKey(txid), &unsigned)
                .await;
            // Drop in-memory broadcast guards for this tx — no more
            // shares to broadcast and no more votes to file.
            self.frost
                .broadcast_signature_shares
                .lock()
                .expect("broadcast_signature_shares mutex poisoned")
                .retain(|(t, _), _| *t != txid);
            self.frost
                .tx_attempt_first_seen
                .lock()
                .expect("tx_attempt_first_seen mutex poisoned")
                .retain(|(t, _), _| *t != txid);

            if let Err(err) = self.btc_rpc.submit_transaction(unsigned.tx).await {
                tracing::warn!(
                    target: LOG_MODULE_WALLETV2,
                    err = %err.fmt_compact_anyhow(),
                    "Error broadcasting finalized FROST transaction"
                );
            }
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
            self.frost
                .in_flight_advance_votes
                .lock()
                .expect("in_flight_advance_votes mutex poisoned")
                .remove(&(txid, attempt));
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
                    err = %err.fmt_compact_anyhow(),
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
    /// `try_progress_pending_signings`. `kind` is "receive" or "send"
    /// for log clarity.
    pub(crate) async fn start_initial_frost_signing(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        unsigned: &FederationTx,
        txid: Txid,
        kind: &'static str,
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
                err = %err.fmt_compact_anyhow(),
                "Couldn't start initial FROST signing attempt for {kind} tx; will retry when commitments replenish"
            );
        }
    }
}

/// Target number of unused FROST signing nonces each peer keeps on disk.
/// Larger buffers let adaptive ROAST advance through more attempts (and let
/// the commitment-aware signer selection still find a viable session) before
/// the federation runs out of fresh nonces. Each unused commitment is also
/// broadcast as a consensus item, so this also caps the per-peer commitment
/// bytes flowing through `AlephBFT`.
pub(crate) const DEFAULT_FROST_NONCE_BUFFER_TARGET: usize = 64;

/// Target size of the local FROST nonce buffer (see
/// [`spawn_initial_nonce_backfill`]).
/// Reads [`FM_WALLETV2_FROST_NONCE_BUFFER_TARGET_ENV`] once on first use,
/// falling back to [`DEFAULT_FROST_NONCE_BUFFER_TARGET`] when unset or
/// unparsable.
pub(crate) fn frost_nonce_buffer_target() -> usize {
    static TARGET: LazyLock<usize> = LazyLock::new(|| {
        std::env::var(FM_WALLETV2_FROST_NONCE_BUFFER_TARGET_ENV)
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(DEFAULT_FROST_NONCE_BUFFER_TARGET)
    });

    *TARGET
}

/// How often a peer re-broadcasts its FROST signature share (or
/// commitment) when the previous broadcast hasn't yet been delivered
/// through consensus. `AlephBFT` can drop a unit when its broadcast lands
/// close to a session boundary — most likely with larger federations
/// where each peer commands a smaller fraction of the per-round byte
/// budget. Picking a value comparable to the typical `AlephBFT` session
/// duration (~20–30 s) keeps re-broadcasts to ~1 per session per item
/// instead of ~10/sec.
pub(crate) const FROST_REBROADCAST_INTERVAL: std::time::Duration =
    std::time::Duration::from_secs(15);

/// Local wall-clock window each peer waits before broadcasting a
/// `FrostAdvanceVote` for a stuck signing session. Per-peer (not
/// consensus) — peers' clocks may differ, but the consensus is on the
/// *vote count*, not the timing. Held at 30s in every environment
/// (including devimint) so that one-input txs get a fair chance to
/// finish on the original `signing_session` before peers start firing
/// advance votes — premature advance creates a swarm of new attempts,
/// which inflates consensus-item volume and can push `AlephBFT` past its
/// per-instance byte budget at different boundaries on different peers.
pub(crate) fn local_advance_timeout() -> std::time::Duration {
    std::time::Duration::from_secs(30)
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
pub(crate) fn spawn_initial_nonce_backfill(
    db: Database,
    task_group: &TaskGroup,
    key_package: KeyPackage,
) {
    task_group.spawn_cancellable("frost initial nonce backfill", async move {
        let mut dbtx = db.begin_transaction().await;
        let count = dbtx
            .find_by_prefix(&FrostSigningNoncesPrefix)
            .await
            .count()
            .await;
        for _ in 0..frost_nonce_buffer_target().saturating_sub(count) {
            let (nonce, commitment) =
                frost_secp256k1_tr::round1::commit(key_package.signing_share(), &mut OsRng);

            dbtx.insert_new_entry(
                &FrostSigningNoncesKey(FrostSigningCommitments(commitment)),
                &FrostSigningNonces(nonce),
            )
            .await;
        }
        dbtx.commit_tx().await;
    });
}

/// Attach BIP-341 key-path witnesses (one 64-byte FROST/Schnorr signature
/// per input) to `federation_tx`. Default sighash, so the witness for
/// each input is just the 64-byte signature with no sighash-type byte
/// appended.
pub(crate) fn finalize_tx_frost(
    federation_tx: &mut FederationTx,
    signatures: &[frost_secp256k1_tr::Signature],
) {
    assert_eq!(
        federation_tx.spent_tx_outs.len(),
        federation_tx.tx.input.len()
    );
    assert_eq!(signatures.len(), federation_tx.tx.input.len());

    for (index, sig) in signatures.iter().enumerate() {
        let sig_bytes = sig
            .serialize()
            .expect("FROST signature serializes to 64-byte BIP-340 form");
        let mut witness = bitcoin::Witness::new();
        witness.push(&sig_bytes);
        federation_tx.tx.input[index].witness = witness;
    }
}

/// Convert a `PeerId` into a FROST `Identifier`.
///
/// FROST identifiers must be non-zero, so we offset by 1.
pub(crate) fn peer_id_to_identifier(peer_id: PeerId) -> Identifier {
    Identifier::try_from(peer_id.to_usize() as u16 + 1)
        .expect("Could not convert PeerId to Identifier")
}

/// Deterministically pick a `threshold`-sized signing session for `(txid,
/// attempt)`. Walks a shuffle of `all_peers` seeded by `(txid, attempt)`,
/// skipping suspects and peers whose `FrostSigningCommitments` pool is
/// shorter than `required_commitments` (one commitment per input is consumed
/// per session peer). Returns the first `threshold` peers, or `None` if not
/// enough viable non-suspects remain.
///
/// All inputs (commitment counts, suspects) are derived from
/// consensus-replicated DB state, so every peer computes the same answer.
/// Each new `attempt` reseeds the shuffle, and the suspect set shrinks
/// whenever a previously slow honest peer broadcasts a late share — together
/// these guarantee progress without any round-robin fallback.
pub(crate) async fn pick_signing_session(
    dbtx: &mut DatabaseTransaction<'_>,
    all_peers: &[PeerId],
    threshold: usize,
    txid: Txid,
    attempt: u32,
    required_commitments: usize,
    suspects: &BTreeSet<PeerId>,
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

    let session: Vec<PeerId> = shuffled
        .iter()
        .copied()
        .filter(|p| !suspects.contains(p) && viable(p))
        .take(threshold)
        .collect();
    if session.len() == threshold {
        return Some(session);
    }
    None
}

/// Generate FROST key material centrally via a trusted dealer for
/// `peers`. Used by `trusted_dealer_gen` (the test / scripted path
/// that doesn't run a real DKG). Produces:
/// - One `KeyPackage` per peer, keyed by `PeerId`. Each peer receives only
///   their own package.
/// - The aggregated verifying key as an `XOnlyPublicKey` — this is what gets
///   stored as `WalletDescriptor::Frost(internal_key)`.
/// - The `PublicKeyPackage` (aggregate VK + per-peer verifying shares),
///   replicated to every peer for share verification.
///
/// Threshold is `peers.threshold()` (BFT majority). The dealer holds
/// every share momentarily and so must be trusted; real federations
/// should use [`dkg`] instead. Skipped entirely when `peers.len() ==
/// 1` (caller collapses to `WalletDescriptor::SinglePeer`).
pub(crate) fn trusted_setup(
    peers: &[PeerId],
) -> anyhow::Result<(
    BTreeMap<PeerId, KeyPackage>,
    XOnlyPublicKey,
    PublicKeyPackage,
)> {
    let threshold = peers.to_num_peers().threshold() as u16;
    let total_peers = peers.len() as u16;
    let (shares, pubkey_package) = frost::keys::generate_with_dealer(
        total_peers,
        threshold,
        frost::keys::IdentifierList::Default,
        OsRng,
    )?;
    let internal_key = frost_verifying_key_to_xonly(&pubkey_package);
    let key_packages = peers
        .iter()
        .map(|peer| {
            let identifier = peer_id_to_identifier(*peer);
            let share = shares
                .get(&identifier)
                .cloned()
                .expect("No share for identifier");
            let key_package =
                frost::keys::KeyPackage::try_from(share).expect("Could not convert share");
            (*peer, key_package)
        })
        .collect();
    Ok((key_packages, internal_key, pubkey_package))
}

/// Run a 3-round FROST distributed key generation across `peers` and
/// return our local share of the result. Unlike [`trusted_setup`], no
/// single party ever sees every secret share — each peer's signing
/// key is assembled locally from contributions exchanged over the
/// `PeerHandleOps` channel.
///
/// Returns:
/// - Our `KeyPackage` (private — only this peer's signing share + the aggregate
///   VK).
/// - The aggregated verifying key as an `XOnlyPublicKey`, stored as
///   `WalletDescriptor::Frost(internal_key)`. All honest peers compute the same
///   value.
/// - The `PublicKeyPackage` for share verification (replicated).
///
/// Round structure:
/// 1. `part1` — generate our polynomial commitment + secret; broadcast the
///    commitment to all peers via `exchange_encodable`.
/// 2. `part2` — using everyone's commitments, build per-peer shares; send each
///    peer their share privately.
/// 3. `part3` — combine our received shares with our retained secret to produce
///    our final `KeyPackage` and the aggregate `PublicKeyPackage`.
///
/// Skipped entirely when `peers.num_peers().total() == 1` (caller
/// collapses to `WalletDescriptor::SinglePeer`). Failures of any
/// `part*` propagate as `Err` and abort federation setup.
pub(crate) async fn dkg(
    peers: &(dyn PeerHandleOps + Send + Sync),
) -> anyhow::Result<(KeyPackage, XOnlyPublicKey, PublicKeyPackage)> {
    let our_identifier = peer_id_to_identifier(peers.identity());
    let threshold = peers.num_peers().threshold() as u16;
    let total_peers = peers.num_peers().total() as u16;
    let (round1_secret_package, round1_package) =
        frost::keys::dkg::part1(our_identifier, total_peers, threshold, OsRng)?;

    let round1_packages = peers
        .exchange_encodable(FrostPolynomial(round1_package))
        .await?
        .into_iter()
        .filter(|(peer_id, _)| *peer_id != peers.identity())
        .map(|(peer_id, poly)| (peer_id_to_identifier(peer_id), poly.0))
        .collect::<BTreeMap<_, _>>();

    let (round2_secret_package, round2_packages) =
        frost::keys::dkg::part2(round1_secret_package, &round1_packages)?;

    // Round 2 packages are per-recipient secret shares — sending them
    // via the broadcast `exchange_encodable` would let any peer
    // interpolate everyone's polynomial and recover the aggregate
    // signing key. Use the directed primitive so each share goes only
    // to its intended recipient.
    let our_round2_packages = peers
        .num_peers()
        .peer_ids()
        .filter(|peer_id| *peer_id != peers.identity())
        .map(|peer_id| {
            let identifier = peer_id_to_identifier(peer_id);
            let package = round2_packages
                .get(&identifier)
                .expect("No round2 package for identifier")
                .clone();
            (peer_id, FrostPolynomialCommitment(package))
        })
        .collect::<BTreeMap<_, _>>();

    let round2_packages = peers
        .exchange_directed_encodable(our_round2_packages)
        .await?
        .into_iter()
        .map(|(sender, package)| (peer_id_to_identifier(sender), package.0))
        .collect::<BTreeMap<_, _>>();

    let (key_package, pubkey_package) =
        frost::keys::dkg::part3(&round2_secret_package, &round1_packages, &round2_packages)?;
    let xonly = frost_verifying_key_to_xonly(&pubkey_package);

    Ok((key_package, xonly, pubkey_package))
}

/// Apply the per-UTXO additive tweak to a FROST `KeyPackage` homomorphically:
///   `s_i`' = `s_i` + `t`,   `Q_i`' = `Q_i` + `t·G`,   `Q`' = `Q` + `t·G`
///
/// The descriptor's internal key for a UTXO is
/// `tweak_xonly_public_key(internal_key, tweak)`, which assumes Even-Y
/// interpretation of the original internal key — so we normalize
/// to Even-Y before adding the tweak. The BIP-341 tap tweak is applied
/// separately by `round2::sign_with_tweak`.
pub(crate) fn apply_utxo_tweak_to_key_package(
    key_package: &KeyPackage,
    tweak: &sha256::Hash,
) -> KeyPackage {
    let key_package = key_package.clone().into_even_y(None);

    let tweak_scalar =
        Scalar::from_be_bytes(tweak.to_byte_array()).expect("Hash is within field order");

    let sk = secp256k1::SecretKey::from_slice(&key_package.signing_share().serialize())
        .expect("FROST signing share is a valid secret key");
    let tweaked_sk = sk
        .add_tweak(&tweak_scalar)
        .expect("Tweaked signing share is non-zero");
    let tweaked_signing_share = SigningShare::deserialize(&tweaked_sk.secret_bytes())
        .expect("Bytes are a valid signing share");

    let vs_bytes = key_package
        .verifying_share()
        .serialize()
        .expect("FROST verifying share serializes");
    let tweaked_vs_pk = secp256k1::PublicKey::from_slice(&vs_bytes)
        .expect("FROST verifying share is a valid public key")
        .add_exp_tweak(secp256k1::SECP256K1, &tweak_scalar)
        .expect("Tweaked verifying share is non-identity");
    let tweaked_verifying_share = VerifyingShare::deserialize(&tweaked_vs_pk.serialize())
        .expect("Bytes are a valid verifying share");

    let vk_bytes = key_package
        .verifying_key()
        .serialize()
        .expect("FROST verifying key serializes");
    let tweaked_vk_pk = secp256k1::PublicKey::from_slice(&vk_bytes)
        .expect("FROST verifying key is a valid public key")
        .add_exp_tweak(secp256k1::SECP256K1, &tweak_scalar)
        .expect("Tweaked verifying key is non-identity");
    let tweaked_verifying_key = VerifyingKey::deserialize(&tweaked_vk_pk.serialize())
        .expect("Bytes are a valid verifying key");

    KeyPackage::new(
        *key_package.identifier(),
        tweaked_signing_share,
        tweaked_verifying_share,
        tweaked_verifying_key,
        *key_package.min_signers(),
    )
}

/// Apply the per-UTXO additive tweak to a FROST `PublicKeyPackage`
/// homomorphically:   `Q`' = `Q` + `t·G`,   `Q_i`' = `Q_i` + `t·G`
///
/// Mirrors `apply_utxo_tweak_to_key_package` on the public side. The BIP-341
/// tap tweak is applied separately by `aggregate_with_tweak`.
pub(crate) fn apply_utxo_tweak_to_pubkey_package(
    pubkey_package: &PublicKeyPackage,
    tweak: &sha256::Hash,
) -> PublicKeyPackage {
    let pubkey_package = pubkey_package.clone().into_even_y(None);

    let tweak_scalar =
        Scalar::from_be_bytes(tweak.to_byte_array()).expect("Hash is within field order");

    let vk_bytes = pubkey_package
        .verifying_key()
        .serialize()
        .expect("FROST verifying key serializes");
    let tweaked_vk_pk = secp256k1::PublicKey::from_slice(&vk_bytes)
        .expect("FROST verifying key is a valid public key")
        .add_exp_tweak(secp256k1::SECP256K1, &tweak_scalar)
        .expect("Tweaked verifying key is non-identity");
    let tweaked_verifying_key = VerifyingKey::deserialize(&tweaked_vk_pk.serialize())
        .expect("Bytes are a valid verifying key");

    let tweaked_verifying_shares = pubkey_package
        .verifying_shares()
        .iter()
        .map(|(id, vs)| {
            let vs_bytes = vs.serialize().expect("FROST verifying share serializes");
            let tweaked_vs_pk = secp256k1::PublicKey::from_slice(&vs_bytes)
                .expect("FROST verifying share is a valid public key")
                .add_exp_tweak(secp256k1::SECP256K1, &tweak_scalar)
                .expect("Tweaked verifying share is non-identity");
            let tweaked_vs = VerifyingShare::deserialize(&tweaked_vs_pk.serialize())
                .expect("Bytes are a valid verifying share");
            (*id, tweaked_vs)
        })
        .collect();

    PublicKeyPackage::new(
        tweaked_verifying_shares,
        tweaked_verifying_key,
        pubkey_package.min_signers(),
    )
}

/// Verify a single peer's signature share against the FROST `pubkey_package`,
/// applying both the per-UTXO additive tweak and the BIP-341 tap tweak so the
/// verifying-share / verifying-key match what the signer used in
/// `sign_with_tweak`. Returns an error if the share doesn't verify (e.g., a
/// malicious or buggy peer).
pub(crate) fn verify_signature_share(
    pubkey_package: &PublicKeyPackage,
    utxo_tweak: &sha256::Hash,
    merkle_root: &[u8],
    peer_id: PeerId,
    signing_package: &SigningPackage,
    signature_share: &SignatureShare,
) -> anyhow::Result<()> {
    let pubkey_package = apply_utxo_tweak_to_pubkey_package(pubkey_package, utxo_tweak);
    let pubkey_package = pubkey_package.tweak(Some(merkle_root));

    let identifier = peer_id_to_identifier(peer_id);
    let verifying_share = pubkey_package
        .verifying_shares()
        .get(&identifier)
        .ok_or_else(|| anyhow::anyhow!("No FROST verifying share for peer {peer_id}"))?;

    frost_core::verify_signature_share(
        identifier,
        verifying_share,
        signature_share,
        signing_package,
        pubkey_package.verifying_key(),
    )
    .map_err(|e| anyhow::anyhow!("FROST signature share from peer {peer_id} is invalid: {e}"))
}

fn frost_verifying_key_to_xonly(pubkey_package: &PublicKeyPackage) -> XOnlyPublicKey {
    let bytes = pubkey_package
        .verifying_key()
        .serialize()
        .expect("FROST verifying key serializes to compressed secp256k1 bytes");
    let pk = PublicKey::from_slice(&bytes).expect("FROST verifying key is a valid secp256k1 point");
    pk.x_only_public_key().0
}

#[derive(Debug, Clone)]
struct FrostPolynomial(frost::keys::dkg::round1::Package);

impl Encodable for FrostPolynomial {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<(), std::io::Error> {
        let bytes = self.0.serialize().map_err(std::io::Error::other)?;
        bytes.consensus_encode(writer)
    }
}

impl Decodable for FrostPolynomial {
    fn consensus_decode_partial<R: std::io::Read>(
        r: &mut R,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let bytes = Vec::<u8>::consensus_decode_partial(r, modules)?;
        frost::keys::dkg::round1::Package::deserialize(&bytes)
            .map(FrostPolynomial)
            .map_err(DecodeError::from_err)
    }
}

#[derive(Debug, Clone)]
struct FrostPolynomialCommitment(frost_secp256k1_tr::keys::dkg::round2::Package);

impl Encodable for FrostPolynomialCommitment {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<(), std::io::Error> {
        let bytes = self.0.serialize().map_err(std::io::Error::other)?;
        bytes.consensus_encode(writer)
    }
}

impl Decodable for FrostPolynomialCommitment {
    fn consensus_decode_partial<R: std::io::Read>(
        r: &mut R,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let bytes = Vec::<u8>::consensus_decode_partial(r, modules)?;
        frost_secp256k1_tr::keys::dkg::round2::Package::deserialize(&bytes)
            .map(FrostPolynomialCommitment)
            .map_err(DecodeError::from_err)
    }
}

#[derive(Debug, Clone)]
pub struct FrostSigningNonces(pub frost::round1::SigningNonces);

impl Encodable for FrostSigningNonces {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<(), std::io::Error> {
        let bytes = self.0.serialize().map_err(std::io::Error::other)?;
        bytes.consensus_encode(writer)
    }
}

impl Decodable for FrostSigningNonces {
    fn consensus_decode_partial<R: std::io::Read>(
        r: &mut R,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let bytes = Vec::<u8>::consensus_decode_partial(r, modules)?;
        frost_secp256k1_tr::round1::SigningNonces::deserialize(&bytes)
            .map(FrostSigningNonces)
            .map_err(DecodeError::from_err)
    }
}

impl serde::Serialize for FrostSigningNonces {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let bytes = self.0.serialize().map_err(serde::ser::Error::custom)?;
        serializer.serialize_str(&fedimint_core::hex::encode(bytes))
    }
}

/// `Encodable`/`Decodable` wrapper for `SigningPackage`. Cached in the DB at
/// `FrostSigningPackagesKey(txid)` so that any peer (including non-session
/// peers) can verify and aggregate `FrostSignatureShare` consensus items
/// without the package being re-sent over the wire by every signer.
#[derive(Debug, Clone)]
pub struct FrostSigningPackage(pub SigningPackage);

impl Encodable for FrostSigningPackage {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<(), std::io::Error> {
        let bytes = self.0.serialize().map_err(std::io::Error::other)?;
        bytes.consensus_encode(writer)
    }
}

impl Decodable for FrostSigningPackage {
    fn consensus_decode_partial<R: std::io::Read>(
        r: &mut R,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let bytes = Vec::<u8>::consensus_decode_partial(r, modules)?;
        SigningPackage::deserialize(&bytes)
            .map(FrostSigningPackage)
            .map_err(DecodeError::from_err)
    }
}

impl serde::Serialize for FrostSigningPackage {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let bytes = self.0.serialize().map_err(serde::ser::Error::custom)?;
        serializer.serialize_str(&fedimint_core::hex::encode(bytes))
    }
}

#[cfg(test)]
mod tests {
    //! Determinism tests for `pick_signing_session`. Each test asserts a
    //! specific invariant about the function's input/output relationship
    //! over synthetic DB state. Built on `MemDatabase` so they run as
    //! cheap unit tests.
    use std::collections::{BTreeMap, BTreeSet};
    use std::str::FromStr;

    use bitcoin::Txid;
    use fedimint_core::PeerId;
    use fedimint_core::db::mem_impl::MemDatabase;
    use fedimint_core::db::{Database, IDatabaseTransactionOpsCoreTyped, IRawDatabaseExt};
    use fedimint_walletv2_common::taproot::frost::FrostSigningCommitments;
    use frost_secp256k1_tr::keys::{IdentifierList, KeyPackage, SigningShare};
    use frost_secp256k1_tr::round1;
    use rand::rngs::OsRng;

    use super::pick_signing_session;
    use crate::db::FrostSigningCommitmentsKey;

    const N: usize = 7;
    const THRESHOLD: usize = 5;

    /// Generates a one-off `SigningShare` we can repeatedly call
    /// `commit()` on to mint distinct synthetic commitments.
    fn signing_share_for_tests() -> SigningShare {
        let (shares, _pubkey_package) =
            frost_secp256k1_tr::keys::generate_with_dealer(7, 5, IdentifierList::Default, OsRng)
                .expect("trusted dealer key gen");
        let any_share = shares.into_values().next().expect("at least one share");
        let key_package = KeyPackage::try_from(any_share).expect("share -> key_package");
        *key_package.signing_share()
    }

    /// Mints `count` distinct commitments. Values are real
    /// `round1::commit` outputs but their content doesn't matter for
    /// `pick_signing_session` — only uniqueness within the per-peer
    /// prefix scan.
    fn mint_commitments(count: usize) -> Vec<FrostSigningCommitments> {
        let signing_share = signing_share_for_tests();
        let mut rng = rand::rngs::OsRng;
        (0..count)
            .map(|_| {
                let (_nonces, commitments) = round1::commit(&signing_share, &mut rng);
                FrostSigningCommitments(commitments)
            })
            .collect()
    }

    fn peers(n: usize) -> Vec<PeerId> {
        (0..n)
            .map(|i| PeerId::from_str(&i.to_string()).unwrap())
            .collect()
    }

    /// Builds a fresh `Database` and seeds it with the given
    /// commitment-count per peer (peers not in the map get 0).
    async fn db_with_commitments(per_peer: &BTreeMap<PeerId, usize>) -> Database {
        let db = MemDatabase::new().into_database();
        let mut dbtx = db.begin_transaction().await;
        for (&peer_id, &count) in per_peer {
            for c in mint_commitments(count) {
                dbtx.insert_entry(
                    &FrostSigningCommitmentsKey {
                        peer_id,
                        frost_commitments: c,
                    },
                    &(),
                )
                .await;
            }
        }
        dbtx.commit_tx().await;
        db
    }

    fn dummy_txid(seed: u8) -> Txid {
        use bitcoin::hashes::Hash;
        Txid::from_byte_array([seed; 32])
    }

    /// Runs `pick_signing_session` against a freshly opened transaction.
    async fn run_pick(
        db: &Database,
        all_peers: &[PeerId],
        threshold: usize,
        txid: Txid,
        attempt: u32,
        required_commitments: usize,
        suspects: &BTreeSet<PeerId>,
    ) -> Option<Vec<PeerId>> {
        let mut dbtx = db.begin_transaction().await;
        pick_signing_session(
            &mut dbtx.to_ref_nc(),
            all_peers,
            threshold,
            txid,
            attempt,
            required_commitments,
            suspects,
        )
        .await
    }

    /// Asserts that two databases with identical synthetic state produce
    /// identical `signing_session` outputs for the same inputs.
    #[tokio::test]
    async fn pick_deterministic_across_peers() {
        let all_peers = peers(N);
        let counts: BTreeMap<_, _> = all_peers.iter().map(|p| (*p, 8)).collect();

        let db_a = db_with_commitments(&counts).await;
        let db_b = db_with_commitments(&counts).await;

        let txid = dummy_txid(1);
        let suspects = BTreeSet::new();

        let a = run_pick(&db_a, &all_peers, THRESHOLD, txid, 0, 1, &suspects).await;
        let b = run_pick(&db_b, &all_peers, THRESHOLD, txid, 0, 1, &suspects).await;

        assert_eq!(a, b);
        assert_eq!(a.as_ref().map(std::vec::Vec::len), Some(THRESHOLD));
    }

    /// Asserts that `attempt` enters the shuffle seed: same
    /// (state, attempt) yields the same session, different attempt
    /// yields a different shuffled order.
    #[tokio::test]
    async fn attempt_drives_shuffle_seed() {
        let all_peers = peers(N);
        let counts: BTreeMap<_, _> = all_peers.iter().map(|p| (*p, 8)).collect();
        let db = db_with_commitments(&counts).await;
        let txid = dummy_txid(2);
        let suspects = BTreeSet::new();

        let a0 = run_pick(&db, &all_peers, THRESHOLD, txid, 0, 1, &suspects).await;
        let a0_again = run_pick(&db, &all_peers, THRESHOLD, txid, 0, 1, &suspects).await;
        let a1 = run_pick(&db, &all_peers, THRESHOLD, txid, 1, 1, &suspects).await;

        assert_eq!(a0, a0_again);
        let a0 = a0.expect("succeeds with all viable");
        let a1 = a1.expect("succeeds with all viable");
        assert_ne!(a0, a1, "attempt should change shuffled order");
    }

    /// Asserts that peers below `required_commitments` are excluded from
    /// the result.
    #[tokio::test]
    async fn viable_filter_excludes_underbuffered() {
        let all_peers = peers(N);
        let mut counts: BTreeMap<_, _> = all_peers.iter().map(|p| (*p, 4)).collect();
        let starved = PeerId::from_str("6").unwrap();
        counts.insert(starved, 0);

        let db = db_with_commitments(&counts).await;
        let txid = dummy_txid(3);
        let suspects = BTreeSet::new();

        let session = run_pick(&db, &all_peers, THRESHOLD, txid, 0, 2, &suspects)
            .await
            .expect("six viable peers ≥ threshold");
        assert!(!session.contains(&starved));
        assert_eq!(session.len(), THRESHOLD);
    }

    /// Asserts that suspects are skipped when enough non-suspect viable
    /// peers remain.
    #[tokio::test]
    async fn suspects_excluded_from_session() {
        let all_peers = peers(N);
        let counts: BTreeMap<_, _> = all_peers.iter().map(|p| (*p, 4)).collect();
        let db = db_with_commitments(&counts).await;
        let txid = dummy_txid(4);

        let mut suspects = BTreeSet::new();
        suspects.insert(PeerId::from_str("5").unwrap());
        suspects.insert(PeerId::from_str("6").unwrap());

        let session = run_pick(&db, &all_peers, THRESHOLD, txid, 0, 1, &suspects)
            .await
            .expect("5 non-suspect viable = threshold");
        for s in &suspects {
            assert!(!session.contains(s), "must drop suspect {s}");
        }
    }

    /// Asserts that the function returns `None` when fewer than
    /// `threshold` viable peers exist.
    #[tokio::test]
    async fn returns_none_when_not_enough_viable() {
        let all_peers = peers(N);
        let mut counts: BTreeMap<_, _> = all_peers.iter().map(|p| (*p, 0)).collect();
        for i in 0..4 {
            counts.insert(PeerId::from_str(&i.to_string()).unwrap(), 8);
        }
        let db = db_with_commitments(&counts).await;
        let txid = dummy_txid(7);
        let suspects = BTreeSet::new();

        let result = run_pick(&db, &all_peers, THRESHOLD, txid, 0, 2, &suspects).await;
        assert!(result.is_none(), "fewer viable than threshold ⇒ None");
    }

    /// Asserts determinism holds as suspects accumulate across attempts:
    /// two identical-state databases walk identical suspect growth and
    /// agree at every step.
    #[tokio::test]
    async fn determinism_holds_across_growing_suspects() {
        let all_peers = peers(N);
        let counts: BTreeMap<_, _> = all_peers.iter().map(|p| (*p, 8)).collect();
        let txid = dummy_txid(8);

        let db_a = db_with_commitments(&counts).await;
        let db_b = db_with_commitments(&counts).await;

        let mut suspects = BTreeSet::new();
        for i in 0..=4 {
            let a = run_pick(&db_a, &all_peers, THRESHOLD, txid, i, 1, &suspects).await;
            let b = run_pick(&db_b, &all_peers, THRESHOLD, txid, i, 1, &suspects).await;
            assert_eq!(a, b, "attempt {i}: results diverge");
            suspects.insert(PeerId::from_str(&i.to_string()).unwrap());
        }
    }
}
