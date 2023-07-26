use std::cmp::{self, max};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fmt;
use std::ops::Range;

use fedimint_client::sm::{OperationId, State, StateTransition};
use fedimint_client::DynGlobalClientContext;
use fedimint_core::core::LEGACY_HARDCODED_INSTANCE_ID_MINT;
use fedimint_core::epoch::{ConsensusItem, SignedEpochOutcome};
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::{Amount, NumPeers, PeerId, TransactionId};
use fedimint_derive_secret::DerivableSecret;
use fedimint_logging::LOG_CLIENT_RECOVERY_MINT;
use fedimint_mint_common::{MintConsensusItem, MintInput, MintOutput, Nonce};
use futures::StreamExt;
use tbs::{
    combine_valid_shares, verify_blind_share, AggregatePublicKey, BlindedMessage, PublicKeyShare,
};
use threshold_crypto::G1Affine;
use tracing::{debug, error, info, trace, warn};

use super::*;
use crate::db::{NextECashNoteIndexKey, NoteKey};
use crate::output::{MintOutputCommon, MintOutputStatesCreated, NoteIssuanceRequest};
use crate::MintClientContext;

/// Restore will progress in chunks of a fixed epoch count,
/// after each the current state is persisted in the database.
/// Larger chunks introduce less "pausing" processing and snapshoting
/// storage and overhead  but risk loosing more progress each time the
/// client app is closed. Some time based, or even "save on close"
/// scheme would be better, but currently not implemented.
const PROGRESS_SNAPSHOT_EPOCHS: u64 = 500;

#[derive(Debug)]
pub struct EcashRecoveryFinalState {
    /// Nonces that we track that are currently spendable.
    spendable_notes: Vec<(Amount, SpendableNote)>,

    /// Unsigned notes
    unconfirmed_notes: Vec<(OutPoint, MultiNoteIssuanceRequest)>,

    /// Note index to derive next note in a given amount tier
    next_note_idx: Tiered<NoteIndex>,
}

/// Newtype over [`BlindedMessage`] to enable `Ord`
#[derive(
    Debug, Clone, Eq, PartialEq, PartialOrd, Ord, Decodable, Encodable, Serialize, Deserialize,
)]
struct CompressedBlindedMessage(#[serde(with = "serde_big_array::BigArray")] [u8; 48]);

impl From<BlindedMessage> for CompressedBlindedMessage {
    fn from(value: BlindedMessage) -> Self {
        Self(value.0.to_compressed())
    }
}

impl From<CompressedBlindedMessage> for BlindedMessage {
    fn from(value: CompressedBlindedMessage) -> Self {
        BlindedMessage(
            std::convert::Into::<Option<G1Affine>>::into(G1Affine::from_compressed(&value.0))
                .expect("We never produce invalid compressed blinded messages"),
        )
    }
}

/// The state machine used for fast-forwarding backup from point when it was
/// taken to the present time by following epoch history items from the time the
/// snapshot was taken.
///
/// The caller is responsible for creating it, and then feeding it in order all
/// valid consensus items from the epoch history between time taken (or even
/// somewhat before it) and present time.
#[derive(Clone, Eq, PartialEq, Decodable, Encodable, Serialize, Deserialize)]
pub(crate) struct MintRestoreInProgressState {
    start_epoch: u64,
    next_epoch: u64,
    end_epoch: u64,

    /// Nonces that we track that are currently spendable.
    spendable_note_by_nonce: BTreeMap<Nonce, (Amount, SpendableNote)>,

    /// Outputs (by `OutPoint`) we track federation member confirmations for
    /// blind nonces.
    ///
    /// Once we get enough confirmation (valid shares), these become new
    /// spendable notes.
    ///
    /// Note that `NoteIssuanceRequest` is optional, as sometimes we might need
    /// to handle a tx where only some of the blind nonces were in the pool.
    /// A `None` means that this blind nonce/message is there only for
    /// validation purposes, and will actually not create a
    /// `spendable_note_by_nonce`
    #[allow(clippy::type_complexity)]
    pending_outputs: BTreeMap<
        OutPoint,
        (
            TieredMulti<(CompressedBlindedMessage, Option<NoteIssuanceRequest>)>,
            BTreeMap<PeerId, Vec<tbs::BlindedSignatureShare>>,
        ),
    >,

    /// Next nonces that we expect might soon get used.
    /// Once we see them, we move the tracking to `pending_outputs`
    ///
    /// Note: since looking up nonces is going to be the most common operation
    /// the pool is kept shared (so only one lookup is enough), and
    /// replenishment is done each time a note is consumed.
    pending_nonces: BTreeMap<CompressedBlindedMessage, (NoteIssuanceRequest, NoteIndex, Amount)>,

    /// Tail of `pending`. `pending_notes` is filled by generating note with
    /// this index and incrementing it.
    next_pending_note_idx: Tiered<NoteIndex>,

    /// `LastECashNoteIndex` but tracked in flight. Basically max index of any
    /// note that got a partial sig from the federation (initialled from the
    /// backup value). TODO: One could imagine a case where the note was
    /// issued but not get any partial sigs yet. Very unlikely in real life
    /// scenario, but worth considering.
    last_mined_nonce_idx: Tiered<NoteIndex>,

    /// Threshold
    threshold: u64,

    /// Public key shares for each peer
    ///
    /// Used to validate contributed consensus items
    pub_key_shares: BTreeMap<PeerId, Tiered<PublicKeyShare>>,

    /// Aggregate public key for each amount tier
    tbs_pks: Tiered<AggregatePublicKey>,

    /// The number of nonces we look-ahead when looking for mints (per each
    /// amount).
    gap_limit: u64,
}

impl fmt::Debug for MintRestoreInProgressState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!(
            "MintRestoreInProgressState(start: {}, next: {}, end: {}, spendable_notes_by_nonce: {}, pending_outputs: {}, pending_nonces: {})",
            self.start_epoch,
            self.next_epoch,
            self.end_epoch,
            self.spendable_note_by_nonce.len(),
            self.pending_outputs.len(),
            self.pending_nonces.len()
        ))
    }
}

impl MintRestoreInProgressState {
    fn transitions(
        &self,
        operation_id: OperationId,
        context: &MintClientContext,
        global_context: &DynGlobalClientContext,
    ) -> Vec<StateTransition<MintRestoreStateMachine>> {
        let global_context = global_context.clone();
        let global_context_2 = global_context.clone();
        let secret = context.secret.clone();
        let self_clone = self.clone();
        vec![StateTransition::new(
            async move {
                self_clone
                    .make_progress(
                        global_context.api().clone(),
                        global_context.decoders().clone(),
                        global_context.client_config().epoch_pk,
                        secret,
                    )
                    .await
                    .consensus_encode_to_hex()
                    .expect("Serialization here can't fail")
            },
            move |dbtx, new_state_hex, old_state_machine: MintRestoreStateMachine| {
                let new_state = MintRestoreInProgressState::consensus_decode_hex(
                    &new_state_hex,
                    &Default::default(),
                )
                .expect("Deserialization here can't fail");
                let global_context = global_context_2.clone();
                Box::pin(async move {
                    if new_state.is_done() {
                        debug!(
                            target: LOG_CLIENT_RECOVERY_MINT,
                            ?new_state,
                            "Finalizing restore"
                        );
                        let finalized = new_state.finalize();

                        {
                            let mut dbtx = dbtx.module_tx();

                            debug!(
                                target: LOG_CLIENT_RECOVERY_MINT,
                                len = finalized.spendable_notes.len(),
                                "Restoring spendable notes"
                            );
                            for (amount, note) in finalized.spendable_notes {
                                let key = NoteKey {
                                    amount,
                                    nonce: note.note.0,
                                };
                                dbtx.insert_new_entry(&key, &note).await;
                            }
                            for (amount, note_idx) in finalized.next_note_idx.iter() {
                                debug!(
                                    target: LOG_CLIENT_RECOVERY_MINT,
                                    %amount,
                                    %note_idx,
                                    "Restoring NextECashNodeIndex"
                                );
                                dbtx.insert_entry(
                                    &NextECashNoteIndexKey(amount),
                                    &note_idx.as_u64(),
                                )
                                .await;
                            }
                        }

                        debug!(
                            target: LOG_CLIENT_RECOVERY_MINT,
                            len = finalized.unconfirmed_notes.len(),
                            "Restoring unconfigured notes state machines"
                        );

                        for (out_point, note_issuance) in finalized.unconfirmed_notes {
                            global_context
                                .add_state_machine(
                                    dbtx,
                                    MintClientStateMachines::Output(MintOutputStateMachine {
                                        common: MintOutputCommon {
                                            operation_id,
                                            out_point,
                                        },
                                        state: crate::output::MintOutputStates::Created(
                                            MintOutputStatesCreated { note_issuance },
                                        ),
                                    }),
                                )
                                .await
                                .expect("Adding state machine can't fail")
                        }

                        MintRestoreStateMachine {
                            operation_id: old_state_machine.operation_id,
                            state: MintRestoreStates::Success,
                        }
                    } else {
                        debug!(
                            target: LOG_CLIENT_RECOVERY_MINT,
                            "Saving restore progress checkpoint"
                        );
                        MintRestoreStateMachine {
                            operation_id: old_state_machine.operation_id,
                            state: MintRestoreStates::InProgress(new_state),
                        }
                    }
                })
            },
        )]
    }

    async fn make_progress<'a>(
        mut self,
        api: DynGlobalApi,
        decoders: ModuleDecoderRegistry,
        epoch_pk: threshold_crypto::PublicKey,
        secret: DerivableSecret,
    ) -> Self {
        assert_eq!(secret.level(), 2);
        let epoch_range = self.next_epoch
            ..cmp::min(
                self.next_epoch.wrapping_add(PROGRESS_SNAPSHOT_EPOCHS),
                self.end_epoch,
            );
        debug!(
            target: LOG_CLIENT_RECOVERY_MINT,
            ?epoch_range,
            "Processing epochs"
        );
        let mut epoch_stream = Self::fetch_epochs_stream(api, epoch_pk, decoders, epoch_range);
        while let Some((epoch, epoch_history)) = epoch_stream.next().await {
            assert_eq!(epoch_history.outcome.epoch, epoch);
            self.next_epoch = epoch + 1;

            info!(target: LOG_CLIENT_RECOVERY_MINT, epoch, "Processing epoch");
            let mut processed_txs = Default::default();
            for (peer_id, items) in &epoch_history.outcome.items {
                for item in items {
                    self.handle_consensus_item(
                        *peer_id,
                        item,
                        &mut processed_txs,
                        &epoch_history.outcome.rejected_txs,
                        &secret,
                    );
                }
            }
        }
        self
    }

    /// Fetch epochs in a given range and send them over `sender`
    ///
    /// Since WASM's `spawn` does not support join handles, we indicate
    /// errors via `sender` itself.
    ///
    /// TODO: could be internal to recovery_loop?
    fn fetch_epochs_stream<'a>(
        api: DynGlobalApi,
        epoch_pk: threshold_crypto::PublicKey,
        decoders: ModuleDecoderRegistry,
        epoch_range: Range<u64>,
    ) -> impl futures::Stream<Item = (u64, SignedEpochOutcome)> + 'a {
        futures::stream::iter(epoch_range)
            .map(move |epoch| {
                let api = api.clone();
                let decoders = decoders.clone();
                Box::pin(async move {
                    info!(epoch, "Fetching epoch");
                    (
                        epoch,
                        loop {
                            info!(target: LOG_CLIENT_RECOVERY_MINT, epoch, "Awaiting epoch");
                            match api.fetch_epoch_history(epoch, epoch_pk, &decoders).await {
                                Ok(o) => break o,
                                Err(e) => {
                                    info!(e = %e, epoch, "Error trying to fetch epoch history");
                                }
                            }
                        },
                    )
                })
            })
            .buffered(8)
    }
}

impl MintRestoreInProgressState {
    pub fn from_backup(
        current_epoch_count: u64,
        backup: EcashBackup,
        gap_limit: u64,
        tbs_pks: Tiered<AggregatePublicKey>,
        pub_key_shares: BTreeMap<PeerId, Tiered<PublicKeyShare>>,
        secret: &DerivableSecret,
    ) -> Self {
        let amount_tiers: Vec<_> = tbs_pks.tiers().copied().collect();
        let mut s = Self {
            start_epoch: backup.epoch_count,
            next_epoch: backup.epoch_count,
            end_epoch: current_epoch_count,
            spendable_note_by_nonce: backup
                .notes
                .into_iter()
                .map(|(amount, note)| (note.note.0, (amount, note)))
                .collect(),
            pending_outputs: backup
                .pending_notes
                .into_iter()
                .map(|(out_point, issuance_requests)| {
                    (
                        out_point,
                        (
                            issuance_requests
                                .notes
                                .iter_items()
                                .map(|(amount, iss_req)| {
                                    (
                                        amount,
                                        (iss_req.recover_blind_nonce().0.into(), Some(*iss_req)),
                                    )
                                })
                                .collect(),
                            BTreeMap::default(),
                        ),
                    )
                })
                .collect(),
            pending_nonces: BTreeMap::default(),
            next_pending_note_idx: backup.next_note_idx.clone(),
            last_mined_nonce_idx: backup.next_note_idx,
            threshold: pub_key_shares.threshold() as u64,
            gap_limit,
            tbs_pks,
            pub_key_shares,
        };

        for amount in amount_tiers {
            s.fill_initial_pending_nonces(amount, secret);
        }

        s
    }

    /// Fill each tier pool to the gap limit
    fn fill_initial_pending_nonces(&mut self, amount: Amount, secret: &DerivableSecret) {
        info!(%amount, count=self.gap_limit, "Generating initial set of nonces for amount tier");
        for _ in 0..self.gap_limit {
            self.add_next_pending_nonce_in_pending_pool(amount, secret);
        }
    }

    /// Add next nonce from `amount` tier to the `next_pending_note_idx`
    fn add_next_pending_nonce_in_pending_pool(&mut self, amount: Amount, secret: &DerivableSecret) {
        let note_idx_ref = self.next_pending_note_idx.get_mut_or_default(amount);

        let (note_issuance_request, blind_nonce) = NoteIssuanceRequest::new(
            secp256k1::SECP256K1,
            MintClientModule::new_note_secret_static(secret, amount, *note_idx_ref),
        );
        assert!(self
            .pending_nonces
            .insert(
                blind_nonce.0.into(),
                (note_issuance_request, *note_idx_ref, amount)
            )
            .is_none());

        note_idx_ref.advance();
    }

    pub fn handle_input(&mut self, input: &MintInput) {
        // We attempt to delete any nonce we see as spent, simple
        for (_amt, note) in input.0.iter_items() {
            self.spendable_note_by_nonce.remove(&note.0);
        }
    }

    pub fn handle_output(
        &mut self,
        out_point: OutPoint,
        output: &MintOutput,
        secret: &DerivableSecret,
    ) {
        // There is nothing preventing other users from creating valid transactions
        // mining notes to our own blind nonce, possibly even racing with us.
        // Including amount in blind nonce derivation helps us avoid accidentally using
        // a nonce mined for as smaller amount, but it doesn't eliminate completely
        // the possibility that we might use a note mined in a different transaction,
        // that our original one.
        // While it is harmless to us, as such duplicated blind nonces are effective as
        // good the as the original ones (same amount), it breaks the assumption
        // that all our blind nonces in an our output need to be in the pending
        // pool. It forces us to be greedy no matter what and take what we can,
        // and just report anything suspicious.
        //
        // found - all nonces that we found in the pool with the correct amount
        // missing - all the nonces we have not found in the pool, either because they
        // are not ours           or were consumed by a previous transaction
        // using this nonce, or possibly gap           buffer was too small
        // wrong - nonces that were ours but were mined to a wrong
        let (found, missing, wrong) = output.0.iter_items().fold(
            (vec![], vec![], vec![]),
            |(mut found, mut missing, mut wrong), (amount_from_output, nonce)| {
                match self.pending_nonces.get(&nonce.0.into()).cloned() {
                    Some((issuance_request, note_idx, pending_amount)) => {
                        // the moment we see our blind nonce in the epoch history, correctly or
                        // incorrectly used, we know that we must have used
                        // already
                        self.observe_nonce_idx_being_used(pending_amount, note_idx, secret);

                        if pending_amount == amount_from_output {
                            found.push((
                                amount_from_output,
                                (
                                    CompressedBlindedMessage::from(nonce.0),
                                    Some(issuance_request),
                                ),
                            ));
                            (found, missing, wrong)
                        } else {
                            // put it back, incorrect amount
                            self.pending_nonces.insert(
                                nonce.0.into(),
                                (issuance_request, note_idx, pending_amount),
                            );
                            // report problem
                            wrong.push((
                                out_point,
                                nonce.0,
                                pending_amount,
                                amount_from_output,
                                note_idx,
                            ));
                            (found, missing, wrong)
                        }
                    }
                    None => {
                        missing.push((amount_from_output, (nonce.0.into(), None)));
                        (found, missing, wrong)
                    }
                }
            },
        );

        for wrong in &wrong {
            warn!(output = ?out_point,
                 blind_nonce = ?wrong.1,
                 expected_amount = %wrong.2,
                 found_amount = %wrong.3,
                 "Transaction output contains blind nonce that looks like ours but is of the wrong amount. Ignoring.");
            // Any blind nonce mined with a wrong amount means that this
            // transaction can't be ours
        }

        if !wrong.is_empty() {
            return;
        }

        if found.is_empty() {
            // If we found nothing, this is not our output
            return;
        }

        for &(_amount, (ref nonce, _)) in &missing {
            warn!(output = ?out_point,
                 nonce = ?nonce,
                 "Missing nonce in pending pool for a transaction with other valid nonces that belong to us. This indicate an issue.");
        }

        // ok, now that we know we track this output as ours and use the nonces we've
        // found delete them from the pool and replace them
        for &(_amount, (ref nonce, _)) in &found {
            assert!(self.pending_nonces.remove(&nonce.clone()).is_some());
        }

        self.pending_outputs.insert(
            out_point,
            (
                TieredMulti::from_iter(found.into_iter().chain(missing.into_iter())),
                BTreeMap::new(),
            ),
        );
    }

    /// React to a valid pending nonce being tracked being used in the epoch
    /// history
    ///
    /// (Possibly) increment the `self.last_mined_nonce_idx`, then replenish the
    /// pending pool to always maintain at least `gap_limit` of pending
    /// nonces in each amount tier.
    fn observe_nonce_idx_being_used(
        &mut self,
        amount: Amount,
        note_idx: NoteIndex,
        secret: &DerivableSecret,
    ) {
        *self.last_mined_nonce_idx.entry(amount).or_default() = max(
            self.last_mined_nonce_idx
                .get(amount)
                .copied()
                .unwrap_or_default(),
            note_idx,
        );

        while self.next_pending_note_idx.get_mut_or_default(amount).0
            < self.gap_limit
                + self
                    .last_mined_nonce_idx
                    .get(amount)
                    .expect("must be there already")
                    .0
        {
            self.add_next_pending_nonce_in_pending_pool(amount, secret);
        }
    }

    pub fn handle_output_confirmation(&mut self, peer_id: PeerId, sigs: &MintConsensusItem) {
        let enough_shares = if let Some((output_data, peer_shares)) =
            self.pending_outputs.get_mut(&sigs.out_point)
        {
            if !sigs.signatures.0.structural_eq(output_data) {
                warn!(
                    peer = %peer_id,
                    "Peer proposed a sig share of wrong structure (different than out_point)",
                );
                return;
            }

            for ((share_amt, share_sig), (output_item_amt, output_data_item)) in
                sigs.signatures.0.iter_items().zip(output_data.iter_items())
            {
                // Guaranteed by the structural_eq check above
                assert_eq!(share_amt, output_item_amt);

                let amount_key = match self.pub_key_shares[&peer_id].tier(&share_amt) {
                    Ok(key) => key,
                    Err(_) => {
                        error!(
                            ?peer_id,
                            amount = ?share_amt,
                            "Missing public key for the amount. This should not happen."
                        );
                        return;
                    }
                };

                if !verify_blind_share(output_data_item.0.clone().into(), share_sig.1, *amount_key)
                {
                    warn!(?peer_id, "Ignoring invalid contribution share from peer");
                    return;
                }
            }

            if let Some(_prev) = peer_shares.insert(
                peer_id,
                // We compact the shares to a `Vec<BlindedSignatureShare>` like
                // we eventually want in the consensus itself: https://github.com/fedimint/fedimint/issues/1053#issue-1477111966
                sigs.signatures
                    .0
                    .iter_items()
                    .map(|(_, (_, sig_share))| *sig_share)
                    .collect(),
            ) {
                warn!(
                    out_point = %sigs.out_point,
                    ?peer_id,
                    "Duplicate signature share for out_point",
                );
            }

            self.threshold <= peer_shares.len() as u64
        } else {
            false
        };

        if enough_shares {
            let (output_data, sig_shares) = self
                .pending_outputs
                .remove(&sigs.out_point)
                .expect("must be in the map already");

            for (item_i, (item_amt, item)) in output_data.iter_items().enumerate() {
                let iss_request = if let Some(iss_request) = item.1 {
                    iss_request
                } else {
                    // Items without issuance request are ones we don't consider ours
                    // for some reason, so there's no point combining sigs for them.
                    continue;
                };

                let sig = combine_valid_shares(
                    sig_shares
                        .iter()
                        .map(|(peer, shares)| (peer.to_usize(), shares[item_i])),
                    self.threshold as usize,
                );

                let note = iss_request
                    .finalize(
                        sig,
                        *self
                            .tbs_pks
                            .tier(&item_amt)
                            .expect("must have keys for all amounts here"),
                    )
                    .expect("We can assume all data valid at this point");

                self.spendable_note_by_nonce
                    .insert(iss_request.nonce(), (item_amt, note));
            }
        }
    }

    pub fn is_done(&self) -> bool {
        self.next_epoch == self.end_epoch
    }

    pub(crate) fn handle_consensus_item(
        &mut self,
        peer_id: PeerId,
        item: &ConsensusItem,
        processed_txs: &mut HashSet<TransactionId>,
        rejected_txs: &BTreeSet<TransactionId>,
        secret: &DerivableSecret,
    ) {
        trace!(
            target: LOG_CLIENT_RECOVERY_MINT,
            ?item,
            "found consensus item"
        );
        // assert_eq!(epoch, self.next_epoch);
        match item {
            ConsensusItem::Transaction(tx) => {
                let txid = tx.tx_hash();

                trace!(
                    target: LOG_CLIENT_RECOVERY_MINT,
                    tx_hash = %tx.tx_hash(),
                    "found transaction"
                );

                if rejected_txs.contains(&txid) {
                    debug!(
                        target: LOG_CLIENT_RECOVERY_MINT,
                        tx_hash = %tx.tx_hash(),
                        "transaction was rejected"
                    );
                    // Do not process invalid transactions.
                    // Consensus history contains all data proposed by each peer, even invalid (e.g.
                    // due to double spent) transactions. Precisely to save
                    // downstream users from having to run the consensus themselves,
                    // each epoch contains a list of transactions  that turned out to be invalid.
                    return;
                }

                if !processed_txs.insert(txid) {
                    // Just like server side consensus, do not attempt to process the same
                    // transaction twice.
                    debug!(
                        target: LOG_CLIENT_RECOVERY_MINT,
                        tx_hash = %tx.tx_hash(),
                        "transaction was already processed"
                    );
                    return;
                }

                debug!(
                    target: LOG_CLIENT_RECOVERY_MINT,
                    tx_hash = %tx.tx_hash(),
                    input_num = tx.inputs.len(),
                    output_num = tx.outputs.len(),
                    "processing transaction"
                );

                for (idx, input) in tx.inputs.iter().enumerate() {
                    debug!(
                        target: LOG_CLIENT_RECOVERY_MINT,
                        tx_hash = %tx.tx_hash(),
                        idx,
                        module_id = input.module_instance_id(),
                        "found transaction input"
                    );
                    if input.module_instance_id() == LEGACY_HARDCODED_INSTANCE_ID_MINT {
                        let input = input
                            .as_any()
                            .downcast_ref::<MintInput>()
                            .expect("mint key just checked");

                        self.handle_input(input);
                    }
                }

                for (out_idx, output) in tx.outputs.iter().enumerate() {
                    debug!(
                        target: LOG_CLIENT_RECOVERY_MINT,
                        tx_hash = %tx.tx_hash(),
                        idx = out_idx,
                        module_id = output.module_instance_id(),
                        "found transaction output"
                    );
                    if output.module_instance_id() == LEGACY_HARDCODED_INSTANCE_ID_MINT {
                        let output = output
                            .as_any()
                            .downcast_ref::<MintOutput>()
                            .expect("mint key just checked");

                        self.handle_output(
                            OutPoint {
                                txid,
                                out_idx: out_idx as u64,
                            },
                            output,
                            secret,
                        );
                    }
                }
            }
            ConsensusItem::Module(module_item) => {
                debug!(
                    target: LOG_CLIENT_RECOVERY_MINT,
                    module_id = module_item.module_instance_id(),
                    "found module consensus item"
                );
                if module_item.module_instance_id() == LEGACY_HARDCODED_INSTANCE_ID_MINT {
                    let mint_item = module_item
                        .as_any()
                        .downcast_ref::<MintConsensusItem>()
                        .expect("mint key just checked");

                    debug!(
                        target: LOG_CLIENT_RECOVERY_MINT,
                        module_id = module_item.module_instance_id(),
                        out_point = %mint_item.out_point,
                        "processing mint consensus item"
                    );
                    self.handle_output_confirmation(peer_id, mint_item);
                }
            }
            _ => {}
        }
    }

    fn finalize(self) -> EcashRecoveryFinalState {
        EcashRecoveryFinalState {
            spendable_notes: self
                .spendable_note_by_nonce
                .into_iter()
                .map(|(_nonce, (amount, snote))| (amount, snote))
                .collect(),
            unconfirmed_notes: self
                .pending_outputs
                .into_iter()
                .map(|(out_point, data)| {
                    (
                        out_point,
                        MultiNoteIssuanceRequest {
                            notes: TieredMulti::from_iter(data.0.into_iter_items().filter_map(
                                |(amount, (_bn, opt_note_iss_req))| {
                                    opt_note_iss_req.map(|iss_req| (amount, iss_req))
                                },
                            )),
                        },
                    )
                })
                .collect(),
            // next note idx is the last one detected as used + 1
            next_note_idx: Tiered::from_iter(
                self.last_mined_nonce_idx
                    .iter()
                    .map(|(amount, value)| (amount, value.next())),
            ),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub(crate) struct MintRestoreFailedState {
    pub reason: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub struct MintRestoreStateMachine {
    pub(crate) operation_id: OperationId,
    pub(crate) state: MintRestoreStates,
}

impl State for MintRestoreStateMachine {
    type ModuleContext = MintClientContext;
    type GlobalContext = DynGlobalClientContext;

    fn transitions(
        &self,
        context: &Self::ModuleContext,
        global_context: &Self::GlobalContext,
    ) -> Vec<StateTransition<Self>> {
        match &self.state {
            MintRestoreStates::InProgress(state) => {
                state.transitions(self.operation_id, context, global_context)
            }
            MintRestoreStates::Failed(_) => vec![],
            MintRestoreStates::Success => vec![],
        }
    }

    fn operation_id(&self) -> OperationId {
        self.operation_id
    }
}

#[aquamarine::aquamarine]
/// State machine managing e-cash that has been taken out of the wallet for
/// out-of-band transmission.
///
/// ```mermaid
/// graph LR
///     Created -- User triggered refund --> RefundU["User Refund"]
///     Created -- Timeout triggered refund --> RefundT["Timeout Refund"]
/// ```
#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub(crate) enum MintRestoreStates {
    /// The restore has been started and is processing
    InProgress(MintRestoreInProgressState),
    /// Done
    Success,
    /// Something went wrong, and restore failed
    Failed(MintRestoreFailedState),
}

#[cfg(test)]
mod tests;
