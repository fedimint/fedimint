use std::cmp::{self, max};
use std::collections::BTreeMap;
use std::fmt;

use fedimint_core::core::LEGACY_HARDCODED_INSTANCE_ID_MINT;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::epoch::ConsensusItem;
use fedimint_core::session_outcome::SessionOutcome;
use fedimint_core::transaction::Transaction;
use fedimint_core::{Amount, NumPeers, OutPoint, PeerId, Tiered, TieredMulti};
use fedimint_derive_secret::DerivableSecret;
use fedimint_logging::LOG_CLIENT_RECOVERY_MINT;
use fedimint_mint_common::{MintInput, MintOutput, Nonce};
use futures::{Stream, StreamExt as _};
use serde::{Deserialize, Serialize};
use tbs::{AggregatePublicKey, BlindedMessage, PublicKeyShare};
use threshold_crypto::G1Affine;
use tracing::{debug, info, trace, warn};

use crate::backup::EcashBackupV0;
use crate::output::NoteIssuanceRequest;
use crate::{MintClientModule, NoteIndex, SpendableNote};

#[derive(Debug, Clone)]
pub struct EcashRecoveryFinalState {
    pub spendable_notes: TieredMulti<SpendableNote>,
    /// Unsigned notes
    pub unconfirmed_notes: Vec<(OutPoint, Amount, NoteIssuanceRequest)>,
    /// Note index to derive next note in a given amount tier
    pub next_note_idx: Tiered<NoteIndex>,
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
pub struct MintRecoveryState {
    pub start_epoch: u64,
    pub next_epoch: u64,
    pub end_epoch: u64,
    spendable_notes: BTreeMap<Nonce, (Amount, SpendableNote)>,
    /// Nonces that we track that are currently spendable.
    pending_outputs: BTreeMap<Nonce, (OutPoint, Amount, NoteIssuanceRequest)>,
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

impl fmt::Debug for MintRecoveryState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!(
            "MintRestoreInProgressState(start: {}, next: {}, end: {}, pending_outputs: {}, pending_nonces: {})",
            self.start_epoch,
            self.next_epoch,
            self.end_epoch,
            self.pending_outputs.len(),
            self.pending_nonces.len()
        ))
    }
}

impl MintRecoveryState {
    pub async fn make_progress<'a>(
        mut self,
        secret: DerivableSecret,
        block_stream: &mut (impl Stream<Item = (u64, SessionOutcome)> + Unpin),
    ) -> Self {
        /// the amount of blocks after which we save progress in the database
        /// (return from this function)
        const PROGRESS_SNAPSHOT_BLOCKS: u64 = 10;
        assert_eq!(secret.level(), 2);

        let block_range = self.next_epoch
            ..cmp::min(
                self.next_epoch.wrapping_add(PROGRESS_SNAPSHOT_BLOCKS),
                self.end_epoch,
            );

        debug!(
            target: LOG_CLIENT_RECOVERY_MINT,
            ?block_range,
            "Processing blocks"
        );

        for _ in block_range {
            let Some((block_idx, block)) = block_stream.next().await else {
                break;
            };

            assert_eq!(self.next_epoch, block_idx);
            for accepted_item in block.items {
                if let ConsensusItem::Transaction(transaction) = accepted_item.item {
                    self.handle_transaction(&transaction, &secret);
                }
            }

            self.next_epoch += 1;
        }
        self
    }
}

impl MintRecoveryState {
    pub fn from_backup(
        current_epoch_count: u64,
        backup: EcashBackupV0,
        gap_limit: u64,
        tbs_pks: Tiered<AggregatePublicKey>,
        pub_key_shares: BTreeMap<PeerId, Tiered<PublicKeyShare>>,
        secret: &DerivableSecret,
    ) -> Self {
        let amount_tiers: Vec<_> = tbs_pks.tiers().copied().collect();
        let mut s = Self {
            start_epoch: backup.session_count,
            next_epoch: backup.session_count,
            end_epoch: current_epoch_count + 1,
            spendable_notes: backup
                .spendable_notes
                .into_iter_items()
                .map(|(amount, note)| (note.nonce(), (amount, note)))
                .collect(),
            pending_outputs: backup
                .pending_notes
                .into_iter()
                .map(|(outpoint, amount, issuance_request)| {
                    (
                        issuance_request.nonce(),
                        (outpoint, amount, issuance_request),
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
        match input {
            MintInput::V0(input) => {
                // We attempt to delete any nonce we see as spent, simple
                self.pending_outputs.remove(&input.note.nonce);
                self.spendable_notes.remove(&input.note.nonce);
            }
            MintInput::Default { variant, .. } => {
                trace!("Ignoring future mint input variant {variant}");
            }
        }
    }

    pub fn handle_output(
        &mut self,
        out_point: OutPoint,
        output: &MintOutput,
        secret: &DerivableSecret,
    ) {
        let output = match output {
            MintOutput::V0(output) => output,
            MintOutput::Default { variant, .. } => {
                trace!("Ignoring future mint output variant {variant}");
                return;
            }
        };

        // There is nothing preventing other users from creating valid
        // transactions mining notes to our own blind nonce, possibly
        // even racing with us. Including amount in blind nonce
        // derivation helps us avoid accidentally using a nonce mined
        // for as smaller amount, but it doesn't eliminate completely
        // the possibility that we might use a note mined in a different
        // transaction, that our original one.
        // While it is harmless to us, as such duplicated blind nonces are
        // effective as good the as the original ones (same amount), it
        // breaks the assumption that all our blind nonces in an our
        // output need to be in the pending pool. It forces us to be
        // greedy no matter what and take what we can, and just report
        // anything suspicious.

        if let Some((issuance_request, note_idx, pending_amount)) = self
            .pending_nonces
            .get(&output.blind_nonce.0.into())
            .cloned()
        {
            // the moment we see our blind nonce in the epoch history, correctly or
            // incorrectly used, we know that we must have used
            // already
            self.observe_nonce_idx_being_used(pending_amount, note_idx, secret);

            if pending_amount == output.amount {
                assert!(self
                    .pending_nonces
                    .remove(&output.blind_nonce.0.into())
                    .is_some());

                self.pending_outputs.insert(
                    issuance_request.nonce(),
                    (out_point, output.amount, issuance_request),
                );
            } else {
                // put it back, incorrect amount
                self.pending_nonces.insert(
                    output.blind_nonce.0.into(),
                    (issuance_request, note_idx, pending_amount),
                );

                warn!(
                    output = ?out_point,
                    blind_nonce = ?output.blind_nonce.0,
                    expected_amount = %pending_amount,
                    found_amount = %output.amount,
                    "Transaction output contains blind nonce that looks like ours but is of the wrong amount. Ignoring."
                );
            }
        }
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

    pub fn is_done(&self) -> bool {
        self.next_epoch == self.end_epoch
    }

    pub(crate) fn handle_transaction(
        &mut self,
        transaction: &Transaction,
        secret: &DerivableSecret,
    ) {
        trace!(
            target: LOG_CLIENT_RECOVERY_MINT,
            ?transaction,
            "found consensus item"
        );

        trace!(
            target: LOG_CLIENT_RECOVERY_MINT,
            tx_hash = %transaction.tx_hash(),
            "found transaction"
        );

        debug!(
            target: LOG_CLIENT_RECOVERY_MINT,
            tx_hash = %transaction.tx_hash(),
            input_num = transaction.inputs.len(),
            output_num = transaction.outputs.len(),
            "processing transaction"
        );

        for (idx, input) in transaction.inputs.iter().enumerate() {
            debug!(
                target: LOG_CLIENT_RECOVERY_MINT,
                tx_hash = %transaction.tx_hash(),
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

        for (out_idx, output) in transaction.outputs.iter().enumerate() {
            debug!(
                target: LOG_CLIENT_RECOVERY_MINT,
                tx_hash = %transaction.tx_hash(),
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
                        txid: transaction.tx_hash(),
                        out_idx: out_idx as u64,
                    },
                    output,
                    secret,
                );
            }
        }
    }

    pub fn finalize(self) -> EcashRecoveryFinalState {
        EcashRecoveryFinalState {
            spendable_notes: self.spendable_notes.into_values().collect(),
            unconfirmed_notes: self.pending_outputs.into_values().collect(),
            // next note idx is the last one detected as used + 1
            next_note_idx: Tiered::from_iter(
                self.last_mined_nonce_idx
                    .iter()
                    .map(|(amount, value)| (amount, value.next())),
            ),
        }
    }
}
