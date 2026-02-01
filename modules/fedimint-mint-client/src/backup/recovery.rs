use std::cmp::max;
use std::collections::BTreeMap;
use std::fmt;
use std::ops::Add;

use fedimint_client_module::module::init::ClientModuleRecoverArgs;
use fedimint_client_module::module::init::recovery::{
    RecoveryFromHistory, RecoveryFromHistoryCommon,
};
use fedimint_client_module::module::{ClientContext, OutPointRange};
use fedimint_core::bitcoin::hashes::hash160;
use fedimint_core::core::OperationId;
use fedimint_core::db::{DatabaseTransaction, IDatabaseTransactionOpsCoreTyped as _};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::secp256k1::SECP256K1;
use fedimint_core::{
    Amount, NumPeersExt, OutPoint, PeerId, Tiered, TieredMulti, apply, async_trait_maybe_send,
};
use fedimint_derive_secret::DerivableSecret;
use fedimint_logging::{LOG_CLIENT_MODULE_MINT, LOG_CLIENT_RECOVERY, LOG_CLIENT_RECOVERY_MINT};
use fedimint_mint_common::{MintInput, MintOutput, Nonce};
use serde::{Deserialize, Serialize};
use tbs::{AggregatePublicKey, BlindedMessage, PublicKeyShare};
use threshold_crypto::G1Affine;
use tracing::{debug, info, trace, warn};

use super::EcashBackup;
use crate::backup::EcashBackupV0;
use crate::client_db::{
    NextECashNoteIndexKey, NoteKey, RecoveryFinalizedKey, RecoveryStateKey, ReusedNoteIndices,
};
use crate::event::NoteCreated;
use crate::output::{
    MintOutputCommon, MintOutputStateMachine, MintOutputStatesCreated, NoteIssuanceRequest,
};
use crate::{MintClientInit, MintClientModule, MintClientStateMachines, NoteIndex, SpendableNote};

#[derive(Clone, Debug)]
pub struct MintRecovery {
    state: MintRecoveryStateV2,
    secret: DerivableSecret,
    client_ctx: ClientContext<MintClientModule>,
}

#[apply(async_trait_maybe_send!)]
impl RecoveryFromHistory for MintRecovery {
    type Init = MintClientInit;

    async fn new(
        _init: &Self::Init,
        args: &ClientModuleRecoverArgs<Self::Init>,
        snapshot: Option<&EcashBackup>,
    ) -> anyhow::Result<(Self, u64)> {
        let snapshot_v0 = match snapshot {
            Some(EcashBackup::V0(snapshot_v0)) => Some(snapshot_v0),
            Some(EcashBackup::Default { variant, .. }) => {
                warn!(%variant, "Unsupported backup variant. Ignoring mint backup.");
                None
            }
            None => None,
        };

        let config = args.cfg();

        let secret = args.module_root_secret().clone();
        let (snapshot, starting_session) = if let Some(snapshot) = snapshot_v0 {
            (snapshot.clone(), snapshot.session_count)
        } else {
            (EcashBackupV0::new_empty(), 0)
        };

        Ok((
            MintRecovery {
                state: MintRecoveryStateV2::from_backup(
                    snapshot,
                    100,
                    config.tbs_pks.clone(),
                    config.peer_tbs_pks.clone(),
                    &secret,
                ),
                secret,
                client_ctx: args.context(),
            },
            starting_session,
        ))
    }

    async fn load_dbtx(
        _init: &Self::Init,
        dbtx: &mut DatabaseTransaction<'_>,
        args: &ClientModuleRecoverArgs<Self::Init>,
    ) -> anyhow::Result<Option<(Self, RecoveryFromHistoryCommon)>> {
        dbtx.ensure_isolated()
            .expect("Must be in prefixed database");
        Ok(dbtx
            .get_value(&RecoveryStateKey)
            .await
            .and_then(|(state, common)| {
                if let MintRecoveryState::V2(state) = state {
                    Some((state, common))
                } else {
                    warn!(target: LOG_CLIENT_RECOVERY, "Found unknown version recovery state. Ignoring");
                    None
                }
            })
            .map(|(state, common)| {
                (
                    MintRecovery {
                        state,
                        secret: args.module_root_secret().clone(),
                        client_ctx: args.context(),
                    },
                    common,
                )
            }))
    }

    async fn store_dbtx(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        common: &RecoveryFromHistoryCommon,
    ) {
        dbtx.ensure_isolated()
            .expect("Must be in prefixed database");
        dbtx.insert_entry(
            &RecoveryStateKey,
            &(MintRecoveryState::V2(self.state.clone()), common.clone()),
        )
        .await;
    }

    async fn delete_dbtx(&self, dbtx: &mut DatabaseTransaction<'_>) {
        dbtx.remove_entry(&RecoveryStateKey).await;
    }

    async fn load_finalized(dbtx: &mut DatabaseTransaction<'_>) -> Option<bool> {
        dbtx.get_value(&RecoveryFinalizedKey).await
    }

    async fn store_finalized(dbtx: &mut DatabaseTransaction<'_>, state: bool) {
        dbtx.insert_entry(&RecoveryFinalizedKey, &state).await;
    }

    async fn handle_input(
        &mut self,
        _client_ctx: &ClientContext<MintClientModule>,
        _idx: usize,
        input: &MintInput,
        _session_idx: u64,
    ) -> anyhow::Result<()> {
        self.state.handle_input(input);
        Ok(())
    }

    async fn handle_output(
        &mut self,
        _client_ctx: &ClientContext<MintClientModule>,
        out_point: OutPoint,
        output: &MintOutput,
        _session_idx: u64,
    ) -> anyhow::Result<()> {
        self.state.handle_output(out_point, output, &self.secret);
        Ok(())
    }

    /// Handle session outcome, adjusting the current state
    async fn finalize_dbtx(&self, dbtx: &mut DatabaseTransaction<'_>) -> anyhow::Result<()> {
        let finalized = self.state.clone().finalize();

        let restored_amount = finalized
            .unconfirmed_notes
            .iter()
            .map(|entry| entry.1)
            .sum::<Amount>()
            + finalized.spendable_notes.total_amount();

        info!(
            amount = %restored_amount,
            burned_total = %finalized.burned_total,
            "Finalizing mint recovery"
        );

        dbtx.insert_new_entry(&ReusedNoteIndices, &finalized.reused_note_indices)
            .await;
        debug!(
            target: LOG_CLIENT_RECOVERY_MINT,
            len = finalized.spendable_notes.count_items(),
            "Restoring spendable notes"
        );
        for (amount, note) in finalized.spendable_notes.into_iter_items() {
            let key = NoteKey {
                amount,
                nonce: note.nonce(),
            };
            debug!(target: LOG_CLIENT_MODULE_MINT, %amount, %note, "Restoring note");
            self.client_ctx
                .log_event(
                    dbtx,
                    NoteCreated {
                        nonce: note.nonce(),
                    },
                )
                .await;
            dbtx.insert_new_entry(&key, &note.to_undecoded()).await;
        }

        for (amount, note_idx) in finalized.next_note_idx.iter() {
            debug!(
                target: LOG_CLIENT_RECOVERY_MINT,
                %amount,
                %note_idx,
                "Restoring NextECashNodeIndex"
            );
            dbtx.insert_entry(&NextECashNoteIndexKey(amount), &note_idx.as_u64())
                .await;
        }

        debug!(
            target: LOG_CLIENT_RECOVERY_MINT,
            len = finalized.unconfirmed_notes.len(),
            "Restoring unconfirmed notes state machines"
        );

        for (out_point, amount, issuance_request) in finalized.unconfirmed_notes {
            self.client_ctx
                .add_state_machines_dbtx(
                    dbtx,
                    self.client_ctx
                        .map_dyn(vec![MintClientStateMachines::Output(
                            MintOutputStateMachine {
                                common: MintOutputCommon {
                                    operation_id: OperationId::new_random(),
                                    out_point_range: OutPointRange::new_single(
                                        out_point.txid,
                                        out_point.out_idx,
                                    )
                                    .expect("Can't overflow"),
                                },
                                state: crate::output::MintOutputStates::Created(
                                    MintOutputStatesCreated {
                                        amount,
                                        issuance_request,
                                    },
                                ),
                            },
                        )])
                        .collect(),
                )
                .await?;
        }

        debug!(
            target: LOG_CLIENT_RECOVERY_MINT,
            "Mint module recovery finalized"
        );

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct EcashRecoveryFinalState {
    pub spendable_notes: TieredMulti<SpendableNote>,
    /// Unsigned notes
    pub unconfirmed_notes: Vec<(OutPoint, Amount, NoteIssuanceRequest)>,
    /// Note index to derive next note in a given amount tier
    pub next_note_idx: Tiered<NoteIndex>,
    /// Total burned amount
    pub burned_total: Amount,
    /// Note indices that were reused.
    pub reused_note_indices: Vec<(Amount, NoteIndex)>,
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

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Decodable, Encodable)]
pub enum MintRecoveryState {
    #[encodable(index = 2)]
    V2(MintRecoveryStateV2),
    // index 0 has incompatible db encoding, index 1 was skipped to match with V2
    #[encodable_default]
    Default { variant: u64, bytes: Vec<u8> },
}

/// The state machine used for fast-forwarding backup from point when it was
/// taken to the present time by following epoch history items from the time the
/// snapshot was taken.
///
/// The caller is responsible for creating it, and then feeding it in order all
/// valid consensus items from the epoch history between time taken (or even
/// somewhat before it) and present time.
#[derive(Clone, Eq, PartialEq, Decodable, Encodable, Serialize, Deserialize)]
pub struct MintRecoveryStateV2 {
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
    /// Nonces that we have already used. Used for detecting double-used nonces
    /// (accidentally burning funds).
    used_nonces: BTreeMap<CompressedBlindedMessage, (NoteIssuanceRequest, NoteIndex, Amount)>,
    /// Note indices that were reused.
    reused_note_indices: Vec<(Amount, NoteIndex)>,
    /// Total amount probably burned due to re-using nonces
    burned_total: Amount,
    /// Tail of `pending`. `pending_notes` is filled by generating note with
    /// this index and incrementing it.
    next_pending_note_idx: Tiered<NoteIndex>,
    /// `LastECashNoteIndex` but tracked in flight. Basically max index of any
    /// note that got a partial sig from the federation (initialled from the
    /// backup value). TODO: One could imagine a case where the note was
    /// issued but not get any partial sigs yet. Very unlikely in real life
    /// scenario, but worth considering.
    last_used_nonce_idx: Tiered<NoteIndex>,
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

impl fmt::Debug for MintRecoveryStateV2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!(
            "MintRestoreInProgressState(pending_outputs: {}, pending_nonces: {}, used_nonces: {}, burned_total: {})",
            self.pending_outputs.len(),
            self.pending_nonces.len(),
            self.used_nonces.len(),
            self.burned_total,
        ))
    }
}

impl MintRecoveryStateV2 {
    pub fn from_backup(
        backup: EcashBackupV0,
        gap_limit: u64,
        tbs_pks: Tiered<AggregatePublicKey>,
        pub_key_shares: BTreeMap<PeerId, Tiered<PublicKeyShare>>,
        secret: &DerivableSecret,
    ) -> Self {
        let amount_tiers: Vec<_> = tbs_pks.tiers().copied().collect();
        let mut s = Self {
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
            reused_note_indices: Vec::new(),
            pending_nonces: BTreeMap::default(),
            used_nonces: BTreeMap::default(),
            burned_total: Amount::ZERO,
            next_pending_note_idx: backup.next_note_idx.clone(),
            last_used_nonce_idx: backup
                .next_note_idx
                .into_iter()
                .filter_map(|(a, idx)| idx.prev().map(|idx| (a, idx)))
                .collect(),
            threshold: pub_key_shares.to_num_peers().threshold() as u64,
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
        for _ in 0..self.gap_limit {
            self.add_next_pending_nonce_in_pending_pool(amount, secret);
        }
    }

    /// Add next nonce from `amount` tier to the `next_pending_note_idx`
    fn add_next_pending_nonce_in_pending_pool(&mut self, amount: Amount, secret: &DerivableSecret) {
        let note_idx_ref = self.next_pending_note_idx.get_mut_or_default(amount);

        let (note_issuance_request, blind_nonce) = NoteIssuanceRequest::new(
            fedimint_core::secp256k1::SECP256K1,
            &MintClientModule::new_note_secret_static(secret, amount, *note_idx_ref),
        );
        assert!(
            self.pending_nonces
                .insert(
                    blind_nonce.0.into(),
                    (note_issuance_request, *note_idx_ref, amount)
                )
                .is_none()
        );

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

        if let Some((_issuance_request, note_idx, amount)) =
            self.used_nonces.get(&output.blind_nonce.0.into())
        {
            self.burned_total += *amount;
            self.reused_note_indices.push((*amount, *note_idx));
            warn!(
                target: LOG_CLIENT_RECOVERY_MINT,
                %note_idx,
                %amount,
                burned_total = %self.burned_total,
                "Detected reused nonce during recovery. This means client probably burned funds in the past."
            );
        }
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

        if let Some((issuance_request, note_idx, pending_amount)) =
            self.pending_nonces.remove(&output.blind_nonce.0.into())
        {
            // the moment we see our blind nonce in the epoch history, correctly or
            // incorrectly used, we know that we must have used
            // already
            self.observe_nonce_idx_being_used(pending_amount, note_idx, secret);

            if pending_amount == output.amount {
                self.used_nonces.insert(
                    output.blind_nonce.0.into(),
                    (issuance_request, note_idx, pending_amount),
                );

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
                    target: LOG_CLIENT_RECOVERY_MINT,
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
        self.last_used_nonce_idx.insert(
            amount,
            max(
                self.last_used_nonce_idx
                    .get(amount)
                    .copied()
                    .unwrap_or_default(),
                note_idx,
            ),
        );

        while self.next_pending_note_idx.get_mut_or_default(amount).0
            < self.gap_limit
                + self
                    .last_used_nonce_idx
                    .get(amount)
                    .expect("must be there already")
                    .0
        {
            self.add_next_pending_nonce_in_pending_pool(amount, secret);
        }
    }

    pub fn finalize(self) -> EcashRecoveryFinalState {
        EcashRecoveryFinalState {
            spendable_notes: self.spendable_notes.into_values().collect(),
            unconfirmed_notes: self.pending_outputs.into_values().collect(),
            // next note idx is the last one detected as used + 1
            next_note_idx: self
                .last_used_nonce_idx
                .iter()
                .map(|(amount, value)| (amount, value.next()))
                .collect(),
            reused_note_indices: self.reused_note_indices,
            burned_total: self.burned_total,
        }
    }
}

const GAP_LIMIT: u64 = 100;

/// Recovery state that can be checkpointed and resumed (slice-based recovery)
#[derive(Clone, Debug, Encodable, Decodable)]
pub struct RecoveryStateV2 {
    /// Next item index to download
    pub next_index: u64,
    /// Total items (for progress calculation)
    pub total_items: u64,
    /// Pending outputs - notes we've seen issued and are waiting to collect
    pending_outputs: BTreeMap<hash160::Hash, (Amount, NoteIssuanceRequest)>,
    /// Next nonces that we expect might soon get used.
    pending_nonces: BTreeMap<(Amount, hash160::Hash), (NoteIssuanceRequest, u64)>,
    /// Tail of pending. `pending_nonces` is filled by generating note with
    /// this index and incrementing it.
    next_pending_note_idx: BTreeMap<Amount, u64>,
    /// `LastECashNoteIndex` but tracked in flight - max index of any note
    /// that got a partial sig from the federation
    last_used_nonce_idx: BTreeMap<Amount, u64>,
}

impl RecoveryStateV2 {
    pub fn new(total_items: u64, amount_tiers: Vec<Amount>, secret: &DerivableSecret) -> Self {
        let mut state = Self {
            next_index: 0,
            total_items,
            pending_outputs: BTreeMap::default(),
            pending_nonces: BTreeMap::default(),
            next_pending_note_idx: BTreeMap::default(),
            last_used_nonce_idx: BTreeMap::default(),
        };

        for amount in amount_tiers {
            state.add_pending_nonces(amount, GAP_LIMIT, secret);
        }

        state
    }

    fn add_pending_nonces(&mut self, amount: Amount, count: u64, secret: &DerivableSecret) {
        let next_idx = self
            .next_pending_note_idx
            .get(&amount)
            .copied()
            .unwrap_or_default();

        self.next_pending_note_idx.insert(amount, next_idx + count);

        for i in next_idx..(next_idx + count) {
            let secret = MintClientModule::new_note_secret_static(secret, amount, NoteIndex(i));

            let (request, blind_nonce) = NoteIssuanceRequest::new(SECP256K1, &secret);

            let hash = blind_nonce.consensus_hash::<hash160::Hash>();

            self.pending_nonces.insert((amount, hash), (request, i));
        }
    }

    pub fn handle_output(
        &mut self,
        amount: Amount,
        blind_nonce_hash: hash160::Hash,
        secret: &DerivableSecret,
    ) {
        if let Some((request, idx)) = self.pending_nonces.remove(&(amount, blind_nonce_hash)) {
            self.observe_nonce_idx_being_used(amount, idx, secret);

            let hash = request.nonce().consensus_hash::<hash160::Hash>();

            self.pending_outputs.insert(hash, (amount, request));
        }
    }

    pub fn handle_input(&mut self, nonce_hash: hash160::Hash) {
        self.pending_outputs.remove(&nonce_hash);
    }

    fn observe_nonce_idx_being_used(&mut self, amount: Amount, idx: u64, secret: &DerivableSecret) {
        let last_used_nonce_idx = self
            .last_used_nonce_idx
            .get(&amount)
            .copied()
            .unwrap_or(idx);

        self.last_used_nonce_idx
            .insert(amount, max(last_used_nonce_idx, idx));

        let next_pending_note_idx = self
            .next_pending_note_idx
            .get(&amount)
            .copied()
            .unwrap_or_default();

        let missing = last_used_nonce_idx
            .add(GAP_LIMIT)
            .saturating_sub(next_pending_note_idx);

        if missing > 0 {
            self.add_pending_nonces(amount, missing, secret);
        }
    }

    pub fn finalize(self) -> RecoveryStateV2Finalized {
        RecoveryStateV2Finalized {
            pending_notes: self.pending_outputs.into_values().collect(),
            next_note_idx: self
                .last_used_nonce_idx
                .into_iter()
                .map(|(amount, idx)| (amount, NoteIndex(idx + 1)))
                .collect(),
        }
    }
}

pub struct RecoveryStateV2Finalized {
    /// Pending notes that need state machines to collect signatures
    pub pending_notes: Vec<(Amount, NoteIssuanceRequest)>,
    /// Next note index per amount tier (for restoring `NextECashNoteIndexKey`)
    pub next_note_idx: BTreeMap<Amount, NoteIndex>,
}
