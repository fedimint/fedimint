use std::cmp::max;
use std::collections::BTreeMap;
use std::fmt;

use fedimint_client::module::init::recovery::{RecoveryFromHistory, RecoveryFromHistoryCommon};
use fedimint_client::module::init::ClientModuleRecoverArgs;
use fedimint_client::module::{ClientContext, ClientDbTxContext};
use fedimint_core::core::OperationId;
use fedimint_core::db::{DatabaseTransaction, IDatabaseTransactionOpsCoreTyped as _};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{
    apply, async_trait_maybe_send, Amount, NumPeers, OutPoint, PeerId, Tiered, TieredMulti,
};
use fedimint_derive_secret::DerivableSecret;
use fedimint_logging::LOG_CLIENT_RECOVERY_MINT;
use fedimint_mint_common::{MintInput, MintOutput, Nonce};
use serde::{Deserialize, Serialize};
use tbs::{AggregatePublicKey, BlindedMessage, PublicKeyShare};
use threshold_crypto::G1Affine;
use tracing::{debug, info, trace, warn};

use super::EcashBackup;
use crate::backup::EcashBackupV0;
use crate::client_db::{NextECashNoteIndexKey, NoteKey, RecoveryFinalizedKey, RecoveryStateKey};
use crate::output::{
    MintOutputCommon, MintOutputStateMachine, MintOutputStatesCreated, NoteIssuanceRequest,
};
use crate::{MintClientInit, MintClientModule, MintClientStateMachines, NoteIndex, SpendableNote};

#[derive(Clone, Debug)]
pub struct MintRecovery {
    state: MintRecoveryState,
    secret: DerivableSecret,
}

#[apply(async_trait_maybe_send!)]
impl RecoveryFromHistory for MintRecovery {
    type Init = MintClientInit;

    async fn new(
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
                state: MintRecoveryState::from_backup(
                    snapshot,
                    30,
                    config.tbs_pks.clone(),
                    config.peer_tbs_pks.clone(),
                    &secret,
                ),
                secret,
            },
            starting_session,
        ))
    }

    async fn load_dbtx(
        dbtx: &mut DatabaseTransaction<'_>,
        args: &ClientModuleRecoverArgs<Self::Init>,
    ) -> Option<(Self, RecoveryFromHistoryCommon)> {
        dbtx.get_value(&RecoveryStateKey)
            .await
            .map(|(state, common)| {
                (
                    MintRecovery {
                        state,
                        secret: args.module_root_secret().clone(),
                    },
                    common,
                )
            })
    }

    async fn store_dbtx(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        common: &RecoveryFromHistoryCommon,
    ) {
        dbtx.insert_entry(&RecoveryStateKey, &(self.state.clone(), common.clone()))
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
    ) -> anyhow::Result<()> {
        self.state.handle_input(input);
        Ok(())
    }

    async fn handle_output(
        &mut self,
        _client_ctx: &ClientContext<MintClientModule>,
        out_point: OutPoint,
        output: &MintOutput,
    ) -> anyhow::Result<()> {
        self.state.handle_output(out_point, output, &self.secret);
        Ok(())
    }

    /// Handle session outcome, adjusting the current state
    async fn finalize_dbtx(
        &self,
        dbtx: &mut ClientDbTxContext<'_, '_, MintClientModule>,
    ) -> anyhow::Result<()> {
        let finalized = self.state.clone().finalize();

        let restored_amount = finalized
            .unconfirmed_notes
            .iter()
            .map(|entry| entry.1)
            .sum::<Amount>()
            + finalized.spendable_notes.total_amount();

        info!(amount = %restored_amount, "Finalizing mint recovery");

        debug!(
            target: LOG_CLIENT_RECOVERY_MINT,
            len = finalized.spendable_notes.count_items(),
            "Restoring spendable notes"
        );
        for (amount, note) in finalized.spendable_notes {
            let key = NoteKey {
                amount,
                nonce: note.nonce(),
            };
            dbtx.module_dbtx().insert_new_entry(&key, &note).await;
        }

        for (amount, note_idx) in finalized.next_note_idx.iter() {
            debug!(
                target: LOG_CLIENT_RECOVERY_MINT,
                %amount,
                %note_idx,
                "Restoring NextECashNodeIndex"
            );
            dbtx.module_dbtx()
                .insert_entry(&NextECashNoteIndexKey(amount), &note_idx.as_u64())
                .await;
        }

        debug!(
            target: LOG_CLIENT_RECOVERY_MINT,
            len = finalized.unconfirmed_notes.len(),
            "Restoring unconfigured notes state machines"
        );

        for (out_point, amount, issuance_request) in finalized.unconfirmed_notes {
            let client_ctx = dbtx.client_ctx();
            dbtx.add_state_machines(
                client_ctx
                    .map_dyn(vec![MintClientStateMachines::Output(
                        MintOutputStateMachine {
                            common: MintOutputCommon {
                                operation_id: OperationId::new_random(),
                                out_point,
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
            "MintRestoreInProgressState(pending_outputs: {}, pending_nonces: {})",
            self.pending_outputs.len(),
            self.pending_nonces.len()
        ))
    }
}

impl MintRecoveryState {
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
