pub mod db;

use std::cmp::Ordering;
use std::fmt;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use db::{NoteKey, NoteKeyPrefix, OutputFinalizationKey, OutputFinalizationKeyPrefix};
use fedimint_core::api::{GlobalFederationApi, MemberError, OutputOutcomeError};
use fedimint_core::core::client::ClientModule;
use fedimint_core::core::Decoder;
use fedimint_core::db::DatabaseTransaction;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::module::{ModuleCommon, TransactionItemAmount};
use fedimint_core::tiered::InvalidAmountTierError;
use fedimint_core::{Amount, OutPoint, Tiered, TieredMulti, TieredSummary, TransactionId};
use fedimint_mint_client::MintModuleTypes;
use futures::executor::block_on;
use futures::{Future, StreamExt};
use secp256k1_zkp::{KeyPair, Secp256k1, Signing};
use serde::{Deserialize, Serialize};
use tbs::{blind_message, unblind_signature, AggregatePublicKey, BlindedSignature, BlindingKey};
use thiserror::Error;
use tracing::{debug, error, trace, warn};

use crate::mint::db::{NextECashNoteIndexKey, NotesPerDenominationKey, PendingNotesKey};
use crate::modules::mint::config::MintClientConfig;
use crate::modules::mint::{
    BlindNonce, MintInput, MintOutput, MintOutputBlindSignatures, MintOutputOutcome, Nonce, Note,
};
use crate::transaction::legacy::{Input, Output, Transaction};
use crate::utils::ClientContext;
use crate::{ChildId, DerivableSecret, FuturesUnordered};

pub mod backup;

const MINT_E_CASH_TYPE_CHILD_ID: ChildId = ChildId(0);
const MINT_E_CASH_BACKUP_SNAPSHOT_TYPE_CHILD_ID: ChildId = ChildId(1);
const MINT_E_CASH_FETCH_TIMEOUT: Duration = Duration::from_secs(10);

/// Federation module client for the Mint module. It can both create transaction
/// inputs and outputs of the mint type.
#[derive(Debug, Clone)]
pub struct MintClient {
    pub epoch_pk: threshold_crypto::PublicKey,
    pub config: MintClientConfig,
    pub context: Arc<ClientContext>,
    pub secret: DerivableSecret,
}

/// An index used to deterministically derive [`Note`]s
///
/// We allow converting it to u64 and incrementing it, but
/// messing with it should be somewhat restricted to prevent
/// silly errors.
#[derive(
    Copy,
    Clone,
    Debug,
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
    Encodable,
    Decodable,
    Default,
    PartialOrd,
    Ord,
)]
pub struct NoteIndex(u64);

impl NoteIndex {
    pub fn next(self) -> Self {
        Self(self.0 + 1)
    }

    pub fn as_u64(self) -> u64 {
        self.0
    }

    // Private. If it turns out it is useful outside,
    // we can relax and convert to `From<u64>`
    // Actually used in tests RN, so cargo complains in non-test builds.
    #[allow(unused)]
    fn from_u64(v: u64) -> Self {
        Self(v)
    }

    pub fn advance(&mut self) {
        *self = self.next()
    }
}

impl fmt::Display for NoteIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}
/// Single [`Note`] issuance request to the mint.f
///
/// Keeps the data to generate [`SpendableNote`] once the
/// mint successfully processed the transaction signing the corresponding
/// [`BlindNonce`].
#[derive(Debug, Copy, Clone, PartialEq, Eq, Deserialize, Serialize, Encodable, Decodable)]
pub struct NoteIssuanceRequest {
    /// Spend key from which the note nonce (corresponding public key) is
    /// derived
    spend_key: KeyPair,
    /// Key to unblind the blind signature supplied by the mint for this note
    blinding_key: BlindingKey,
}

impl NoteIssuanceRequest {
    pub fn recover_blind_nonce(&self) -> BlindNonce {
        let message = Nonce(self.spend_key.x_only_public_key().0).to_message();
        BlindNonce(tbs::blind_message(message, self.blinding_key))
    }

    pub fn finalize(
        &self,
        bsig: BlindedSignature,
        mint_pub_key: AggregatePublicKey,
    ) -> std::result::Result<SpendableNote, NoteFinalizationError> {
        let sig = unblind_signature(self.blinding_key, bsig);
        let note = Note(self.nonce(), sig);
        if note.verify(mint_pub_key) {
            let spendable_note = SpendableNote {
                note,
                spend_key: self.spend_key,
            };

            Ok(spendable_note)
        } else {
            Err(NoteFinalizationError::InvalidSignature)
        }
    }
}
/// Multiple [`Note`] issuance requests
///
/// Keeps all the data to generate [`SpendableNote`]s once the
/// mint successfully processed corresponding [`NoteIssuanceRequest`]s.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize, Encodable, Decodable)]
pub struct NoteIssuanceRequests {
    /// Finalization data for all note outputs in this request
    notes: TieredMulti<NoteIssuanceRequest>,
}

/// A [`Note`] with associated secret key that allows to proof ownership (spend
/// it)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct SpendableNote {
    pub note: Note,
    pub spend_key: KeyPair,
}

impl ClientModule for MintClient {
    const KIND: &'static str = "mint";
    type Module = MintModuleTypes;

    fn decoder(&self) -> Decoder {
        <Self::Module as ModuleCommon>::decoder()
    }

    fn input_amount(&self, input: &MintInput) -> TransactionItemAmount {
        TransactionItemAmount {
            amount: input.total_amount(),
            fee: self.config.fee_consensus.note_spend_abs * (input.count_items() as u64),
        }
    }

    fn output_amount(&self, output: &MintOutput) -> TransactionItemAmount {
        TransactionItemAmount {
            amount: output.total_amount(),
            fee: self.config.fee_consensus.note_issuance_abs * (output.count_items() as u64),
        }
    }
}

impl MintClient {
    pub async fn start_dbtx(&self) -> DatabaseTransaction<'_> {
        self.context.db.begin_transaction().await
    }

    /// Adds the final amounts of `change` to the tx before submitting it
    /// Allows for multiple `change` outputs
    pub async fn finalize_change(
        &self,
        tx: &mut Transaction,
        dbtx: &mut DatabaseTransaction<'_>,
        change: Vec<Amount>,
    ) {
        // remove the spent ecash from the DB
        let mut input_ecash: Vec<(Amount, SpendableNote)> = vec![];
        for input in &tx.inputs {
            if let Input::Mint(MintInput(notes)) = input {
                for (amount, note) in notes.clone() {
                    let key = NoteKey {
                        amount,
                        nonce: note.0,
                    };
                    let spendable = dbtx.get_value(&key).await.expect("Missing note");
                    input_ecash.push((amount, spendable));
                    dbtx.remove_entry(&key).await;
                }
            }
        }

        let mut change_outputs: Vec<(usize, NoteIssuanceRequests)> = vec![];
        let notes_per_denomination = self.notes_per_denomination(dbtx).await;
        for amount in change.clone() {
            if amount == Amount::ZERO {
                continue;
            }
            let (issuances, nonces) = self
                .create_ecash(amount, notes_per_denomination, dbtx)
                .await;
            let out_idx = tx.outputs.len();
            tx.outputs.push(Output::Mint(MintOutput(nonces)));
            change_outputs.push((out_idx, issuances));
        }
        let txid = tx.tx_hash();

        // move ecash to pending state, awaiting a transaction
        if !input_ecash.is_empty() {
            let pending = TieredMulti::from_iter(input_ecash.into_iter());
            dbtx.insert_entry(&PendingNotesKey(txid), &pending).await;
        }

        // write ecash outputs to db to await for tx success to be fetched later
        for (out_idx, notes) in change_outputs.iter() {
            dbtx.insert_new_entry(
                &OutputFinalizationKey(OutPoint {
                    txid,
                    out_idx: *out_idx as u64,
                }),
                &notes.clone(),
            )
            .await;
        }
    }

    pub async fn set_notes_per_denomination(&self, notes: u16) {
        let mut dbtx = self.start_dbtx().await;
        dbtx.insert_entry(&NotesPerDenominationKey, &notes).await;
        dbtx.commit_tx().await;
    }

    async fn notes_per_denomination(&self, dbtx: &mut DatabaseTransaction<'_>) -> u16 {
        dbtx.get_value(&NotesPerDenominationKey)
            .await
            .unwrap_or(self.config.max_notes_per_denomination - 1)
    }

    /// Generates unsigned ecash, along with the private keys that can spend it
    async fn create_ecash(
        &self,
        amount: Amount,
        notes_per_denomination: u16,
        dbtx: &mut DatabaseTransaction<'_>,
    ) -> (NoteIssuanceRequests, TieredMulti<BlindNonce>) {
        let mut amount_requests: Vec<((Amount, NoteIssuanceRequest), (Amount, BlindNonce))> =
            Vec::new();
        let denominations = TieredSummary::represent_amount(
            amount,
            &self.summary().await,
            &self.config.tbs_pks,
            notes_per_denomination,
        );
        for (amt, num) in denominations.iter() {
            for _ in 0..num {
                let (request, blind_nonce) =
                    self.new_ecash_note(&self.context.secp, amt, dbtx).await;
                amount_requests.push(((amt, request), (amt, blind_nonce)));
            }
        }
        let (note_finalization_data, sig_req): (NoteIssuanceRequests, MintOutput) =
            amount_requests.into_iter().unzip();

        debug!(
            %amount,
            notes = %sig_req.0.count_items(),
            tiers = ?sig_req.0.iter_tiers().collect::<Vec<_>>(),
            "Generated issuance request"
        );

        (note_finalization_data, sig_req.0)
    }

    pub async fn select_input(&self, amount: Amount) -> Result<(Vec<KeyPair>, Input)> {
        Self::ecash_input(self.select_notes(amount).await?)
    }

    pub fn ecash_input(ecash: TieredMulti<SpendableNote>) -> Result<(Vec<KeyPair>, Input)> {
        let note_key_pairs = ecash
            .into_iter()
            .map(|(amt, note)| {
                // We check for note validity in case we got it from an untrusted third party.
                // We don't want to needlessly create invalid tx and bother the
                // federation with them.
                let spend_pub_key = note.spend_key.x_only_public_key().0;
                if &spend_pub_key == note.note.spend_key() {
                    Ok((note.spend_key, (amt, note.note)))
                } else {
                    Err(MintClientError::ReceivedUnspendableNote)
                }
            })
            .collect::<Result<Vec<_>>>()?;
        let (key_pairs, input) = note_key_pairs.into_iter().unzip();
        Ok((key_pairs, Input::Mint(MintInput(input))))
    }

    pub async fn notes(&self) -> TieredMulti<SpendableNote> {
        self.start_dbtx()
            .await
            .find_by_prefix(&NoteKeyPrefix)
            .await
            .map(|(key, spendable_note)| (key.amount, spendable_note))
            .collect()
            .await
    }

    /// Get available spendable notes with a db transaction already opened
    pub async fn get_available_notes(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
    ) -> TieredMulti<SpendableNote> {
        dbtx.find_by_prefix(&NoteKeyPrefix)
            .await
            .map(|(key, spendable_note)| (key.amount, spendable_note))
            .collect()
            .await
    }

    pub async fn get_next_note_index(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        amount: Amount,
    ) -> NoteIndex {
        NoteIndex(
            dbtx.get_value(&NextECashNoteIndexKey(amount))
                .await
                .unwrap_or(0),
        )
    }

    async fn new_note_secret(
        &self,
        amount: Amount,
        dbtx: &mut DatabaseTransaction<'_>,
    ) -> DerivableSecret {
        let new_idx = self.get_next_note_index(dbtx, amount).await;
        dbtx.insert_entry(&NextECashNoteIndexKey(amount), &new_idx.next().as_u64())
            .await;
        Self::new_note_secret_static(&self.secret, amount, new_idx)
    }

    /// Derive the note `DerivableSecret` from the Mint's `secret` the `amount`
    /// tier and `note_idx`
    ///
    /// Static to help re-use in other places, that don't have a whole [`Self`]
    /// available
    pub fn new_note_secret_static(
        secret: &DerivableSecret,
        amount: Amount,
        note_idx: NoteIndex,
    ) -> DerivableSecret {
        assert_eq!(secret.level(), 1);
        debug!(?secret, %amount, %note_idx, "Deriving new mint note");
        secret
            .child_key(MINT_E_CASH_TYPE_CHILD_ID) // TODO: cache
            .child_key(ChildId(amount.msats))
            .child_key(ChildId(note_idx.as_u64()))
            .child_key(ChildId(amount.msats))
    }

    pub async fn new_ecash_note<C: Signing>(
        &self,
        ctx: &Secp256k1<C>,
        amount: Amount,
        dbtx: &mut DatabaseTransaction<'_>,
    ) -> (NoteIssuanceRequest, BlindNonce) {
        let secret = self.new_note_secret(amount, dbtx).await;
        NoteIssuanceRequest::new(ctx, secret)
    }

    pub async fn summary(&self) -> TieredSummary {
        self.start_dbtx()
            .await
            .find_by_prefix(&NoteKeyPrefix)
            .await
            .fold(
                TieredSummary::default(),
                |mut acc, (key, _note)| async move {
                    acc.inc(key.amount, 1);
                    acc
                },
            )
            .await
    }

    /// Select notes with total amount of *at least* `amount`. If more than
    /// requested amount of notes are returned it was because exact change
    /// couldn't be made, and the next smallest amount will be returned.
    ///
    /// The caller can request change from the federation.
    pub async fn select_notes(&self, amount: Amount) -> Result<TieredMulti<SpendableNote>> {
        let mut dbtx = self.start_dbtx().await;
        let note_stream = dbtx
            .find_by_prefix_sorted_descending(&NoteKeyPrefix)
            .await
            .map(|(key, note)| (key.amount, note));
        Self::select_notes_from_stream(note_stream, amount).await
    }

    // We are using a greedy algorithm to select notes. We start with the largest
    // then proceed to the lowest tiers/denominations.
    // But there is a catch: we don't know if there are enough notes in the lowest
    // tiers, so we need to save a big note in case the sum of the following
    // small notes are not enough.
    async fn select_notes_from_stream<Note>(
        stream: impl futures::Stream<Item = (Amount, Note)>,
        requested_amount: Amount,
    ) -> Result<TieredMulti<Note>> {
        if requested_amount == Amount::ZERO {
            return Ok(TieredMulti::default());
        }
        let mut stream = Box::pin(stream);
        let mut selected = vec![];
        // This is the big note we save in case the sum of the following small notes are
        // not sufficient to cover the pending amount
        // The tuple is (amount, note, checkpoint), where checkpoint is the index where
        // the note should be inserted on the selected vector if it is needed
        let mut last_big_note_checkpoint: Option<(Amount, Note, usize)> = None;
        let mut pending_amount = requested_amount;
        let mut previous_amount: Option<Amount> = None; // used to assert descending order
        loop {
            if let Some((note_amount, note)) = stream.next().await {
                assert!(
                    previous_amount.map_or(true, |previous| previous >= note_amount),
                    "notes are not sorted in descending order"
                );
                previous_amount = Some(note_amount);
                match note_amount.cmp(&pending_amount) {
                    Ordering::Less => {
                        // keep adding notes until we have enough
                        pending_amount -= note_amount;
                        selected.push((note_amount, note))
                    }
                    Ordering::Greater => {
                        // probably we don't need this big note, but we'll keep it in case the
                        // following small notes don't add up to the
                        // requested amount
                        last_big_note_checkpoint = Some((note_amount, note, selected.len()));
                    }
                    Ordering::Equal => {
                        // exactly enough notes, return
                        selected.push((note_amount, note));
                        return Ok(selected.into_iter().collect());
                    }
                }
            } else {
                assert!(pending_amount > Amount::ZERO);
                if let Some((big_note_amount, big_note, checkpoint)) = last_big_note_checkpoint {
                    // the sum of the small notes don't add up to the pending amount, remove
                    // them
                    selected.truncate(checkpoint);
                    // and use the big note to cover it
                    selected.push((big_note_amount, big_note));
                    // so now we have enough to cover the requested amount, return
                    return Ok(selected.into_iter().collect());
                } else {
                    let total_amount = requested_amount - pending_amount;
                    // not enough notes, return
                    return Err(MintClientError::InsufficientBalance(
                        requested_amount,
                        total_amount,
                    ));
                }
            }
        }
    }

    pub async fn receive_notes(
        &self,
        amount: Amount,
    ) -> (TieredMulti<BlindNonce>, Box<dyn Fn(OutPoint)>) {
        let db = self.context.db.clone();
        let mut dbtx = self.context.db.begin_transaction().await;
        let notes_per_denomination = self.notes_per_denomination(&mut dbtx).await;
        let (finalization, notes) = self
            .create_ecash(amount, notes_per_denomination, &mut dbtx)
            .await;
        dbtx.commit_tx().await;

        (
            notes,
            Box::new(move |out_point| {
                let mut dbtx = block_on(db.begin_transaction());
                block_on(dbtx.insert_new_entry(&OutputFinalizationKey(out_point), &finalization));
                block_on(dbtx.commit_tx());
            }),
        )
    }

    pub async fn await_fetch_notes<'a>(
        &self,
        dbtx: &mut DatabaseTransaction<'a>,
        outpoint: &OutPoint,
    ) -> Result<OutPoint> {
        let mut total_time = Duration::ZERO;
        let retry_duration = Duration::from_millis(200);

        loop {
            match self.fetch_notes(dbtx, *outpoint).await {
                Ok(_) => {
                    break Ok(*outpoint);
                }
                // TODO: make mint error more expressive (currently any HTTP error) and maybe use
                // custom return type instead of error for retrying
                Err(e) if e.is_retryable() && total_time < MINT_E_CASH_FETCH_TIMEOUT => {
                    trace!("Mint returned retryable error: {:?}", e);
                    fedimint_core::task::sleep(retry_duration).await
                }
                Err(e) => {
                    warn!("Mint returned error: {:?}", e);
                    break Err(e);
                }
            }
            total_time += retry_duration;
        }
    }

    pub async fn fetch_notes<'a>(
        &self,
        dbtx: &mut DatabaseTransaction<'a>,
        outpoint: OutPoint,
    ) -> Result<()> {
        let issuance = self
            .context
            .db
            .begin_transaction()
            .await
            .get_value(&OutputFinalizationKey(outpoint))
            .await
            .ok_or(MintClientError::FinalizationError(
                NoteFinalizationError::UnknownIssuance,
            ))?;

        let bsig = self
            .context
            .api
            .fetch_output_outcome::<MintOutputOutcome>(outpoint, &self.context.decoders)
            .await?
            .ok_or(MintClientError::OutputNotReadyYet(outpoint))?
            .as_ref()
            .cloned()
            .ok_or(MintClientError::OutputNotReadyYet(outpoint))?;

        let notes = issuance.finalize(bsig, &self.config.tbs_pks)?;

        for (amount, note) in notes.into_iter() {
            let key = NoteKey {
                amount,
                nonce: note.note.0,
            };
            let value = note;
            dbtx.insert_new_entry(&key, &value).await;
        }
        dbtx.remove_entry(&OutputFinalizationKey(outpoint)).await;

        Ok(())
    }

    pub async fn list_active_issuances(&self) -> Vec<(OutPoint, NoteIssuanceRequests)> {
        self.context
            .db
            .begin_transaction()
            .await
            .find_by_prefix(&OutputFinalizationKeyPrefix)
            .await
            .map(|(OutputFinalizationKey(outpoint), cfd)| (outpoint, cfd))
            .collect()
            .await
    }

    pub async fn fetch_all_notes(&self) -> Vec<Result<OutPoint>> {
        let active_issuances = &self.list_active_issuances().await;
        let mut results = vec![];

        #[cfg(not(target_family = "wasm"))]
        let mut futures = FuturesUnordered::<Pin<Box<dyn Future<Output = _> + Send>>>::new();
        #[cfg(target_family = "wasm")]
        let mut futures = FuturesUnordered::<Pin<Box<dyn Future<Output = _>>>>::new();
        for (outpoint, _) in active_issuances {
            futures.push(Box::pin(async {
                let mut dbtx = self.context.db.begin_transaction().await;
                let res = self.await_fetch_notes(&mut dbtx, outpoint).await;
                dbtx.commit_tx().await;
                res
            }))
        }

        while let Some(result) = futures.next().await {
            results.push(result);
        }

        results
    }
}

impl Extend<(Amount, NoteIssuanceRequest)> for NoteIssuanceRequests {
    fn extend<T: IntoIterator<Item = (Amount, NoteIssuanceRequest)>>(&mut self, iter: T) {
        self.notes.extend(iter)
    }
}

impl NoteIssuanceRequests {
    /// Finalize the issuance request using a [`MintOutputBlindSignatures`] from
    /// the mint containing the blind signatures for all notes in this
    /// `IssuanceRequest`. It also takes the mint's [`AggregatePublicKey`]
    /// to validate the supplied blind signatures.
    pub fn finalize(
        &self,
        bsigs: MintOutputBlindSignatures,
        mint_pub_key: &Tiered<AggregatePublicKey>,
    ) -> std::result::Result<TieredMulti<SpendableNote>, NoteFinalizationError> {
        if !self.notes.structural_eq(&bsigs.0) {
            return Err(NoteFinalizationError::WrongMintAnswer);
        }

        self.notes
            .iter_items()
            .zip(bsigs.0)
            .enumerate()
            .map(|(idx, ((amt, note_req), (_amt, bsig)))| {
                Ok((
                    amt,
                    match note_req.finalize(bsig, *mint_pub_key.tier(&amt)?) {
                        Err(NoteFinalizationError::InvalidSignature) => {
                            Err(NoteFinalizationError::InvalidSignatureAtIdx(idx))
                        }
                        other => other,
                    }?,
                ))
            })
            .collect()
    }

    pub fn note_count(&self) -> usize {
        self.notes.count_items()
    }

    pub fn note_amount(&self) -> Amount {
        self.notes.total_amount()
    }
}

impl NoteIssuanceRequest {
    /// Generate a request session for a single note and returns it plus the
    /// corresponding blinded message
    fn new<C>(ctx: &Secp256k1<C>, secret: DerivableSecret) -> (NoteIssuanceRequest, BlindNonce)
    where
        C: Signing,
    {
        let spend_key = secret.child_key(ChildId(0)).to_secp_key(ctx);
        let nonce = Nonce(spend_key.x_only_public_key().0);
        let blinding_key = BlindingKey(secret.child_key(ChildId(1)).to_bls12_381_key());
        let blinded_nonce = blind_message(nonce.to_message(), blinding_key);

        let cr = NoteIssuanceRequest {
            spend_key,
            blinding_key,
        };

        (cr, BlindNonce(blinded_nonce))
    }

    pub fn nonce(&self) -> Nonce {
        Nonce(self.spend_key.x_only_public_key().0)
    }
}

type Result<T> = std::result::Result<T, MintClientError>;

#[derive(Error, Debug)]
pub enum NoteFinalizationError {
    #[error("The returned answer does not fit the request")]
    WrongMintAnswer,
    #[error("The blind signature")]
    InvalidSignature,
    #[error("The blind signature at index {0} is invalid")]
    InvalidSignatureAtIdx(usize),
    #[error("Expected signatures for issuance request {0}, got signatures for request {1}")]
    InvalidIssuanceId(TransactionId, TransactionId),
    #[error("Invalid amount tier {0:?}")]
    InvalidAmountTier(Amount),
    #[error("The client does not know this issuance")]
    UnknownIssuance,
}

#[derive(Error, Debug)]
pub enum MintClientError {
    #[error("Error querying federation: {0}")]
    ApiError(#[from] MemberError),
    #[error("Could not finalize issuance request: {0}")]
    FinalizationError(#[from] NoteFinalizationError),
    #[error("Insufficient balance. Amount requested={0} Mint balance={1}")]
    InsufficientBalance(Amount, Amount),
    #[error("The transaction outcome received from the mint did not contain a result for output {0} yet")]
    OutputNotReadyYet(OutPoint),
    #[error("Output outcome error: {0}")]
    OutputOutcomeError(#[from] OutputOutcomeError),
    #[error("The transaction outcome returned by the mint contains too few outputs (output {0})")]
    InvalidOutcomeWrongStructure(OutPoint),
    #[error("The transaction outcome returned by the mint has an invalid type (output {0})")]
    InvalidOutcomeType(OutPoint),
    #[error("One of the notes meant to be spent is unspendable")]
    ReceivedUnspendableNote,
}

impl MintClientError {
    /// Returns `true` if queried outpoint isn't ready yet but may become ready
    /// later
    pub fn is_retryable(&self) -> bool {
        match self {
            MintClientError::OutputOutcomeError(OutputOutcomeError::Federation(e)) => {
                e.is_retryable()
            }
            MintClientError::ApiError(e) => e.is_retryable(),
            MintClientError::OutputNotReadyYet(_) => true,
            _ => false,
        }
    }
}

impl From<InvalidAmountTierError> for NoteFinalizationError {
    fn from(e: InvalidAmountTierError) -> Self {
        NoteFinalizationError::InvalidAmountTier(e.0)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, HashSet};
    use std::sync::Arc;

    use bitcoin::hashes::Hash;
    use fedimint_core::api::WsFederationApi;
    use fedimint_core::config::ConfigGenModuleParams;
    use fedimint_core::core::{
        DynOutputOutcome, ModuleInstanceId, LEGACY_HARDCODED_INSTANCE_ID_MINT,
    };
    use fedimint_core::db::mem_impl::MemDatabase;
    use fedimint_core::db::Database;
    use fedimint_core::module::registry::ModuleDecoderRegistry;
    use fedimint_core::outcome::{SerdeOutputOutcome, TransactionStatus};
    use fedimint_core::{Amount, OutPoint, ServerModule, Tiered, TieredMulti, TransactionId};
    use fedimint_mint_server::{Mint, MintGen, MintGenParams};
    use fedimint_testing::FakeFed;
    use futures::executor::block_on;
    use itertools::Itertools;
    use tokio::sync::Mutex;

    use super::*;
    use crate::api::fake::FederationApiFaker;
    use crate::mint::db::NextECashNoteIndexKey;
    use crate::mint::MintClient;
    use crate::modules::mint::config::MintClientConfig;
    use crate::modules::mint::MintOutput;
    use crate::transaction::legacy::Input;
    use crate::{
        module_decode_stubs, BlindNonce, ClientContext, DerivableSecret, TransactionBuilder,
        MINT_SECRET_CHILD_ID,
    };

    type Fed = FakeFed<Mint>;

    async fn make_test_mint_fed(
        module_id: ModuleInstanceId,
        fed: Arc<Mutex<FakeFed<Mint>>>,
    ) -> FederationApiFaker<tokio::sync::Mutex<FakeFed<Mint>>> {
        let members = fed
            .lock()
            .await
            .members
            .iter()
            .map(|(peer_id, _, _, _)| *peer_id)
            .collect();
        FederationApiFaker::new(fed, members)
            .with(
                "/fetch_transaction",
                move |mint: Arc<Mutex<FakeFed<Mint>>>, tx: TransactionId| async move {
                    let mint = mint.lock().await;
                    Ok(Some(TransactionStatus::Accepted {
                        epoch: 0,
                        outputs: vec![SerdeOutputOutcome::from(&DynOutputOutcome::from_typed(
                            module_id,
                            mint.output_outcome(OutPoint {
                                txid: tx,
                                out_idx: 0,
                            })
                            .await
                            .unwrap(),
                        ))],
                    }))
                },
            )
            .with(
                "/wait_transaction",
                move |mint: Arc<Mutex<FakeFed<Mint>>>, tx: TransactionId| async move {
                    let mint = mint.lock().await;
                    Ok(TransactionStatus::Accepted {
                        epoch: 0,
                        outputs: vec![SerdeOutputOutcome::from(&DynOutputOutcome::from_typed(
                            module_id,
                            mint.output_outcome(OutPoint {
                                txid: tx,
                                out_idx: 0,
                            })
                            .await
                            .unwrap(),
                        ))],
                    })
                },
            )
    }

    async fn new_mint_and_client() -> (
        Arc<tokio::sync::Mutex<Fed>>,
        MintClientConfig,
        ClientContext,
    ) {
        let module_id = LEGACY_HARDCODED_INSTANCE_ID_MINT;
        let fed = Arc::new(tokio::sync::Mutex::new(
            FakeFed::<Mint>::new(
                4,
                |cfg, _db| async move { Ok(Mint::new(cfg.to_typed().unwrap())) },
                &ConfigGenModuleParams::from_typed(MintGenParams {
                    mint_amounts: vec![
                        Amount::from_sats(1),
                        Amount::from_sats(10),
                        Amount::from_sats(20),
                    ],
                })
                .expect("Invalid mint config"),
                &MintGen,
                module_id,
            )
            .await
            .unwrap(),
        ));

        let api = make_test_mint_fed(module_id, fed.clone()).await;

        let client_config = fed.lock().await.client_cfg().clone();

        let client_context = ClientContext {
            decoders: ModuleDecoderRegistry::from_iter([(
                module_id,
                <Mint as ServerModule>::decoder(),
            )]),
            module_gens: Default::default(),
            db: Database::new(MemDatabase::new(), module_decode_stubs()),
            api: api.into(),
            secp: secp256k1_zkp::Secp256k1::new(),
        };

        (fed, client_config.cast().unwrap(), client_context)
    }

    async fn issue_notes<'a>(
        fed: &'a tokio::sync::Mutex<Fed>,
        client: &'a MintClient,
        _client_db: &'a Database,
        amt: Amount,
    ) {
        let txid = TransactionId::from_inner([0x42; 32]);
        let out_point = OutPoint { txid, out_idx: 0 };

        let (output, callback) = block_on(client.receive_notes(amt));
        {
            let mut fed = block_on(fed.lock());
            block_on(fed.consensus_round(&[], &[(out_point, MintOutput(output))]));
            // Generate signatures
            block_on(fed.consensus_round(&[], &[]));
        }
        callback(out_point);

        client.fetch_all_notes().await;
    }

    #[test_log::test(tokio::test)]
    async fn create_output() {
        let (fed, client_config, client_context) = new_mint_and_client().await;

        let context = Arc::new(client_context);
        let client = MintClient {
            epoch_pk: threshold_crypto::SecretKey::random().public_key(),
            config: client_config,
            context: context.clone(),
            secret: DerivableSecret::new_root(&[], &[]).child_key(MINT_SECRET_CHILD_ID),
        };

        const ISSUE_AMOUNT: Amount = Amount::from_sats(12);
        issue_notes(&fed, &client, &context.db, ISSUE_AMOUNT).await;

        assert_eq!(client.summary().await.total_amount(), ISSUE_AMOUNT)
    }

    fn notes_distribution(summary: &TieredSummary) -> Vec<(Amount, usize)> {
        summary.iter().collect::<Vec<_>>()
    }

    #[test_log::test(tokio::test)]
    async fn create_input() {
        const SPEND_AMOUNT: Amount = Amount::from_sats(21);

        let (fed, client_config, client_context) = new_mint_and_client().await;

        let context = Arc::new(client_context);
        let client = MintClient {
            epoch_pk: threshold_crypto::SecretKey::random().public_key(),
            config: client_config,
            context: context.clone(),
            secret: DerivableSecret::new_root(&[], &[]).child_key(MINT_SECRET_CHILD_ID),
        };

        issue_notes(&fed, &client, &context.db, SPEND_AMOUNT * 2).await;
        let summary = client.summary().await;
        let notes = client.notes().await;
        assert_eq!(notes.total_amount(), SPEND_AMOUNT * 2);
        assert_eq!(summary.total_amount(), notes.total_amount());
        assert_eq!(
            notes_distribution(&summary),
            vec![
                (Amount::from_sats(1), 2),
                (Amount::from_sats(10), 2),
                (Amount::from_sats(20), 1)
            ]
        );

        // Spending works
        let mut dbtx = client.context.db.begin_transaction().await;
        let mut builder = TransactionBuilder::default();
        let secp = &client.context.secp;
        let _tbs_pks = &client.config.tbs_pks;
        let rng = rand::rngs::OsRng;
        let notes = client.select_notes(SPEND_AMOUNT).await.unwrap();
        let summary = notes.summary();
        assert_eq!(
            notes_distribution(&summary),
            vec![(Amount::from_sats(1), 1), (Amount::from_sats(20), 1)]
        );
        let (spend_keys, ecash_input) = MintClient::ecash_input(notes.clone()).unwrap();

        builder.input(&mut spend_keys.clone(), ecash_input.clone());
        let client = &client;
        builder
            .build_with_change(
                client.clone(),
                &mut dbtx,
                rng,
                vec![Amount::from_sats(0)],
                secp,
            )
            .await;
        dbtx.commit_tx().await;

        if let Input::Mint(input) = ecash_input {
            let meta = fed.lock().await.verify_input(&input).await.unwrap();
            assert_eq!(meta.amount.amount, SPEND_AMOUNT);
            assert_eq!(
                meta.keys,
                spend_keys
                    .into_iter()
                    .map(|key| secp256k1_zkp::XOnlyPublicKey::from_keypair(&key).0)
                    .collect::<Vec<_>>()
            );

            fed.lock()
                .await
                .consensus_round(&[input.clone()], &[])
                .await;
            let summary = client.summary().await;
            // The right amount of money is left
            assert_eq!(summary.total_amount(), SPEND_AMOUNT);
            assert_eq!(
                notes_distribution(&summary),
                vec![(Amount::from_sats(1), 1), (Amount::from_sats(10), 2)]
            );

            // Double spends aren't possible
            assert!(fed.lock().await.verify_input(&input).await.is_err());
        }

        // We can exactly spend the remainder
        let mut dbtx = client.context.db.begin_transaction().await;
        let mut builder = TransactionBuilder::default();
        let notes = client.select_notes(SPEND_AMOUNT).await.unwrap();
        let summary = client.summary().await;
        assert_eq!(
            notes_distribution(&summary),
            vec![(Amount::from_sats(1), 1), (Amount::from_sats(10), 2)]
        );
        let rng = rand::rngs::OsRng;
        let (spend_keys, ecash_input) = MintClient::ecash_input(notes).unwrap();

        builder.input(&mut spend_keys.clone(), ecash_input.clone());
        builder
            .build_with_change(
                client.clone(),
                &mut dbtx,
                rng,
                vec![Amount::from_sats(0)],
                secp,
            )
            .await;
        dbtx.commit_tx().await;

        if let Input::Mint(input) = ecash_input {
            let meta = fed.lock().await.verify_input(&input).await.unwrap();
            assert_eq!(meta.amount.amount, SPEND_AMOUNT);
            assert_eq!(
                meta.keys,
                spend_keys
                    .into_iter()
                    .map(|key| secp256k1_zkp::XOnlyPublicKey::from_keypair(&key).0)
                    .collect::<Vec<_>>()
            );

            // No money is left
            assert_eq!(client.summary().await.total_amount(), Amount::ZERO);
        }
    }

    #[allow(clippy::needless_collect)]
    #[tokio::test(flavor = "multi_thread")]
    async fn test_parallel_issuance() {
        const ITERATIONS: usize = 10_000;

        let db = fedimint_rocksdb::RocksDb::open(tempfile::tempdir().unwrap()).unwrap();

        let module_id = LEGACY_HARDCODED_INSTANCE_ID_MINT;

        let client: MintClient = MintClient {
            epoch_pk: threshold_crypto::SecretKey::random().public_key(),
            config: MintClientConfig {
                tbs_pks: Tiered::from_iter([]),
                fee_consensus: Default::default(),
                peer_tbs_pks: BTreeMap::default(),
                max_notes_per_denomination: 0,
            },
            context: Arc::new(ClientContext {
                decoders: ModuleDecoderRegistry::from_iter([(
                    module_id,
                    <Mint as ServerModule>::decoder(),
                )]),
                module_gens: Default::default(),
                db: Database::new(db, module_decode_stubs()),
                api: WsFederationApi::new(vec![]).into(),
                secp: Default::default(),
            }),
            secret: DerivableSecret::new_root(&[], &[]).child_key(MINT_SECRET_CHILD_ID),
        };
        let client_copy = client.clone();
        let amount = Amount::from_msats(1);

        let issuance_thread = move || {
            (0..ITERATIONS)
                .filter_map({
                    |_| {
                        let client = client_copy.clone();
                        block_on(async {
                            let mut dbtx = client.context.db.begin_transaction().await;
                            let (_, nonce) = client
                                .new_ecash_note(secp256k1_zkp::SECP256K1, amount, &mut dbtx)
                                .await;
                            dbtx.commit_tx_result().await.map(|_| nonce).ok()
                        })
                    }
                })
                .collect::<Vec<BlindNonce>>()
        };

        let threads = (0..4)
            .map(|_| std::thread::spawn(issuance_thread.clone()))
            .collect::<Vec<_>>();
        let results = threads
            .into_iter()
            .flat_map(|t| {
                let output = t.join().unwrap();
                // Most threads will have produces far less than ITERATIONS items notes due to
                // database transactions failing
                output
            })
            .collect::<Vec<_>>();

        let result_count = results.len();
        let result_count_deduplicated = results.into_iter().collect::<HashSet<_>>().len();

        // Ensure all notes are unique
        assert_eq!(result_count, result_count_deduplicated);

        let last_idx = client
            .context
            .db
            .begin_transaction()
            .await
            .get_value(&NextECashNoteIndexKey(amount))
            .await
            .unwrap_or(0);
        // Ensure we didn't skip any keys
        assert_eq!(last_idx, result_count as u64);
    }

    #[test_log::test(tokio::test)]
    async fn select_notes_avg_test() {
        let max_amount = Amount::from_sats(1000000);
        let tiers = Tiered::gen_denominations(max_amount);
        let tiered =
            TieredSummary::represent_amount::<()>(max_amount, &Default::default(), &tiers, 3);

        let mut total_notes = 0;
        for multiplier in 1..100 {
            let stream = reverse_sorted_note_stream(tiered.iter().collect());
            let select =
                MintClient::select_notes_from_stream(stream, Amount::from_sats(multiplier * 1000))
                    .await;
            total_notes += select.unwrap().into_iter_items().count();
        }
        assert_eq!(total_notes / 100, 10);
    }

    #[test_log::test(tokio::test)]
    async fn select_notes_returns_exact_amount_with_minimum_notes() {
        let f = || {
            reverse_sorted_note_stream(vec![
                (Amount::from_sats(1), 10),
                (Amount::from_sats(5), 10),
                (Amount::from_sats(20), 10),
            ])
        };
        assert_eq!(
            MintClient::select_notes_from_stream(f(), Amount::from_sats(7))
                .await
                .unwrap(),
            notes(vec![(Amount::from_sats(1), 2), (Amount::from_sats(5), 1)])
        );
        assert_eq!(
            MintClient::select_notes_from_stream(f(), Amount::from_sats(20))
                .await
                .unwrap(),
            notes(vec![(Amount::from_sats(20), 1)])
        );
    }

    #[test_log::test(tokio::test)]
    async fn select_notes_returns_next_smallest_amount_if_exact_change_cannot_be_made() {
        let stream = reverse_sorted_note_stream(vec![
            (Amount::from_sats(1), 1),
            (Amount::from_sats(5), 5),
            (Amount::from_sats(20), 5),
        ]);
        assert_eq!(
            MintClient::select_notes_from_stream(stream, Amount::from_sats(7))
                .await
                .unwrap(),
            notes(vec![(Amount::from_sats(5), 2)])
        );
    }

    #[test_log::test(tokio::test)]
    async fn select_notes_uses_big_note_if_small_amounts_are_not_sufficient() {
        let stream = reverse_sorted_note_stream(vec![
            (Amount::from_sats(1), 3),
            (Amount::from_sats(5), 3),
            (Amount::from_sats(20), 2),
        ]);
        assert_eq!(
            MintClient::select_notes_from_stream(stream, Amount::from_sats(39))
                .await
                .unwrap(),
            notes(vec![(Amount::from_sats(20), 2)])
        );
    }

    #[test_log::test(tokio::test)]
    async fn select_notes_returns_error_if_amount_is_too_large() {
        let stream = reverse_sorted_note_stream(vec![(Amount::from_sats(10), 1)]);
        match MintClient::select_notes_from_stream(stream, Amount::from_sats(100))
            .await
            .unwrap_err()
        {
            MintClientError::InsufficientBalance(_, total) => {
                assert_eq!(total, Amount::from_sats(10))
            }
            other => panic!("Unexpected error: {other:?}"),
        };
    }

    fn reverse_sorted_note_stream(
        notes: Vec<(Amount, usize)>,
    ) -> impl futures::Stream<Item = (Amount, String)> {
        futures::stream::iter(
            notes
                .into_iter()
                // We are creating `number` dummy notes of `amount` value
                .flat_map(|(amount, number)| vec![(amount, "dummy note".into()); number])
                .sorted()
                .rev(),
        )
    }

    fn notes(notes: Vec<(Amount, usize)>) -> TieredMulti<String> {
        notes
            .into_iter()
            .flat_map(|(amount, number)| vec![(amount, "dummy note".into()); number])
            .collect()
    }
}
