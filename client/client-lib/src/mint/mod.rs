pub mod db;

use std::fmt;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use db::{NoteKey, NoteKeyPrefix, OutputFinalizationKey, OutputFinalizationKeyPrefix};
use fedimint_api::core::client::ClientModule;
use fedimint_api::db::DatabaseTransaction;
use fedimint_api::encoding::{Decodable, Encodable};
use fedimint_api::module::registry::ModuleDecoderRegistry;
use fedimint_api::module::TransactionItemAmount;
use fedimint_api::tiered::InvalidAmountTierError;
use fedimint_api::{Amount, OutPoint, ServerModule, Tiered, TieredMulti, TransactionId};
use fedimint_core::api::{GlobalFederationApi, MemberError, OutputOutcomeError};
use futures::{Future, StreamExt};
use secp256k1_zkp::{KeyPair, Secp256k1, Signing};
use serde::{Deserialize, Serialize};
use tbs::{blind_message, unblind_signature, AggregatePublicKey, BlindedSignature, BlindingKey};
use thiserror::Error;
use tracing::{debug, error, trace, warn};

use crate::mint::db::{NextECashNoteIndexKey, NotesPerDenominationKey, PendingNotesKey};
use crate::modules::mint::config::MintClientConfig;
use crate::modules::mint::{
    BlindNonce, Mint, MintInput, MintOutput, MintOutputBlindSignatures, MintOutputOutcome, Nonce,
    Note,
};
use crate::outcome::legacy::OutputOutcome;
use crate::transaction::legacy::{Input, Output, Transaction};
use crate::utils::ClientContext;
use crate::{ChildId, DerivableSecret, FuturesUnordered, MintDecoder};

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
    type Decoder = <Mint as ServerModule>::Decoder;
    type Module = Mint;

    fn decoder(&self) -> Self::Decoder {
        MintDecoder
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
                    let spendable = dbtx
                        .get_value(&key)
                        .await
                        .expect("DB Error")
                        .expect("Missing note");
                    input_ecash.push((amount, spendable));
                    dbtx.remove_entry(&key).await.expect("DB Error");
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
            dbtx.insert_entry(&PendingNotesKey(txid), &pending)
                .await
                .expect("DB Error");
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
            .await
            .expect("DB Error");
        }
    }

    pub async fn set_notes_per_denomination(&self, notes: u16) {
        let mut dbtx = self.start_dbtx().await;
        dbtx.insert_entry(&NotesPerDenominationKey, &notes)
            .await
            .expect("DB error");
        dbtx.commit_tx().await.expect("DB error");
    }

    async fn notes_per_denomination(&self, dbtx: &mut DatabaseTransaction<'_>) -> u16 {
        dbtx.get_value(&NotesPerDenominationKey)
            .await
            .expect("DB Error")
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
        let denominations = TieredMulti::represent_amount(
            amount,
            &self.notes().await,
            &self.config.tbs_pks,
            notes_per_denomination,
        );
        for (amt, num) in denominations.iter() {
            for _ in 0..*num {
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
                    Err(MintClientError::ReceivedUspendableNote)
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
            .map(|res| {
                let (key, spendable_note) = res.expect("DB error");
                (key.amount, spendable_note)
            })
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
            .map(|res| {
                let (key, spendable_note) = res.expect("DB error");
                (key.amount, spendable_note)
            })
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
                .expect("DB error")
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
            .await
            .expect("DB Error");
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

    pub async fn select_notes(&self, amount: Amount) -> Result<TieredMulti<SpendableNote>> {
        let notes = self.notes().await;
        let selected_notes = notes.select_notes(amount).ok_or_else(|| {
            MintClientError::InsufficientBalance(amount, TieredMulti::total_amount(&notes))
        })?;

        Ok(selected_notes)
    }

    pub async fn receive_notes<'a, F, Fut>(
        &self,
        amount: Amount,
        dbtx: &mut DatabaseTransaction<'a>,
        mut create_tx: F,
    ) where
        F: FnMut(TieredMulti<BlindNonce>) -> Fut,
        Fut: futures::Future<Output = OutPoint>,
    {
        let notes_per_denomination = self.notes_per_denomination(dbtx).await;
        let (finalization, notes) = self
            .create_ecash(amount, notes_per_denomination, dbtx)
            .await;
        let out_point = create_tx(notes).await;
        dbtx.insert_new_entry(&OutputFinalizationKey(out_point), &finalization)
            .await
            .expect("DB Error");
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
                    fedimint_api::task::sleep(retry_duration).await
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
            .expect("DB error")
            .ok_or(MintClientError::FinalizationError(
                NoteFinalizationError::UnknownIssuance,
            ))?;

        let bsig = self
            .context
            .api
            .fetch_output_outcome::<OutputOutcome>(outpoint, &self.context.decoders)
            .await?
            .try_into_variant::<MintOutputOutcome>()?
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
            dbtx.insert_new_entry(&key, &value).await.expect("DB Error");
        }
        dbtx.remove_entry(&OutputFinalizationKey(outpoint))
            .await
            .expect("DB Error");

        Ok(())
    }

    pub async fn list_active_issuances(&self) -> Vec<(OutPoint, NoteIssuanceRequests)> {
        self.context
            .db
            .begin_transaction()
            .await
            .find_by_prefix(&OutputFinalizationKeyPrefix)
            .await
            .map(|res| {
                let (OutputFinalizationKey(outpoint), cfd) = res.expect("DB error");
                (outpoint, cfd)
            })
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
                dbtx.commit_tx().await.expect("DB Error");
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
    ReceivedUspendableNote,
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
    use fedimint_api::config::ConfigGenParams;
    use fedimint_api::core::{
        DynOutputOutcome, ModuleInstanceId, LEGACY_HARDCODED_INSTANCE_ID_MINT,
    };
    use fedimint_api::db::mem_impl::MemDatabase;
    use fedimint_api::db::Database;
    use fedimint_api::module::registry::ModuleDecoderRegistry;
    use fedimint_api::{Amount, OutPoint, Tiered, TransactionId};
    use fedimint_core::api::WsFederationApi;
    use fedimint_core::outcome::{SerdeOutputOutcome, TransactionStatus};
    use fedimint_mint::common::MintDecoder;
    use fedimint_testing::FakeFed;
    use futures::executor::block_on;
    use tokio::sync::Mutex;

    use crate::api::fake::FederationApiFaker;
    use crate::mint::db::NextECashNoteIndexKey;
    use crate::mint::MintClient;
    use crate::modules::mint::config::MintClientConfig;
    use crate::modules::mint::{Mint, MintGen, MintGenParams, MintOutput};
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
        FederationApiFaker::new(fed, members).with(
            "/fetch_transaction",
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
                &ConfigGenParams::new().attach(MintGenParams {
                    mint_amounts: vec![
                        Amount::from_sats(1),
                        Amount::from_sats(10),
                        Amount::from_sats(20),
                    ],
                }),
                &MintGen,
                module_id,
            )
            .await
            .unwrap(),
        ));

        let api = make_test_mint_fed(module_id, fed.clone()).await;

        let client_config = fed.lock().await.client_cfg().clone();

        let client_context = ClientContext {
            decoders: ModuleDecoderRegistry::from_iter([(module_id, MintDecoder.into())]),
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
        client_db: &'a Database,
        amt: Amount,
    ) {
        let txid = TransactionId::from_inner([0x42; 32]);
        let out_point = OutPoint { txid, out_idx: 0 };

        let mut dbtx = client_db.begin_transaction().await;
        client
            .receive_notes(amt, &mut dbtx, |output| async {
                // Agree on output
                let mut fed = block_on(fed.lock());
                block_on(fed.consensus_round(&[], &[(out_point, MintOutput(output))]));
                // Generate signatures
                block_on(fed.consensus_round(&[], &[]));

                out_point
            })
            .await;
        dbtx.commit_tx().await.expect("DB Error");

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

        assert_eq!(client.notes().await.total_amount(), ISSUE_AMOUNT)
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

        // Spending works
        let mut dbtx = client.context.db.begin_transaction().await;
        let mut builder = TransactionBuilder::default();
        let secp = &client.context.secp;
        let _tbs_pks = &client.config.tbs_pks;
        let rng = rand::rngs::OsRng;
        let notes = client.select_notes(SPEND_AMOUNT).await.unwrap();
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
        dbtx.commit_tx().await.expect("DB Error");

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

            // The right amount of money is left
            assert_eq!(client.notes().await.total_amount(), SPEND_AMOUNT);

            // Double spends aren't possible
            assert!(fed.lock().await.verify_input(&input).await.is_err());
        }

        // We can exactly spend the remainder
        let mut dbtx = client.context.db.begin_transaction().await;
        let mut builder = TransactionBuilder::default();
        let notes = client.select_notes(SPEND_AMOUNT).await.unwrap();
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
        dbtx.commit_tx().await.expect("DB Error");

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
            assert_eq!(client.notes().await.total_amount(), Amount::ZERO);
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
                decoders: ModuleDecoderRegistry::from_iter([(module_id, MintDecoder.into())]),
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
                            dbtx.commit_tx().await.map(|_| nonce).ok()
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
                output.len();
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
            .expect("DB error")
            .unwrap_or(0);
        // Ensure we didn't skip any keys
        assert_eq!(last_idx, result_count as u64);
    }
}
