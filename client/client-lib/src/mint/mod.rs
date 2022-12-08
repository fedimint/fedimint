pub mod db;
pub mod decode_stub;

use std::borrow::Cow;
use std::sync::Arc;
use std::time::Duration;

use db::{CoinKey, CoinKeyPrefix, OutputFinalizationKey, OutputFinalizationKeyPrefix};
use fedimint_api::core::client::ClientModulePlugin;
use fedimint_api::core::{ModuleKey, MODULE_KEY_MINT};
use fedimint_api::db::DatabaseTransaction;
use fedimint_api::encoding::{Decodable, Encodable, ModuleRegistry};
use fedimint_api::module::TransactionItemAmount;
use fedimint_api::tiered::InvalidAmountTierError;
use fedimint_api::{Amount, OutPoint, ServerModulePlugin, Tiered, TieredMulti, TransactionId};
use fedimint_core::modules::mint::config::MintClientConfig;
use fedimint_core::modules::mint::{
    BlindNonce, Mint, MintInput, MintOutput, MintOutputOutcome, Nonce, Note, OutputOutcome,
};
use fedimint_core::transaction::legacy::{Input, Output, Transaction};
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use secp256k1_zkp::{KeyPair, Secp256k1, Signing};
use serde::de::Error;
use serde::{Deserialize, Serialize};
use tbs::{blind_message, unblind_signature, AggregatePublicKey, BlindedSignature, BlindingKey};
use thiserror::Error;
use tracing::{debug, trace, warn};

use crate::api::ApiError;
use crate::mint::db::{NextECashNoteIndexKey, PendingCoinsKey};
use crate::utils::ClientContext;
use crate::{ChildId, DerivableSecret};

pub mod backup;

const MINT_E_CASH_TYPE_CHILD_ID: ChildId = ChildId(0);

/// Federation module client for the Mint module. It can both create transaction inputs and outputs
/// of the mint type.
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

/// Single [`Note`] issuance request to the mint.
///
/// Keeps the data to generate [`SpendableNote`] once the
/// mint successfully processed the transaction signing the corresponding [`BlindNonce`].
#[derive(Debug, Clone, Deserialize, Serialize, Encodable, Decodable)]
pub struct NoteIssuanceRequest {
    /// Spend key from which the coin nonce (corresponding public key) is derived
    spend_key: KeyPair,
    /// Key to unblind the blind signature supplied by the mint for this coin
    blinding_key: BlindingKey,
}

impl NoteIssuanceRequest {
    pub fn finalize(
        &self,
        bsig: BlindedSignature,
        mint_pub_key: AggregatePublicKey,
    ) -> std::result::Result<SpendableNote, CoinFinalizationError> {
        let sig = unblind_signature(self.blinding_key, bsig);
        let note = Note(self.nonce(), sig);
        if note.verify(mint_pub_key) {
            let spendable_note = SpendableNote {
                note,
                spend_key: self.spend_key,
            };

            Ok(spendable_note)
        } else {
            Err(CoinFinalizationError::InvalidSignature)
        }
    }
}
/// Multiple [`Note`] issuance requests
///
/// Keeps all the data to generate [`SpendableNote`]s once the
/// mint successfully processed corresponding [`NoteIssuanceRequest`]s.
#[derive(Debug, Clone, Default, Deserialize, Serialize, Encodable, Decodable)]
pub struct NoteIssuanceRequests {
    /// Finalization data for all coin outputs in this request
    coins: TieredMulti<NoteIssuanceRequest>,
}

/// A [`Note`] with associated secret key that allows to proof ownership (spend it)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct SpendableNote {
    pub note: Note,
    #[serde(deserialize_with = "deserialize_key_pair")]
    pub spend_key: KeyPair,
}

impl ClientModulePlugin for MintClient {
    type Decoder = <Mint as ServerModulePlugin>::Decoder;
    type Module = Mint;
    const MODULE_KEY: ModuleKey = MODULE_KEY_MINT;

    fn input_amount(
        &self,
        input: &<Self::Module as ServerModulePlugin>::Input,
    ) -> TransactionItemAmount {
        TransactionItemAmount {
            amount: input.total_amount(),
            fee: self.config.fee_consensus.coin_spend_abs * (input.item_count() as u64),
        }
    }

    fn output_amount(
        &self,
        output: &<Self::Module as ServerModulePlugin>::Output,
    ) -> TransactionItemAmount {
        TransactionItemAmount {
            amount: output.total_amount(),
            fee: self.config.fee_consensus.coin_issuance_abs * (output.item_count() as u64),
        }
    }
}

impl MintClient {
    pub async fn start_dbtx(&self) -> DatabaseTransaction<'_> {
        self.context
            .db
            .begin_transaction(ModuleRegistry::default())
            .await
    }

    /// Adds the final amounts of `change` to the tx before submitting it
    /// Allows for multiple `change` outputs
    pub async fn finalize_change(&self, tx: &mut Transaction, change: Vec<Amount>) {
        let mut change_outputs: Vec<(usize, NoteIssuanceRequests)> = vec![];

        for amount in change {
            let (issuances, nonces) = self.create_output_coins(amount).await;
            let out_idx = tx.outputs.len();
            tx.outputs.push(Output::Mint(MintOutput(nonces)));
            change_outputs.push((out_idx, issuances));
        }
        let txid = tx.tx_hash();

        let mut dbtx = self
            .context
            .db
            .begin_transaction(ModuleRegistry::default())
            .await;

        // remove the spent ecash from the DB
        let mut input_ecash: Vec<(Amount, SpendableNote)> = vec![];
        for input in &tx.inputs {
            if let Input::Mint(MintInput(notes)) = input {
                for (amount, note) in notes.clone() {
                    let key = CoinKey {
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

        // move ecash to pending state, awaiting a transaction
        if !input_ecash.is_empty() {
            let pending = TieredMulti::from_iter(input_ecash.into_iter());
            dbtx.insert_entry(&PendingCoinsKey(txid), &pending)
                .await
                .expect("DB Error");
        }

        // write ecash outputs to db to await for tx success to be fetched later
        for (out_idx, coins) in change_outputs.iter() {
            dbtx.insert_new_entry(
                &OutputFinalizationKey(OutPoint {
                    txid,
                    out_idx: *out_idx as u64,
                }),
                &coins.clone(),
            )
            .await
            .expect("DB Error");
        }

        dbtx.commit_tx().await.expect("DB Error");
    }

    async fn create_output_coins(
        &self,
        amount: Amount,
    ) -> (NoteIssuanceRequests, TieredMulti<BlindNonce>) {
        let mut amount_requests: Vec<((Amount, NoteIssuanceRequest), (Amount, BlindNonce))> =
            Vec::new();
        for (amt, ()) in TieredMulti::represent_amount(amount, &self.config.tbs_pks).into_iter() {
            let (request, blind_nonce) = self.new_ecash_note(&self.context.secp, amt).await;
            amount_requests.push(((amt, request), (amt, blind_nonce)));
        }
        let (coin_finalization_data, sig_req): (NoteIssuanceRequests, MintOutput) =
            amount_requests.into_iter().unzip();

        debug!(
            %amount,
            coins = %sig_req.0.item_count(),
            tiers = ?sig_req.0.tiers().collect::<Vec<_>>(),
            "Generated issuance request"
        );

        (coin_finalization_data, sig_req.0)
    }

    pub async fn select_input(&self, amount: Amount) -> Result<(Vec<KeyPair>, Input)> {
        Self::ecash_input(self.select_coins(amount).await?)
    }

    pub fn ecash_input(ecash: TieredMulti<SpendableNote>) -> Result<(Vec<KeyPair>, Input)> {
        let note_key_pairs = ecash
            .into_iter()
            .map(|(amt, note)| {
                // We check for note validity in case we got it from an untrusted third party. We
                // don't want to needlessly create invalid tx and bother the federation with them.
                let spend_pub_key = note.spend_key.x_only_public_key().0;
                if &spend_pub_key == note.note.spend_key() {
                    Ok((note.spend_key, (amt, note.note)))
                } else {
                    Err(MintClientError::ReceivedUspendableCoin)
                }
            })
            .collect::<Result<Vec<_>>>()?;
        let (key_pairs, input) = note_key_pairs.into_iter().unzip();
        Ok((key_pairs, Input::Mint(MintInput(input))))
    }

    pub async fn coins(&self) -> TieredMulti<SpendableNote> {
        self.start_dbtx()
            .await
            .find_by_prefix(&CoinKeyPrefix)
            .await
            .map(|res| {
                let (key, spendable_coin) = res.expect("DB error");
                (key.amount, spendable_coin)
            })
            .collect()
    }

    /// Get available spendable notes with a db transaction already opened
    pub async fn get_available_notes(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
    ) -> TieredMulti<SpendableNote> {
        dbtx.find_by_prefix(&CoinKeyPrefix)
            .await
            .map(|res| {
                let (key, spendable_coin) = res.expect("DB error");
                (key.amount, spendable_coin)
            })
            .collect()
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

    async fn new_note_secret(&self, amount: Amount) -> DerivableSecret {
        let mut new_idx;
        loop {
            let mut dbtx = self.start_dbtx().await;
            new_idx = self.get_next_note_index(&mut dbtx, amount).await;
            dbtx.insert_entry(&NextECashNoteIndexKey(amount), &new_idx.next().as_u64())
                .await
                .expect("DB error");
            if dbtx.commit_tx().await.is_ok() {
                break;
            }
        }

        Self::new_note_secret_static(&self.secret, amount, new_idx)
    }

    /// Derive the note `DerivableSecret` from the Mint's `secret` the `amount` tier and `note_idx`
    ///
    /// Static to help re-use in other places, that don't have a whole [`Self`] available
    pub fn new_note_secret_static(
        secret: &DerivableSecret,
        amount: Amount,
        note_idx: NoteIndex,
    ) -> DerivableSecret {
        secret
            .child_key(MINT_E_CASH_TYPE_CHILD_ID) // TODO: cache
            .child_key(ChildId(amount.milli_sat))
            .child_key(ChildId(note_idx.as_u64()))
            .child_key(ChildId(amount.milli_sat))
    }

    pub async fn new_ecash_note<C: Signing>(
        &self,
        ctx: &Secp256k1<C>,
        amount: Amount,
    ) -> (NoteIssuanceRequest, BlindNonce) {
        let secret = self.new_note_secret(amount).await;
        NoteIssuanceRequest::new(ctx, secret)
    }

    pub async fn select_coins(&self, amount: Amount) -> Result<TieredMulti<SpendableNote>> {
        let coins = self.coins().await;
        let selected_coins = coins.select_coins(amount).ok_or_else(|| {
            MintClientError::InsufficientBalance(amount, TieredMulti::total_amount(&coins))
        })?;

        Ok(selected_coins)
    }

    pub async fn receive_coins<'a, F, Fut>(
        &self,
        amount: Amount,
        dbtx: &mut DatabaseTransaction<'a>,
        mut create_tx: F,
    ) where
        F: FnMut(TieredMulti<BlindNonce>) -> Fut,
        Fut: futures::Future<Output = OutPoint>,
    {
        let (finalization, coins) = self.create_output_coins(amount).await;
        let out_point = create_tx(coins).await;
        dbtx.insert_new_entry(&OutputFinalizationKey(out_point), &finalization)
            .await
            .expect("DB Error");
    }

    pub async fn fetch_coins<'a>(
        &self,
        dbtx: &mut DatabaseTransaction<'a>,
        outpoint: OutPoint,
    ) -> Result<()> {
        let issuance = self
            .context
            .db
            .begin_transaction(ModuleRegistry::default())
            .await
            .get_value(&OutputFinalizationKey(outpoint))
            .await
            .expect("DB error")
            .ok_or(MintClientError::FinalizationError(
                CoinFinalizationError::UnknownIssuance,
            ))?;

        let bsig = self
            .context
            .api
            .fetch_output_outcome::<MintOutputOutcome>(outpoint)
            .await?
            .as_ref()
            .cloned()
            .ok_or(MintClientError::OutputNotReadyYet(outpoint))?;

        let coins = issuance.finalize(bsig, &self.config.tbs_pks)?;

        for (amount, coin) in coins.into_iter() {
            let key = CoinKey {
                amount,
                nonce: coin.note.0,
            };
            let value = coin;
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
            .begin_transaction(ModuleRegistry::default())
            .await
            .find_by_prefix(&OutputFinalizationKeyPrefix)
            .await
            .map(|res| {
                let (OutputFinalizationKey(outpoint), cfd) = res.expect("DB error");
                (outpoint, cfd)
            })
            .collect()
    }

    pub async fn fetch_all_coins(&self) -> Vec<Result<OutPoint>> {
        let active_issuances = self.list_active_issuances().await;
        if active_issuances.is_empty() {
            return Vec::new();
        }

        let stream = active_issuances
            .into_iter()
            .map(|(out_point, _)| async move {
                let mut dbtx = self
                    .context
                    .db
                    .begin_transaction(ModuleRegistry::default())
                    .await;
                loop {
                    match self.fetch_coins(&mut dbtx, out_point).await {
                        Ok(_) => {
                            dbtx.commit_tx().await.expect("DB Error");
                            return Ok(out_point);
                        }
                        // TODO: make mint error more expressive (currently any HTTP error) and maybe use custom return type instead of error for retrying
                        Err(e) if e.is_retryable() => {
                            trace!("Mint returned retryable error: {:?}", e);
                            fedimint_api::task::sleep(Duration::from_secs(1)).await
                        }
                        Err(e) => {
                            warn!("Mint returned error: {:?}", e);
                            return Err(e);
                        }
                    }
                }
            })
            .collect::<FuturesUnordered<_>>();
        stream.collect::<Vec<Result<_>>>().await
    }
}

impl Extend<(Amount, NoteIssuanceRequest)> for NoteIssuanceRequests {
    fn extend<T: IntoIterator<Item = (Amount, NoteIssuanceRequest)>>(&mut self, iter: T) {
        self.coins.extend(iter)
    }
}

impl NoteIssuanceRequests {
    /// Finalize the issuance request using a [`OutputOutcome`] from the mint containing the blind
    /// signatures for all coins in this `IssuanceRequest`. It also takes the mint's
    /// [`AggregatePublicKey`] to validate the supplied blind signatures.
    pub fn finalize(
        &self,
        bsigs: OutputOutcome,
        mint_pub_key: &Tiered<AggregatePublicKey>,
    ) -> std::result::Result<TieredMulti<SpendableNote>, CoinFinalizationError> {
        if !self.coins.structural_eq(&bsigs.0) {
            return Err(CoinFinalizationError::WrongMintAnswer);
        }

        self.coins
            .iter_items()
            .zip(bsigs.0)
            .enumerate()
            .map(|(idx, ((amt, coin_req), (_amt, bsig)))| {
                Ok((
                    amt,
                    match coin_req.finalize(bsig, *mint_pub_key.tier(&amt)?) {
                        Err(CoinFinalizationError::InvalidSignature) => {
                            Err(CoinFinalizationError::InvalidSignatureAtIdx(idx))
                        }
                        other => other,
                    }?,
                ))
            })
            .collect()
    }

    pub fn coin_count(&self) -> usize {
        self.coins.item_count()
    }

    pub fn coin_amount(&self) -> Amount {
        self.coins.total_amount()
    }
}

impl NoteIssuanceRequest {
    /// Generate a request session for a single coin and returns it plus the corresponding blinded
    /// message
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
pub enum CoinFinalizationError {
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
    ApiError(#[from] ApiError),
    #[error("Could not finalize issuance request: {0}")]
    FinalizationError(#[from] CoinFinalizationError),
    #[error("Insufficient balance. Amount requested={0} Mint balance={1}")]
    InsufficientBalance(Amount, Amount),
    #[error("The transaction outcome received from the mint did not contain a result for output {0} yet")]
    OutputNotReadyYet(OutPoint),
    #[error("The transaction outcome returned by the mint contains too few outputs (output {0})")]
    InvalidOutcomeWrongStructure(OutPoint),
    #[error("The transaction outcome returned by the mint has an invalid type (output {0})")]
    InvalidOutcomeType(OutPoint),
    #[error("One of the coins meant to be spent is unspendable")]
    ReceivedUspendableCoin,
}

impl MintClientError {
    /// Returns `true` if queried outpoint isn't ready yet but may become ready later
    pub fn is_retryable(&self) -> bool {
        match self {
            MintClientError::ApiError(e) => e.is_retryable(),
            MintClientError::OutputNotReadyYet(_) => true,
            _ => false,
        }
    }
}

impl From<InvalidAmountTierError> for CoinFinalizationError {
    fn from(e: InvalidAmountTierError) -> Self {
        CoinFinalizationError::InvalidAmountTier(e.0)
    }
}

// TODO: remove once rust-bitcoin/rust-secp256k1#491 is fixed
fn deserialize_key_pair<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<KeyPair, D::Error> {
    if d.is_human_readable() {
        let hex_bytes: Cow<'_, str> = Deserialize::deserialize(d)?;
        let bytes = hex::decode(hex_bytes.as_ref()).map_err(|_| D::Error::custom("Invalid hex"))?;
        KeyPair::from_seckey_slice(secp256k1_zkp::SECP256K1, &bytes)
            .map_err(|_| D::Error::custom("Not a valid private key"))
    } else {
        let bytes: [u8; 32] = Deserialize::deserialize(d)?;
        KeyPair::from_seckey_slice(secp256k1_zkp::SECP256K1, &bytes)
            .map_err(|_| D::Error::custom("Not a valid private key"))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::sync::Arc;

    use async_trait::async_trait;
    use bitcoin::hashes::Hash;
    use bitcoin::Address;
    use fedimint_api::backup::SignedBackupRequest;
    use fedimint_api::config::ModuleConfigGenParams;
    use fedimint_api::db::mem_impl::MemDatabase;
    use fedimint_api::db::Database;
    use fedimint_api::encoding::ModuleRegistry;
    use fedimint_api::{Amount, OutPoint, Tiered, TransactionId};
    use fedimint_core::epoch::EpochHistory;
    use fedimint_core::modules::ln::contracts::incoming::IncomingContractOffer;
    use fedimint_core::modules::ln::contracts::ContractId;
    use fedimint_core::modules::ln::{ContractAccount, LightningGateway};
    use fedimint_core::modules::mint::config::MintClientConfig;
    use fedimint_core::modules::mint::{Mint, MintConfigGenerator, MintOutput};
    use fedimint_core::modules::wallet::PegOutFees;
    use fedimint_core::outcome::{SerdeOutputOutcome, TransactionStatus};
    use fedimint_core::transaction::legacy::Input;
    use fedimint_testing::FakeFed;
    use futures::executor::block_on;
    use threshold_crypto::PublicKey;

    use crate::api::{IFederationApi, WsFederationApi};
    use crate::mint::db::NextECashNoteIndexKey;
    use crate::mint::MintClient;
    use crate::{
        BlindNonce, ClientContext, DerivableSecret, LegacyTransaction, TransactionBuilder,
    };

    type Fed = FakeFed<Mint>;

    #[derive(Debug)]
    struct FakeApi {
        mint: Arc<tokio::sync::Mutex<Fed>>,
    }

    #[async_trait]
    impl IFederationApi for FakeApi {
        async fn fetch_tx_outcome(
            &self,
            tx: TransactionId,
        ) -> crate::api::Result<TransactionStatus> {
            let mint = self.mint.lock().await;
            Ok(TransactionStatus::Accepted {
                epoch: 0,
                outputs: vec![SerdeOutputOutcome::from(
                    &(mint
                        .output_outcome(OutPoint {
                            txid: tx,
                            out_idx: 0,
                        })
                        .await
                        .unwrap()
                        .into()),
                )],
            })
        }

        async fn submit_transaction(
            &self,
            _tx: LegacyTransaction,
        ) -> crate::api::Result<TransactionId> {
            unimplemented!()
        }

        async fn fetch_contract(
            &self,
            _contract: ContractId,
        ) -> crate::api::Result<ContractAccount> {
            unimplemented!()
        }

        async fn fetch_consensus_block_height(&self) -> crate::api::Result<u64> {
            unimplemented!()
        }

        async fn fetch_offer(
            &self,
            _payment_hash: bitcoin::hashes::sha256::Hash,
        ) -> crate::api::Result<IncomingContractOffer> {
            unimplemented!();
        }

        async fn fetch_peg_out_fees(
            &self,
            _address: &Address,
            _amount: &bitcoin::Amount,
        ) -> crate::api::Result<Option<PegOutFees>> {
            unimplemented!();
        }

        async fn fetch_gateways(&self) -> crate::api::Result<Vec<LightningGateway>> {
            unimplemented!()
        }

        async fn register_gateway(&self, _gateway: LightningGateway) -> crate::api::Result<()> {
            unimplemented!()
        }

        async fn fetch_epoch_history(
            &self,
            _epoch: u64,
            _pk: PublicKey,
        ) -> crate::api::Result<EpochHistory> {
            unimplemented!()
        }

        async fn fetch_last_epoch(&self) -> crate::api::Result<u64> {
            unimplemented!()
        }

        async fn offer_exists(
            &self,
            _payment_hash: bitcoin::hashes::sha256::Hash,
        ) -> crate::api::Result<bool> {
            unimplemented!()
        }

        async fn upload_ecash_backup(
            &self,
            _request: &SignedBackupRequest,
        ) -> crate::api::Result<()> {
            unimplemented!()
        }

        async fn download_ecash_backup(
            &self,
            _id: &secp256k1::XOnlyPublicKey,
        ) -> crate::api::Result<Vec<u8>> {
            unimplemented!()
        }
    }

    async fn new_mint_and_client() -> (
        Arc<tokio::sync::Mutex<Fed>>,
        MintClientConfig,
        ClientContext,
    ) {
        let fed = Arc::new(tokio::sync::Mutex::new(
            FakeFed::<Mint>::new(
                4,
                |cfg, _db| async move { Ok(Mint::new(cfg.to_typed().unwrap())) },
                &ModuleConfigGenParams {
                    mint_amounts: vec![Amount::from_sat(1), Amount::from_sat(10)],
                    ..ModuleConfigGenParams::fake_config_gen_params()
                },
                &MintConfigGenerator,
            )
            .await
            .unwrap(),
        ));

        let api = FakeApi { mint: fed.clone() };

        let client_config = fed.lock().await.client_cfg().clone();

        let client_context = ClientContext {
            db: MemDatabase::new().into(),
            api: api.into(),
            secp: secp256k1_zkp::Secp256k1::new(),
        };

        (fed, client_config.cast().unwrap(), client_context)
    }

    async fn issue_tokens<'a>(
        fed: &'a tokio::sync::Mutex<Fed>,
        client: &'a MintClient,
        client_db: &'a Database,
        amt: Amount,
    ) {
        let txid = TransactionId::from_inner([0x42; 32]);
        let out_point = OutPoint { txid, out_idx: 0 };

        let mut dbtx = client_db.begin_transaction(ModuleRegistry::default()).await;
        client
            .receive_coins(amt, &mut dbtx, |output| async {
                // Agree on output
                let mut fed = block_on(fed.lock());
                block_on(fed.consensus_round(&[], &[(out_point, MintOutput(output))]));
                // Generate signatures
                block_on(fed.consensus_round(&[], &[]));

                out_point
            })
            .await;
        dbtx.commit_tx().await.expect("DB Error");

        client.fetch_all_coins().await;
    }

    #[test_log::test(tokio::test)]
    async fn create_output() {
        let (fed, client_config, client_context) = new_mint_and_client().await;

        let context = Arc::new(client_context);
        let client = MintClient {
            epoch_pk: threshold_crypto::SecretKey::random().public_key(),
            config: client_config,
            context: context.clone(),
            secret: DerivableSecret::new_root(&[], &[]),
        };

        const ISSUE_AMOUNT: Amount = Amount::from_sat(12);
        issue_tokens(&fed, &client, &context.db, ISSUE_AMOUNT).await;

        assert_eq!(client.coins().await.total_amount(), ISSUE_AMOUNT)
    }

    #[test_log::test(tokio::test)]
    async fn create_input() {
        const SPEND_AMOUNT: Amount = Amount::from_sat(21);

        let (fed, client_config, client_context) = new_mint_and_client().await;

        let context = Arc::new(client_context);
        let client = MintClient {
            epoch_pk: threshold_crypto::SecretKey::random().public_key(),
            config: client_config,
            context: context.clone(),
            secret: DerivableSecret::new_root(&[], &[]),
        };

        issue_tokens(&fed, &client, &context.db, SPEND_AMOUNT * 2).await;

        // Spending works
        let dbtx = client
            .context
            .db
            .begin_transaction(ModuleRegistry::default())
            .await;
        let mut builder = TransactionBuilder::default();
        let secp = &client.context.secp;
        let _tbs_pks = &client.config.tbs_pks;
        let rng = rand::rngs::OsRng;
        let coins = client.select_coins(SPEND_AMOUNT).await.unwrap();
        let (spend_keys, ecash_input) = MintClient::ecash_input(coins.clone()).unwrap();

        builder.input(&mut spend_keys.clone(), ecash_input.clone());
        let client = &client;
        builder
            .build_with_change(client.clone(), rng, vec![Amount::from_sat(0)], secp)
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
            assert_eq!(client.coins().await.total_amount(), SPEND_AMOUNT);

            // Double spends aren't possible
            assert!(fed.lock().await.verify_input(&input).await.is_err());
        }

        // We can exactly spend the remainder
        let dbtx = client
            .context
            .db
            .begin_transaction(ModuleRegistry::default())
            .await;
        let mut builder = TransactionBuilder::default();
        let coins = client.select_coins(SPEND_AMOUNT).await.unwrap();
        let rng = rand::rngs::OsRng;
        let (spend_keys, ecash_input) = MintClient::ecash_input(coins).unwrap();

        builder.input(&mut spend_keys.clone(), ecash_input.clone());
        builder
            .build_with_change(client.clone(), rng, vec![Amount::from_sat(0)], secp)
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
            assert_eq!(client.coins().await.total_amount(), Amount::ZERO);
        }
    }

    #[allow(clippy::needless_collect)]
    #[tokio::test]
    async fn test_parallel_issuance() {
        const ITERATIONS: usize = 10_000;

        let db = fedimint_rocksdb::RocksDb::open(tempfile::tempdir().unwrap()).unwrap();

        let client: MintClient = MintClient {
            epoch_pk: threshold_crypto::SecretKey::random().public_key(),
            config: MintClientConfig {
                tbs_pks: Tiered::from_iter([]),
                fee_consensus: Default::default(),
            },
            context: Arc::new(ClientContext {
                db: db.into(),
                api: WsFederationApi::new(vec![]).into(),
                secp: Default::default(),
            }),
            secret: DerivableSecret::new_root(&[], &[]),
        };
        let client_copy = client.clone();
        let amount = Amount::from_milli_sats(1);

        let issuance_thread = move || {
            (0..ITERATIONS)
                .filter_map({
                    |_| {
                        let client = client_copy.clone();
                        block_on(async {
                            let (_, nonce) = client
                                .new_ecash_note(secp256k1_zkp::SECP256K1, amount)
                                .await;
                            Some(nonce)
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
                dbg!(output.len());
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
            .begin_transaction(ModuleRegistry::default())
            .await
            .get_value(&NextECashNoteIndexKey(amount))
            .await
            .expect("DB error")
            .unwrap_or(0);
        // Ensure we didn't skip any keys
        assert_eq!(last_idx, result_count as u64);
    }
}
