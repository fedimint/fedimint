pub mod db;

use std::borrow::Cow;
use std::time::Duration;

use db::{CoinKey, CoinKeyPrefix, OutputFinalizationKey, OutputFinalizationKeyPrefix};
use fedimint_api::db::DatabaseTransaction;
use fedimint_api::encoding::{Decodable, Encodable};
use fedimint_api::module::TransactionItemAmount;
use fedimint_api::tiered::InvalidAmountTierError;
use fedimint_api::{Amount, FederationModule, OutPoint, Tiered, TieredMulti, TransactionId};
use fedimint_core::config::ClientConfig;
use fedimint_core::modules::mint::config::MintClientConfig;
use fedimint_core::modules::mint::{BlindNonce, Mint, Nonce, Note, SigResponse};
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use rand::{CryptoRng, RngCore};
use secp256k1_zkp::{KeyPair, Secp256k1, Signing};
use serde::de::Error;
use serde::{Deserialize, Serialize};
use tbs::{blind_message, unblind_signature, AggregatePublicKey, BlindingKey};
use thiserror::Error;
use tracing::{trace, warn};

use crate::api::ApiError;
use crate::mint::db::LastECashNoteIndexKey;
use crate::transaction::TransactionBuilder;
use crate::utils::ClientContext;
use crate::{ChildId, Client, DerivableSecret, ModuleClient};

const MINT_E_CASH_TYPE_CHILD_ID: ChildId = ChildId(0);

/// Federation module client for the Mint module. It can both create transaction inputs and outputs
/// of the mint type.
pub struct MintClient<'c> {
    pub config: &'c MintClientConfig,
    pub context: &'c ClientContext,
    pub secret: DerivableSecret,
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

impl<'a> ModuleClient for MintClient<'a> {
    type Module = Mint;
    type OperationStates = ();

    fn input_amount(
        &self,
        input: &<Self::Module as FederationModule>::TxInput,
    ) -> TransactionItemAmount {
        TransactionItemAmount {
            amount: input.total_amount(),
            fee: self.config.fee_consensus.coin_spend_abs * (input.item_count() as u64),
        }
    }

    fn output_amount(
        &self,
        output: &<Self::Module as FederationModule>::TxOutput,
    ) -> TransactionItemAmount {
        TransactionItemAmount {
            amount: output.total_amount(),
            fee: self.config.fee_consensus.coin_issuance_abs * (output.item_count() as u64),
        }
    }
}

impl<'c> MintClient<'c> {
    pub fn coins(&self) -> TieredMulti<SpendableNote> {
        self.context
            .db
            .begin_transaction()
            .find_by_prefix(&CoinKeyPrefix)
            .map(|res| {
                let (key, spendable_coin) = res.expect("DB error");
                (key.amount, spendable_coin)
            })
            .collect()
    }

    fn new_note_secret(&self, dbtx: &mut DatabaseTransaction<'_>) -> DerivableSecret {
        let new_idx = dbtx
            .get_value(&LastECashNoteIndexKey)
            .expect("DB error")
            .unwrap_or(0)
            + 1;
        dbtx.insert_entry(&LastECashNoteIndexKey, &new_idx)
            .expect("DB error");
        self.secret
            .child_key(MINT_E_CASH_TYPE_CHILD_ID) // TODO: cache
            .child_key(ChildId(new_idx))
    }

    pub fn new_ecash_note<C: Signing>(
        &self,
        ctx: &Secp256k1<C>,
        dbtx: &mut DatabaseTransaction<'_>,
    ) -> (NoteIssuanceRequest, BlindNonce) {
        let secret = self.new_note_secret(dbtx);
        NoteIssuanceRequest::new(ctx, secret)
    }

    pub fn select_coins(&self, amount: Amount) -> Result<TieredMulti<SpendableNote>> {
        let coins = self
            .coins()
            .select_coins(amount)
            .ok_or(MintClientError::NotEnoughCoins)?;

        Ok(coins)
    }

    pub async fn submit_tx_with_change<'a, C, R>(
        &self,
        client: &Client<C>,
        tx: TransactionBuilder,
        rng: R,
    ) -> Result<TransactionId>
    where
        C: AsRef<ClientConfig> + Clone,
        R: RngCore + CryptoRng,
    {
        let mut dbtx = self.context.db.begin_transaction();
        let change_required = tx.change_required(client);
        let final_tx = tx.build(
            change_required,
            &mut dbtx,
            |tx| self.new_ecash_note(&self.context.secp, tx),
            &self.context.secp,
            &self.config.tbs_pks,
            rng,
        );
        let txid = final_tx.tx_hash();
        let mint_tx_id = self.context.api.submit_transaction(final_tx).await?;
        assert_eq!(
            txid, mint_tx_id,
            "Federation is faulty, returned wrong tx id."
        );

        dbtx.commit_tx().expect("DB Error");
        Ok(txid)
    }

    pub fn receive_coins<'a>(
        &self,
        amount: Amount,
        dbtx: &mut DatabaseTransaction<'a>,
        coin_gen: impl Fn(&mut DatabaseTransaction<'_>) -> (NoteIssuanceRequest, BlindNonce),
        mut create_tx: impl FnMut(TieredMulti<BlindNonce>) -> OutPoint,
    ) {
        let mut builder = TransactionBuilder::default();

        let (finalization, coins) =
            builder.create_output_coins(amount, || coin_gen(dbtx), &self.config.tbs_pks);
        let out_point = create_tx(coins);
        dbtx.insert_new_entry(&OutputFinalizationKey(out_point), &finalization)
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
            .begin_transaction()
            .get_value(&OutputFinalizationKey(outpoint))
            .expect("DB error")
            .ok_or(MintClientError::FinalizationError(
                CoinFinalizationError::UnknownIssuance,
            ))?;

        let bsig = self
            .context
            .api
            .fetch_output_outcome::<Option<SigResponse>>(outpoint)
            .await?
            .ok_or(MintClientError::OutputNotReadyYet(outpoint))?;

        let coins = issuance.finalize(bsig, &self.config.tbs_pks)?;

        coins
            .into_iter()
            .for_each(|(amount, coin): (Amount, SpendableNote)| {
                let key = CoinKey {
                    amount,
                    nonce: coin.note.0.clone(),
                };
                let value = coin;
                dbtx.insert_new_entry(&key, &value).expect("DB Error");
            });
        dbtx.remove_entry(&OutputFinalizationKey(outpoint))
            .expect("DB Error");

        Ok(())
    }

    pub fn list_active_issuances(&self) -> Vec<(OutPoint, NoteIssuanceRequests)> {
        self.context
            .db
            .begin_transaction()
            .find_by_prefix(&OutputFinalizationKeyPrefix)
            .map(|res| {
                let (OutputFinalizationKey(outpoint), cfd) = res.expect("DB error");
                (outpoint, cfd)
            })
            .collect()
    }

    pub async fn fetch_all_coins(&self) -> Vec<Result<OutPoint>> {
        let active_issuances = self.list_active_issuances();
        if active_issuances.is_empty() {
            return Vec::new();
        }

        let stream = active_issuances
            .into_iter()
            .map(|(out_point, _)| async move {
                let mut dbtx = self.context.db.begin_transaction();
                loop {
                    match self.fetch_coins(&mut dbtx, out_point).await {
                        Ok(_) => {
                            dbtx.commit_tx().expect("DB Error");
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
    /// Finalize the issuance request using a [`SigResponse`] from the mint containing the blind
    /// signatures for all coins in this `IssuanceRequest`. It also takes the mint's
    /// [`AggregatePublicKey`] to validate the supplied blind signatures.
    pub fn finalize(
        &self,
        bsigs: SigResponse,
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
                let sig = unblind_signature(coin_req.blinding_key, bsig);
                let coin = Note(coin_req.nonce(), sig);
                if coin.verify(*mint_pub_key.tier(&amt)?) {
                    let coin = SpendableNote {
                        note: coin,
                        spend_key: coin_req.spend_key,
                    };

                    Ok((amt, coin))
                } else {
                    Err(CoinFinalizationError::InvalidSignature(idx))
                }
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
    #[error("The blind signature at index {0} is invalid")]
    InvalidSignature(usize),
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
    #[error("The client's wallet has not enough coins or they are not in the right denomination")]
    NotEnoughCoins,
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
    use fedimint_api::db::mem_impl::MemDatabase;
    use fedimint_api::db::Database;
    use fedimint_api::{Amount, OutPoint, Tiered, TransactionId};
    use fedimint_core::epoch::EpochHistory;
    use fedimint_core::modules::ln::contracts::incoming::IncomingContractOffer;
    use fedimint_core::modules::ln::contracts::ContractId;
    use fedimint_core::modules::ln::{ContractAccount, LightningGateway};
    use fedimint_core::modules::mint::config::MintClientConfig;
    use fedimint_core::modules::mint::Mint;
    use fedimint_core::modules::wallet::PegOutFees;
    use fedimint_core::outcome::{OutputOutcome, TransactionStatus};
    use fedimint_core::transaction::Transaction;
    use fedimint_testing::FakeFed;
    use futures::executor::block_on;
    use threshold_crypto::PublicKey;

    use crate::api::{IFederationApi, WsFederationApi};
    use crate::mint::db::LastECashNoteIndexKey;
    use crate::mint::MintClient;
    use crate::{BlindNonce, ClientContext, DerivableSecret, TransactionBuilder};

    type Fed = FakeFed<Mint, MintClientConfig>;

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
                outputs: vec![OutputOutcome::Mint(
                    mint.output_outcome(OutPoint {
                        txid: tx,
                        out_idx: 0,
                    })
                    .unwrap(),
                )],
            })
        }

        async fn submit_transaction(&self, _tx: Transaction) -> crate::api::Result<TransactionId> {
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

        async fn offer_exists(
            &self,
            _payment_hash: bitcoin::hashes::sha256::Hash,
        ) -> crate::api::Result<bool> {
            unimplemented!()
        }
    }

    async fn new_mint_and_client() -> (
        Arc<tokio::sync::Mutex<Fed>>,
        MintClientConfig,
        ClientContext,
    ) {
        let fed = Arc::new(tokio::sync::Mutex::new(
            FakeFed::<Mint, MintClientConfig>::new(
                4,
                |cfg, db| async { Mint::new(cfg, db) },
                &[Amount::from_sat(1), Amount::from_sat(10)][..],
            )
            .await,
        ));
        let api = FakeApi { mint: fed.clone() };

        let client_config = fed.lock().await.client_cfg().clone();

        let client_context = ClientContext {
            db: MemDatabase::new().into(),
            api: api.into(),
            secp: secp256k1_zkp::Secp256k1::new(),
        };

        (fed, client_config, client_context)
    }

    async fn issue_tokens<'a>(
        fed: &'a tokio::sync::Mutex<Fed>,
        client: &'a MintClient<'a>,
        client_db: &'a Database,
        amt: Amount,
    ) {
        let txid = TransactionId::from_inner([0x42; 32]);
        let out_point = OutPoint { txid, out_idx: 0 };

        let mut dbtx = client_db.begin_transaction();
        client.receive_coins(
            amt,
            &mut dbtx,
            |dbtx| client.new_ecash_note(secp256k1_zkp::SECP256K1, dbtx),
            |output| {
                // Agree on output
                let mut fed = block_on(fed.lock());
                block_on(fed.consensus_round(&[], &[(out_point, output)]));
                // Generate signatures
                block_on(fed.consensus_round(&[], &[]));

                out_point
            },
        );
        dbtx.commit_tx().expect("DB Error");

        client.fetch_all_coins().await;
    }

    #[test_log::test(tokio::test)]
    async fn create_output() {
        let (fed, client_config, client_context) = new_mint_and_client().await;

        let client = MintClient {
            config: &client_config,
            context: &client_context,
            secret: DerivableSecret::new(&[], &[]),
        };

        const ISSUE_AMOUNT: Amount = Amount::from_sat(12);
        issue_tokens(&fed, &client, &client_context.db, ISSUE_AMOUNT).await;

        assert_eq!(client.coins().total_amount(), ISSUE_AMOUNT)
    }

    #[test_log::test(tokio::test)]
    async fn create_input() {
        const SPEND_AMOUNT: Amount = Amount::from_sat(21);

        let (fed, client_config, client_context) = new_mint_and_client().await;
        let client = MintClient {
            config: &client_config,
            context: &client_context,
            secret: DerivableSecret::new(&[], &[]),
        };

        issue_tokens(&fed, &client, &client_context.db, SPEND_AMOUNT * 2).await;

        // Spending works
        let mut dbtx = client.context.db.begin_transaction();
        let mut builder = TransactionBuilder::default();
        let secp = &client.context.secp;
        let tbs_pks = &client.config.tbs_pks;
        let rng = rand::rngs::OsRng;
        let coins = client.select_coins(SPEND_AMOUNT).unwrap();
        let (spend_keys, input) = builder.create_input_from_coins(coins.clone()).unwrap();
        builder.input_coins(coins).unwrap();
        builder.build(
            Amount::from_sat(0),
            &mut dbtx,
            |dbtx| client.new_ecash_note(secp, dbtx),
            secp,
            tbs_pks,
            rng,
        );
        dbtx.commit_tx().expect("DB Error");

        let meta = fed.lock().await.verify_input(&input).unwrap();
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
        assert_eq!(client.coins().total_amount(), SPEND_AMOUNT);

        // Double spends aren't possible
        assert!(fed.lock().await.verify_input(&input).is_err());

        // We can exactly spend the remainder
        let mut dbtx = client.context.db.begin_transaction();
        let mut builder = TransactionBuilder::default();
        let coins = client.select_coins(SPEND_AMOUNT).unwrap();
        let rng = rand::rngs::OsRng;
        let (spend_keys, input) = builder.create_input_from_coins(coins.clone()).unwrap();
        builder.input_coins(coins).unwrap();
        builder.build(
            Amount::from_sat(0),
            &mut dbtx,
            |dbtx| client.new_ecash_note(secp, dbtx),
            secp,
            tbs_pks,
            rng,
        );
        dbtx.commit_tx().expect("DB Error");

        let meta = fed.lock().await.verify_input(&input).unwrap();
        assert_eq!(meta.amount.amount, SPEND_AMOUNT);
        assert_eq!(
            meta.keys,
            spend_keys
                .into_iter()
                .map(|key| secp256k1_zkp::XOnlyPublicKey::from_keypair(&key).0)
                .collect::<Vec<_>>()
        );

        // No money is left
        assert_eq!(client.coins().total_amount(), Amount::ZERO);
    }

    #[allow(clippy::needless_collect)]
    #[tokio::test]
    async fn test_parallel_issuance() {
        const ITERATIONS: usize = 10_000;

        let db = fedimint_rocksdb::RocksDb::open(tempfile::tempdir().unwrap()).unwrap();

        let client: MintClient<'static> = MintClient {
            config: Box::leak(Box::new(MintClientConfig {
                tbs_pks: Tiered::from_iter([]),
                fee_consensus: Default::default(),
            })),
            context: Box::leak(Box::new(ClientContext {
                db: db.into(),
                api: WsFederationApi::new(vec![]).into(),
                secp: Default::default(),
            })),
            secret: DerivableSecret::new(&[], &[]),
        };

        let client_ref: &'static MintClient<'static> = Box::leak(Box::new(client));
        let issuance_thread = || {
            (0..ITERATIONS)
                .filter_map(|_| {
                    let mut tx = client_ref.context.db.begin_transaction();
                    let (_, nonce) = client_ref.new_ecash_note(secp256k1_zkp::SECP256K1, &mut tx);
                    tx.commit_tx().map(|_| nonce).ok()
                })
                .collect::<Vec<BlindNonce>>()
        };

        let threads = (0..4)
            .map(|_| std::thread::spawn(issuance_thread))
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

        let last_idx = client_ref
            .context
            .db
            .begin_transaction()
            .get_value(&LastECashNoteIndexKey)
            .expect("DB error")
            .unwrap_or(0);
        // Ensure we didn't skip any keys
        assert_eq!(last_idx, result_count as u64);
    }
}
