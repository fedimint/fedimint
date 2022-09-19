pub mod db;

use crate::api::ApiError;
use crate::transaction::TransactionBuilder;
use crate::utils::ClientContext;

use db::{CoinKey, CoinKeyPrefix, OutputFinalizationKey, OutputFinalizationKeyPrefix};
use fedimint_api::db::batch::{Accumulator, BatchItem, BatchTx, DbBatch};
use fedimint_api::encoding::{Decodable, Encodable};
use fedimint_api::{Amount, OutPoint, TransactionId};
use fedimint_core::config::FeeConsensus;
use fedimint_core::modules::mint::config::MintClientConfig;
use fedimint_core::modules::mint::tiered::TieredMulti;
use fedimint_core::modules::mint::{
    BlindNonce, InvalidAmountTierError, Nonce, Note, SigResponse, SignRequest, Tiered,
};
use futures::stream::FuturesUnordered;
use futures::StreamExt;

use rand::{CryptoRng, RngCore};
use secp256k1_zkp::{Secp256k1, Signing};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tbs::{blind_message, unblind_signature, AggregatePublicKey, BlindedMessage, BlindingKey};
use thiserror::Error;
use tracing::{debug, trace, warn};

/// Federation module client for the Mint module. It can both create transaction inputs and outputs
/// of the mint type.
pub struct MintClient<'c> {
    pub config: &'c MintClientConfig,
    pub context: &'c ClientContext,
}

/// Client side representation of one coin in an issuance request that keeps all necessary
/// information to generate one spendable coin once the blind signature arrives.
#[derive(Debug, Clone, Deserialize, Serialize, Encodable, Decodable)]
pub struct CoinRequest {
    /// Spend key from which the coin nonce (corresponding public key) is derived
    spend_key: [u8; 32], // FIXME: either make KeyPair Serializable or add secret key newtype
    /// Nonce belonging to the secret key
    nonce: Nonce,
    /// Key to unblind the blind signature supplied by the mint for this coin
    blinding_key: BlindingKey,
}

/// Client side representation of a coin reissuance that keeps all necessary information to
/// generate spendable coins once the blind signatures arrive.
#[derive(Debug, Clone, Deserialize, Serialize, Encodable, Decodable)]
pub struct CoinFinalizationData {
    /// Finalization data for all coin outputs in this request
    coins: TieredMulti<CoinRequest>,
}

/// A [`Note`] with associated secret key that allows to proof ownership (spend it)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct SpendableNote {
    pub coin: Note,
    pub spend_key: [u8; 32],
}

impl<'c> MintClient<'c> {
    pub fn coins(&self) -> TieredMulti<SpendableNote> {
        self.context
            .db
            .find_by_prefix(&CoinKeyPrefix)
            .map(|res| {
                let (key, spendable_coin) = res.expect("DB error");
                (key.amount, spendable_coin)
            })
            .collect()
    }

    pub fn select_coins(&self, amount: Amount) -> Result<TieredMulti<SpendableNote>> {
        let coins = self
            .coins()
            .select_coins(amount)
            .ok_or(MintClientError::NotEnoughCoins)?;

        Ok(coins)
    }

    pub async fn submit_tx_with_change<R: RngCore + CryptoRng>(
        &self,
        fee_consensus: &FeeConsensus,
        tx: TransactionBuilder,
        mut batch: Accumulator<BatchItem>,
        rng: R,
    ) -> Result<TransactionId> {
        let change_required = tx.change_required(fee_consensus);
        let final_tx = tx.build(
            change_required,
            batch.transaction(),
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

        self.context.db.apply_batch(batch).expect("DB error");
        Ok(txid)
    }

    pub fn receive_coins<R: RngCore + CryptoRng>(
        &self,
        amount: Amount,
        mut tx: BatchTx,
        rng: R,
        mut create_tx: impl FnMut(TieredMulti<BlindNonce>) -> OutPoint,
    ) {
        let mut builder = TransactionBuilder::default();

        let (finalization, coins) =
            builder.create_output_coins(amount, &self.context.secp, &self.config.tbs_pks, rng);
        let out_point = create_tx(coins);
        tx.append_insert_new(OutputFinalizationKey(out_point), finalization);
        tx.commit();
    }

    pub async fn fetch_coins(&self, mut batch: BatchTx<'_>, outpoint: OutPoint) -> Result<()> {
        let issuance = self
            .context
            .db
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

        batch.append_from_iter(
            coins
                .into_iter()
                .map(|(amount, coin): (Amount, SpendableNote)| {
                    let key = CoinKey {
                        amount,
                        nonce: coin.coin.0.clone(),
                    };
                    let value = coin;
                    BatchItem::insert_new(key, value)
                }),
        );
        batch.append_delete(OutputFinalizationKey(outpoint));
        batch.commit();

        Ok(())
    }

    pub fn list_active_issuances(&self) -> Vec<(OutPoint, CoinFinalizationData)> {
        self.context
            .db
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
                let mut batch = DbBatch::new();
                loop {
                    match self.fetch_coins(batch.transaction(), out_point).await {
                        Ok(_) => {
                            self.context.db.apply_batch(batch).expect("DB error");
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

impl CoinFinalizationData {
    /// Generate a new `IssuanceRequest` and the associates [`SignRequest`]
    pub fn new<K, C>(
        amount: Amount,
        amount_tiers: &Tiered<K>,
        ctx: &Secp256k1<C>,
        mut rng: impl RngCore + CryptoRng,
    ) -> (CoinFinalizationData, SignRequest)
    where
        C: Signing,
    {
        let (requests, blinded_nonces): (TieredMulti<_>, TieredMulti<_>) =
            TieredMulti::represent_amount(amount, amount_tiers)
                .into_iter()
                .map(|(amt, ())| {
                    let (request, blind_msg) = CoinRequest::new(ctx, &mut rng);
                    ((amt, request), (amt, blind_msg))
                })
                .unzip();

        debug!(
            %amount,
            coins = %requests.item_count(),
            tiers = ?requests.tiers().collect::<Vec<_>>(),
            "Generated issuance request"
        );

        let sig_req = SignRequest(blinded_nonces);
        let issuance_req = CoinFinalizationData { coins: requests };

        (issuance_req, sig_req)
    }

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
                let coin = Note(coin_req.nonce.clone(), sig);
                if coin.verify(*mint_pub_key.tier(&amt)?) {
                    let coin = SpendableNote {
                        coin,
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

impl CoinRequest {
    /// Generate a request session for a single coin and returns it plus the corresponding blinded
    /// message
    fn new<C>(
        ctx: &Secp256k1<C>,
        mut rng: impl RngCore + CryptoRng,
    ) -> (CoinRequest, BlindedMessage)
    where
        C: Signing,
    {
        let spend_key = bitcoin::KeyPair::new(ctx, &mut rng);
        let nonce = Nonce(spend_key.public_key());
        let (blinding_key, blinded_nonce) = blind_message(nonce.to_message());

        let cr = CoinRequest {
            spend_key: spend_key.secret_bytes(),
            nonce,
            blinding_key,
        };

        (cr, blinded_nonce)
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

#[cfg(test)]
mod tests {
    use crate::api::FederationApi;

    use crate::mint::MintClient;
    use crate::{ClientContext, TransactionBuilder};
    use async_trait::async_trait;
    use bitcoin::hashes::Hash;
    use bitcoin::Address;
    use fedimint_api::db::batch::DbBatch;
    use fedimint_api::db::mem_impl::MemDatabase;
    use fedimint_api::db::Database;
    use fedimint_api::module::testing::FakeFed;
    use fedimint_api::{Amount, OutPoint, TransactionId};
    use fedimint_core::epoch::EpochHistory;
    use fedimint_core::modules::ln::contracts::incoming::IncomingContractOffer;
    use fedimint_core::modules::ln::contracts::ContractId;
    use fedimint_core::modules::ln::{ContractAccount, LightningGateway};
    use fedimint_core::modules::mint::config::MintClientConfig;
    use fedimint_core::modules::mint::Mint;
    use fedimint_core::modules::wallet::PegOutFees;
    use fedimint_core::outcome::{OutputOutcome, TransactionStatus};
    use fedimint_core::transaction::Transaction;
    use futures::executor::block_on;
    use std::sync::Arc;
    use threshold_crypto::PublicKey;

    type Fed = FakeFed<Mint, MintClientConfig>;

    struct FakeApi {
        mint: Arc<tokio::sync::Mutex<Fed>>,
    }

    #[async_trait]
    impl FederationApi for FakeApi {
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
    }

    async fn new_mint_and_client() -> (
        Arc<tokio::sync::Mutex<Fed>>,
        MintClientConfig,
        ClientContext,
    ) {
        let fed = Arc::new(tokio::sync::Mutex::new(
            FakeFed::<Mint, MintClientConfig>::new(
                4,
                1,
                |cfg, db| async { Mint::new(cfg, Arc::new(db)) },
                &[Amount::from_sat(1), Amount::from_sat(10)][..],
            )
            .await,
        ));
        let api = FakeApi { mint: fed.clone() };

        let client_config = fed.lock().await.client_cfg().clone();

        let client_context = ClientContext {
            db: Box::new(MemDatabase::new()),
            api: Box::new(api),
            secp: secp256k1_zkp::Secp256k1::new(),
        };

        (fed, client_config, client_context)
    }

    async fn issue_tokens<'a, R: rand::RngCore + rand::CryptoRng>(
        fed: &'a tokio::sync::Mutex<Fed>,
        client: &'a MintClient<'a>,
        client_db: &'a dyn Database,
        amt: Amount,
        rng: &'a mut R,
    ) {
        let txid = TransactionId::from_inner([0x42; 32]);
        let out_point = OutPoint { txid, out_idx: 0 };

        let mut batch = DbBatch::new();
        client.receive_coins(amt, batch.transaction(), rng, |output| {
            // Agree on output
            let mut fed = block_on(fed.lock());
            block_on(fed.consensus_round(&[], &[(out_point, output)]));
            // Generate signatures
            block_on(fed.consensus_round(&[], &[]));

            out_point
        });
        client_db.apply_batch(batch).unwrap();

        client.fetch_all_coins().await;
    }

    #[test_log::test(tokio::test)]
    async fn create_output() {
        let mut rng = rand::rngs::OsRng::new().unwrap();
        let (fed, client_config, client_context) = new_mint_and_client().await;

        let client = MintClient {
            config: &client_config,
            context: &client_context,
        };

        const ISSUE_AMOUNT: Amount = Amount::from_sat(12);
        issue_tokens(
            &fed,
            &client,
            client_context.db.as_ref(),
            ISSUE_AMOUNT,
            &mut rng,
        )
        .await;

        assert_eq!(client.coins().total_amount(), ISSUE_AMOUNT)
    }

    #[test_log::test(tokio::test)]
    async fn create_input() {
        let mut rng = rand::rngs::OsRng::new().unwrap();

        const SPEND_AMOUNT: Amount = Amount::from_sat(21);

        let (fed, client_config, client_context) = new_mint_and_client().await;
        let client = MintClient {
            config: &client_config,
            context: &client_context,
        };

        issue_tokens(
            &fed,
            &client,
            client_context.db.as_ref(),
            SPEND_AMOUNT * 2,
            &mut rng,
        )
        .await;

        // Spending works
        let mut batch = DbBatch::new();
        let mut builder = TransactionBuilder::default();
        let secp = &client.context.secp;
        let tbs_pks = &client.config.tbs_pks;
        let rng = rand::rngs::OsRng::new().unwrap();
        let coins = client.select_coins(SPEND_AMOUNT).unwrap();
        let (spend_keys, input) = builder
            .create_input_from_coins(coins.clone(), secp)
            .unwrap();
        builder.input_coins(coins, secp).unwrap();
        builder.build(Amount::from_sat(0), batch.transaction(), secp, tbs_pks, rng);
        client_context.db.apply_batch(batch).unwrap();

        let meta = fed.lock().await.verify_input(&input).unwrap();
        assert_eq!(meta.amount, SPEND_AMOUNT);
        assert_eq!(
            meta.keys,
            spend_keys
                .into_iter()
                .map(|key| secp256k1_zkp::XOnlyPublicKey::from_keypair(&key))
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
        let mut batch = DbBatch::new();
        let mut builder = TransactionBuilder::default();
        let coins = client.select_coins(SPEND_AMOUNT).unwrap();
        let rng = rand::rngs::OsRng::new().unwrap();
        let (spend_keys, input) = builder
            .create_input_from_coins(coins.clone(), secp)
            .unwrap();
        builder.input_coins(coins, secp).unwrap();
        builder.build(Amount::from_sat(0), batch.transaction(), secp, tbs_pks, rng);
        client_context.db.apply_batch(batch).unwrap();

        let meta = fed.lock().await.verify_input(&input).unwrap();
        assert_eq!(meta.amount, SPEND_AMOUNT);
        assert_eq!(
            meta.keys,
            spend_keys
                .into_iter()
                .map(|key| secp256k1_zkp::XOnlyPublicKey::from_keypair(&key))
                .collect::<Vec<_>>()
        );

        // No money is left
        assert_eq!(client.coins().total_amount(), Amount::ZERO);
    }
}
