use std::error::Error as StdError;
use std::sync::Arc;

use async_trait::async_trait;
use bitcoin::hashes::sha256::Hash as Sha256Hash;
use bitcoin::{Address, Transaction as BitcoinTransaction, Txid};
use fedimint_client::module::init::ClientModuleInitRegistry;
use fedimint_client_legacy::ln::incoming::ConfirmedInvoice;
use fedimint_client_legacy::ln::outgoing::OutgoingContractAccount;
use fedimint_client_legacy::mint::backup::Metadata;
use fedimint_client_legacy::mint::{MintClient, SpendableNote};
use fedimint_client_legacy::transaction::legacy::Output;
use fedimint_client_legacy::transaction::TransactionBuilder;
use fedimint_client_legacy::{module_decode_stubs, Client, GatewayClientConfig, UserClientConfig};
use fedimint_core::api::WsFederationApi;
use fedimint_core::cancellable::Cancellable;
use fedimint_core::config::ClientConfig;
use fedimint_core::core::KeyPair;
use fedimint_core::db::mem_impl::MemDatabase;
use fedimint_core::db::Database;
use fedimint_core::epoch::SignedEpochOutcome;
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::task::TaskGroup;
use fedimint_core::txoproof::TxOutProof;
use fedimint_core::{Amount, OutPoint, PeerId, TieredMulti, TransactionId};
use fedimint_ln_client::contracts::{ContractId, Preimage};
use fedimint_ln_client::{ContractAccount, LightningGateway};
use fedimint_mint_client::BlindNonce;
use fedimint_wallet_client::txoproof::PegInProof;
use fedimint_wallet_client::{PegOut, PegOutFees, Rbf};
use futures::executor::block_on;
use lightning_invoice::Bolt11Invoice;
use threshold_crypto::PublicKey;

use crate::fixtures;
use crate::fixtures::rng;
use crate::fixtures::user::{
    IGatewayClient, ILegacyClientError, ILegacyLightningClient, ILegacyMintClient,
    ILegacyTestClient, ILegacyWalletClient, LegacyClientResult,
};

#[derive(Clone)]
pub struct LegacyTestUser<C> {
    pub client: Arc<Client<C>>,
    pub config: C,
}

impl<T: AsRef<ClientConfig> + Clone + Send> LegacyTestUser<T> {
    pub fn new(
        config: T,
        decoders: ModuleDecoderRegistry,
        module_inits: ClientModuleInitRegistry,
        peers: Vec<PeerId>,
        db: Database,
    ) -> LegacyTestUser<T> {
        let api = WsFederationApi::new(
            config
                .as_ref()
                .api_endpoints
                .iter()
                .filter(|(id, _)| peers.contains(id))
                .map(|(id, endpoint)| (*id, endpoint.url.clone()))
                .collect(),
        )
        .into();

        let client = Arc::new(block_on(Client::new_with_api(
            config.clone(),
            decoders,
            module_inits,
            db,
            api,
            Default::default(),
        )));
        LegacyTestUser { client, config }
    }
}

#[async_trait]
impl IGatewayClient for LegacyTestUser<GatewayClientConfig> {
    async fn get_outgoing_contract(
        &self,
        id: ContractId,
    ) -> LegacyClientResult<OutgoingContractAccount> {
        self.client
            .ln_client()
            .get_outgoing_contract(id)
            .await
            .map_err(other)
    }

    async fn save_outgoing_payment(&self, contract: OutgoingContractAccount) {
        self.client.save_outgoing_payment(contract).await
    }

    async fn abort_outgoing_payment(&self, id: ContractId) -> LegacyClientResult<()> {
        self.client.abort_outgoing_payment(id).await.map_err(other)
    }

    async fn claim_outgoing_contract(
        &self,
        contract_id: ContractId,
        preimage: Preimage,
    ) -> LegacyClientResult<OutPoint> {
        self.client
            .claim_outgoing_contract(contract_id, preimage, rng())
            .await
            .map_err(other)
    }

    async fn refund_incoming_contract(
        &self,
        contract_id: ContractId,
    ) -> LegacyClientResult<TransactionId> {
        self.client
            .refund_incoming_contract(contract_id, rng())
            .await
            .map_err(other)
    }
}

fn other<T: StdError + Send + Sync + 'static>(err: T) -> ILegacyClientError {
    ILegacyClientError::Other(anyhow::Error::new(err))
}

#[async_trait]
impl ILegacyWalletClient for LegacyTestUser<UserClientConfig> {
    async fn get_new_peg_in_address(&self) -> Address {
        self.client.get_new_pegin_address(rng()).await
    }

    async fn submit_peg_in(
        &self,
        txout_proof: TxOutProof,
        btc_transaction: BitcoinTransaction,
    ) -> LegacyClientResult<TransactionId> {
        self.client
            .peg_in(txout_proof, btc_transaction, rng())
            .await
            .map_err(other)
    }

    async fn fetch_peg_out_fees(
        &self,
        amount: bitcoin::Amount,
        recipient: Address,
    ) -> LegacyClientResult<PegOut> {
        self.client
            .new_peg_out_with_fees(amount, recipient)
            .await
            .map_err(other)
    }

    async fn submit_peg_out(&self, peg_out: PegOut) -> LegacyClientResult<(PegOutFees, OutPoint)> {
        let out_point = self.client.peg_out(peg_out.clone(), rng()).await;
        out_point
            .map(|out_point| (peg_out.fees, out_point))
            .map_err(other)
    }

    async fn await_peg_out_txid(&self, out_point: OutPoint) -> LegacyClientResult<Txid> {
        self.client
            .wallet_client()
            .await_peg_out_outcome(out_point)
            .await
            .map_err(other)
    }

    async fn rbf_peg_out_tx(&self, rbf: Rbf) -> LegacyClientResult<OutPoint> {
        self.client.rbf_tx(rbf).await.map_err(other)
    }

    async fn await_consensus_block_count(&self, block_count: u64) -> LegacyClientResult<u64> {
        self.client
            .await_consensus_block_count(block_count)
            .await
            .map_err(other)
    }
}

#[async_trait]
impl ILegacyMintClient for LegacyTestUser<UserClientConfig> {
    async fn set_notes_per_denomination(&self, notes: u16) {
        self.client
            .mint_client()
            .set_notes_per_denomination(notes)
            .await;
    }

    async fn submit_pay_for_ecash(
        &self,
        ecash: TieredMulti<BlindNonce>,
    ) -> LegacyClientResult<OutPoint> {
        self.client
            .pay_to_blind_nonces(ecash, rng())
            .await
            .map_err(other)
    }

    async fn payable_ecash_tx(
        &self,
        amount: Amount,
    ) -> (TieredMulti<BlindNonce>, Box<dyn Fn(OutPoint)>) {
        self.client.receive_notes(amount).await
    }

    async fn get_stored_ecash(
        &self,
        amount: Amount,
    ) -> LegacyClientResult<TieredMulti<SpendableNote>> {
        self.client
            .mint_client()
            .select_notes(amount)
            .await
            .map_err(other)
    }

    async fn all_stored_ecash(&self) -> TieredMulti<SpendableNote> {
        self.client.notes().await
    }

    async fn remove_stored_ecash(&self, ecash: TieredMulti<SpendableNote>) {
        self.client.remove_ecash(ecash).await
    }

    async fn remove_all_stored_ecash(&self) -> LegacyClientResult<()> {
        self.client
            .mint_client()
            .wipe_notes()
            .await
            .map_err(ILegacyClientError::Other)
    }

    async fn await_all_issued(&self) -> LegacyClientResult<Vec<OutPoint>> {
        self.client.fetch_all_notes().await.map_err(other)
    }

    async fn await_ecash_issued(&self, outpoint: OutPoint) -> LegacyClientResult<()> {
        self.client.fetch_notes(outpoint).await.map_err(other)
    }

    async fn reissue_ecash_failed_tx(&self) -> LegacyClientResult<OutPoint> {
        self.client
            .reissue_pending_notes(rng())
            .await
            .map_err(other)
    }

    async fn reissue(&self, notes: TieredMulti<SpendableNote>) -> LegacyClientResult<OutPoint> {
        self.client.reissue(notes, rng()).await.map_err(other)
    }

    async fn back_up_ecash_to_federation(&self, metadata: Metadata) -> LegacyClientResult<()> {
        self.client
            .mint_client()
            .back_up_ecash_to_federation(metadata)
            .await
            .map_err(ILegacyClientError::Other)
    }

    async fn restore_ecash_from_federation(
        &self,
        gap_limit: usize,
        task_group: &mut TaskGroup,
    ) -> LegacyClientResult<Cancellable<Metadata>> {
        self.client
            .mint_client()
            .restore_ecash_from_federation(gap_limit, task_group)
            .await
            .map_err(ILegacyClientError::Other)
    }
}

#[async_trait]
impl ILegacyLightningClient for LegacyTestUser<UserClientConfig> {
    async fn await_outgoing_contract_acceptance(
        &self,
        outpoint: OutPoint,
    ) -> LegacyClientResult<()> {
        self.client
            .await_outgoing_contract_acceptance(outpoint)
            .await
            .map_err(other)
    }

    async fn get_contract_account(&self, id: ContractId) -> LegacyClientResult<ContractAccount> {
        self.client
            .ln_client()
            .get_contract_account(id)
            .await
            .map_err(other)
    }

    async fn claim_incoming_contract(
        &self,
        contract_id: ContractId,
    ) -> LegacyClientResult<OutPoint> {
        self.client
            .claim_incoming_contract(contract_id, rng())
            .await
            .map_err(other)
    }

    async fn fetch_active_gateway(&self) -> LegacyClientResult<LightningGateway> {
        self.client.fetch_active_gateway().await.map_err(other)
    }

    async fn fund_outgoing_ln_contract(
        &self,
        invoice: Bolt11Invoice,
    ) -> LegacyClientResult<(ContractId, OutPoint)> {
        self.client
            .fund_outgoing_ln_contract(invoice, rng())
            .await
            .map_err(other)
    }

    async fn await_invoice_confirmation(
        &self,
        txid: TransactionId,
        invoice: Bolt11Invoice,
        payment_keypair: KeyPair,
    ) -> LegacyClientResult<ConfirmedInvoice> {
        self.client
            .await_invoice_confirmation(txid, invoice, payment_keypair)
            .await
            .map_err(other)
    }

    async fn submit_unconfirmed_invoice(
        &self,
        amount: Amount,
        description: String,
    ) -> LegacyClientResult<(TransactionId, Bolt11Invoice, KeyPair)> {
        self.client
            .generate_unconfirmed_invoice_and_submit(amount, description, &mut rng(), None)
            .await
            .map_err(other)
    }

    async fn try_refund_outgoing_contract(
        &self,
        contract_id: ContractId,
    ) -> LegacyClientResult<OutPoint> {
        self.client
            .try_refund_outgoing_contract(contract_id, rng())
            .await
            .map_err(other)
    }
}

#[async_trait]
impl ILegacyTestClient for LegacyTestUser<UserClientConfig> {
    fn decoders(&self) -> ModuleDecoderRegistry {
        self.client.decoders().clone()
    }

    fn new_client_with_peers(&self, peers: Vec<PeerId>) -> Box<dyn ILegacyTestClient> {
        Box::new(LegacyTestUser::new(
            self.config.clone(),
            self.client.decoders().clone(),
            self.client.module_inits().clone(),
            peers,
            Database::new(MemDatabase::new(), module_decode_stubs()),
        ))
    }

    fn create_mint_tx(
        &self,
        input: TieredMulti<SpendableNote>,
        output: Amount,
    ) -> fedimint_core::transaction::Transaction {
        let mint = self.client.mint_client();
        let mut dbtx = block_on(mint.start_dbtx());

        let mut builder = TransactionBuilder::default();
        let (mut keys, input) = MintClient::ecash_input(input).unwrap();
        builder.input(&mut keys, input);

        block_on(builder.build_with_change(
            self.client.mint_client(),
            &mut dbtx,
            fixtures::rng(),
            vec![output],
            &fixtures::secp(),
        ))
        .into_type_erased()
    }

    fn create_peg_in_proof(
        &self,
        txout_proof: TxOutProof,
        btc_transaction: BitcoinTransaction,
    ) -> PegInProof {
        block_on(
            self.client
                .wallet_client()
                .create_pegin_input(txout_proof, btc_transaction),
        )
        .unwrap()
        .1
    }

    fn config(&self) -> ClientConfig {
        self.config.0.clone()
    }

    fn fetch_epoch_history(&self, epoch: u64, epoch_pk: PublicKey) -> SignedEpochOutcome {
        block_on(self.client.fetch_epoch_history(epoch, epoch_pk)).unwrap()
    }

    fn create_offer_tx(
        &self,
        amount: Amount,
        payment_hash: Sha256Hash,
        payment_secret: Preimage,
        expiry_time: Option<u64>,
    ) -> fedimint_core::transaction::Transaction {
        let mint = self.client.mint_client();
        let mut dbtx = block_on(mint.start_dbtx());

        let offer_output = self.client.ln_client().create_offer_output(
            amount,
            payment_hash,
            payment_secret,
            expiry_time,
        );
        let mut builder = TransactionBuilder::default();
        builder.output(Output::LN(offer_output));
        let res = block_on(builder.build_with_change(
            self.client.mint_client(),
            &mut dbtx,
            rng(),
            vec![],
            &fixtures::secp(),
        ))
        .into_type_erased();

        block_on(dbtx.commit_tx());

        res
    }
}
