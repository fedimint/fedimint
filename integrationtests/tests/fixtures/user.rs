use std::iter::repeat;

use async_trait::async_trait;
use bitcoin::hashes::sha256::Hash as Sha256Hash;
use bitcoin::{Address, Transaction as BitcoinTransaction, Txid};
use fedimint_client_legacy::ln::incoming::ConfirmedInvoice;
use fedimint_client_legacy::ln::outgoing::OutgoingContractAccount;
use fedimint_client_legacy::mint::backup::Metadata;
use fedimint_client_legacy::mint::SpendableNote;
use fedimint_core::cancellable::Cancellable;
use fedimint_core::config::ClientConfig;
use fedimint_core::core::KeyPair;
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
use itertools::Itertools;
use lightning_invoice::Invoice;
use threshold_crypto::PublicKey;
use tracing::warn;

// TODO: These interfaces are for the old client, eventually they will be
// replaced

pub type LegacyClientResult<T> = Result<T, ILegacyClientError>;

/// Represents any error from the client
// TODO: Return more meaningful types
#[derive(Debug)]
pub enum ILegacyClientError {
    Other(anyhow::Error),
}

#[async_trait]
/// Interface for the client that the LN gateway uses
pub trait IGatewayClient {
    /// Get LN contract that pays on behalf of a user
    async fn get_outgoing_contract(
        &self,
        id: ContractId,
    ) -> LegacyClientResult<OutgoingContractAccount>;

    /// Save the details about an outgoing payment the client is about to
    /// process. This function has to be called prior to instructing the
    /// lightning node to pay the invoice since otherwise a crash could lead
    /// to loss of funds.
    ///
    /// Note though that extended periods of staying offline will result in loss
    /// of funds anyway if the client can not claim the respective contract
    /// in time.
    async fn save_outgoing_payment(&self, contract: OutgoingContractAccount);

    /// Abort payment if our node can't route it and give money back to user
    async fn abort_outgoing_payment(&self, id: ContractId) -> LegacyClientResult<()>;

    /// Claim an outgoing contract after acquiring the preimage by paying the
    /// associated invoice and initiates e-cash issuances to receive the
    /// bitcoin from the contract (these still need to be fetched later to
    /// finalize them).
    ///
    /// Callers need to make sure that the contract can still be claimed by the
    /// gateway and has not timed out yet. Otherwise the transaction will
    /// fail.
    async fn claim_outgoing_contract(
        &self,
        contract_id: ContractId,
        preimage: Preimage,
    ) -> LegacyClientResult<OutPoint>;

    /// Claw back funds after incoming contract that had invalid preimage
    async fn refund_incoming_contract(
        &self,
        contract_id: ContractId,
    ) -> LegacyClientResult<TransactionId>;
}

#[async_trait]
/// Interface for a client that uses a wallet module
pub trait ILegacyWalletClient {
    /// Returns a bitcoin address suited to perform a fedimint
    /// [peg-in](Self::peg_in)
    ///
    /// This function requires a cryptographically secure randomness source, and
    /// utilizes the [wallet-clients](crate::wallet::WalletClient)
    /// [get_new_pegin_address](crate::wallet::WalletClient::get_new_pegin_address) to **derive** a bitcoin-address from the federations
    /// public descriptor by tweaking it.
    /// - this function will write to the clients DB
    ///
    /// read more on fedimints address derivation: <https://fedimint.org/Fedimint/wallet/>
    async fn get_new_peg_in_address(&self) -> Address;

    /// Submits a peg in transaction to the federation, proving that we are the
    /// ones paying them on-chain
    async fn submit_peg_in(
        &self,
        txout_proof: TxOutProof,
        btc_transaction: BitcoinTransaction,
    ) -> LegacyClientResult<TransactionId>;

    /// Takes an address and amount we wish to withdraw and creates a `PegOut`
    /// with the federation's required fees
    async fn fetch_peg_out_fees(
        &self,
        amount: bitcoin::Amount,
        recipient: Address,
    ) -> LegacyClientResult<PegOut>;

    /// Submits the peg-out transaction to the federation, if successful will
    /// result in an on-chain transaction being broadcast
    async fn submit_peg_out(&self, peg_out: PegOut) -> LegacyClientResult<(PegOutFees, OutPoint)>;

    /// Awaits the federation broadcasting the peg-out transaction and returns
    /// the transaction id
    async fn await_peg_out_txid(&self, out_point: OutPoint) -> LegacyClientResult<Txid>;

    /// Submit an RBF request to the federation who will bump the fees for our
    /// on-chain transaction
    ///
    /// Helps prevent transactions from getting stuck in the mempool
    async fn rbf_peg_out_tx(&self, rbf: Rbf) -> LegacyClientResult<OutPoint>;

    /// Awaits for the federation's consensus block count to reach a target
    ///
    /// The consensus block count will be below the actual block count to
    /// account for finality delay
    async fn await_consensus_block_count(&self, block_count: u64) -> LegacyClientResult<u64>;
}

#[async_trait]
/// Interface for a client that uses a mint module
pub trait ILegacyMintClient {
    /// Sets our target number of notes per denomination
    ///
    /// Higher values makes it easier to make change or have a bigger anonymity
    /// set, but may be more storage and computationally expensive
    async fn set_notes_per_denomination(&self, notes: u16);

    /// Submits a transaction to the federation that spends our ecash in order
    /// to sign the ecash of a recipient
    async fn submit_pay_for_ecash(
        &self,
        ecash: TieredMulti<BlindNonce>,
    ) -> LegacyClientResult<OutPoint>;

    /// Generates payable ecash of the `amount` specified
    ///
    /// The payer can use `submit_pay_for_ecash` to pay for the federation to
    /// sign our blind nonces. Returns a `Fn` that should be called with the
    /// `OutPoint` so we can request the issuance from the federation once it is
    /// signed.
    async fn payable_ecash_tx(
        &self,
        amount: Amount,
    ) -> (TieredMulti<BlindNonce>, Box<dyn Fn(OutPoint)>);

    /// Select notes with total amount of *at least* `amount`. If more than
    /// requested amount of notes are returned it was because exact change
    /// couldn't be made, and the next smallest amount will be returned.
    ///
    /// Could be used for the offline sending ecash to a recipient (so long as
    /// they trust us not to double-spend). Once the ecash is spent, remove
    /// it using `remove_stored_ecash`
    async fn get_stored_ecash(
        &self,
        amount: Amount,
    ) -> LegacyClientResult<TieredMulti<SpendableNote>>;

    /// Returns all spendable ecash
    async fn all_stored_ecash(&self) -> TieredMulti<SpendableNote>;

    /// Removes spendable ecash from our database, use only if we are certain
    /// that the ecash has been spent
    async fn remove_stored_ecash(&self, ecash: TieredMulti<SpendableNote>);

    /// Removes ALL ecash from our database, only really useful if we have
    /// already backed-up our ecash to the federation
    async fn remove_all_stored_ecash(&self) -> LegacyClientResult<()>;

    /// Waits for all of our blind ecash submitted to the federation to be
    /// issued (blind-signed)
    async fn await_all_issued(&self) -> LegacyClientResult<Vec<OutPoint>>;

    /// Waits for our blind ecash submitted to the federation at a given
    /// `OutPoint` to be issued
    async fn await_ecash_issued(&self, outpoint: OutPoint) -> LegacyClientResult<()>;

    /// Should be called after any transaction faileds in order to get our ecash
    /// inputs back.
    async fn reissue_ecash_failed_tx(&self) -> LegacyClientResult<OutPoint>;

    /// Spent some [`SpendableNote`]s to receive a freshly minted ones
    ///
    /// This is useful in scenarios where certain notes were handed over
    /// directly to us by another user as a payment. By spending them we can
    /// make sure they can no longer be potentially double-spent.
    ///
    /// Reissuing also breaks up larger notes into change if we need smaller
    /// denominations.
    async fn reissue(&self, notes: TieredMulti<SpendableNote>) -> LegacyClientResult<OutPoint>;

    /// Prepare an encrypted backup and send it to federation for storing
    async fn back_up_ecash_to_federation(&self, metadata: Metadata) -> LegacyClientResult<()>;

    /// Restores our ecash backup from the federation
    async fn restore_ecash_from_federation(
        &self,
        gap_limit: usize,
        task_group: &mut TaskGroup,
    ) -> LegacyClientResult<Cancellable<Metadata>>;
}

#[async_trait]
/// Interface for a client that uses a lightning module
// TODO: need better comments, this is a confusing interface
pub trait ILegacyLightningClient {
    /// Awaits for our submitted contract to be accepted by the federation
    async fn await_outgoing_contract_acceptance(
        &self,
        outpoint: OutPoint,
    ) -> LegacyClientResult<()>;

    /// Gets our contract account
    async fn get_contract_account(&self, id: ContractId) -> LegacyClientResult<ContractAccount>;

    /// Receive ecash in return for paying a gateway's LN invoice
    async fn claim_incoming_contract(
        &self,
        contract_id: ContractId,
    ) -> LegacyClientResult<OutPoint>;

    /// Gets the gateway that we are interacting with for LN payments
    async fn fetch_active_gateway(&self) -> LegacyClientResult<LightningGateway>;

    /// Pays ecash to fund a LN invoice that will be paid by the gateway
    async fn fund_outgoing_ln_contract(
        &self,
        invoice: Invoice,
    ) -> LegacyClientResult<(ContractId, OutPoint)>;

    /// Submits a LN invoice to the federation (without paying anything yet)
    async fn submit_unconfirmed_invoice(
        &self,
        amount: Amount,
        description: String,
    ) -> LegacyClientResult<(TransactionId, Invoice, KeyPair)>;
    async fn try_refund_outgoing_contract(
        &self,
        contract_id: ContractId,
    ) -> LegacyClientResult<OutPoint>;

    /// After calling `submit_unconfirmed_invoice` waits for the federation to
    /// confirm the invoice
    async fn await_invoice_confirmation(
        &self,
        txid: TransactionId,
        invoice: Invoice,
        payment_keypair: KeyPair,
    ) -> LegacyClientResult<ConfirmedInvoice>;
}

#[async_trait]
/// Interface used just for running our tests
// TODO: Implement for new client so we can test it and remove the legacy client
pub trait ILegacyTestClient:
    Sync + ILegacyWalletClient + ILegacyMintClient + ILegacyLightningClient
{
    fn decoders(&self) -> ModuleDecoderRegistry;

    /// Helper to make restore ecash less verbose
    async fn restore_ecash(&self, gap_limit: usize, task_group: &mut TaskGroup) -> Metadata {
        self.restore_ecash_from_federation(gap_limit, task_group)
            .await
            .unwrap()
            .unwrap()
    }

    /// Helper that fetches the peg-out fees then submits the peg-out
    fn peg_out(&self, amount: u64, address: &Address) -> (PegOutFees, OutPoint) {
        let peg_out =
            block_on(self.fetch_peg_out_fees(bitcoin::Amount::from_sat(amount), address.clone()))
                .unwrap();
        block_on(self.submit_peg_out(peg_out)).unwrap()
    }

    /// Gets the total value of our ecash (after fetching any issued ecash)
    fn ecash_total(&self) -> Amount {
        self.ecash_amounts().into_iter().sum()
    }

    /// Gets all the denominations of our ecash (after fetching any issued
    /// ecash)
    fn ecash_amounts(&self) -> Vec<Amount> {
        match block_on(self.await_all_issued()) {
            Ok(_) => {}
            Err(e) => warn!("Error fetching all issued {:?}", e),
        }
        block_on(self.all_stored_ecash())
            .iter()
            .flat_map(|(a, c)| repeat(*a).take(c.len()))
            .sorted()
            .collect::<Vec<Amount>>()
    }

    /// Creates a test client that communicates only with a subset of peers
    fn new_client_with_peers(&self, peers: Vec<PeerId>) -> Box<dyn ILegacyTestClient>;

    /// Creates a mint tx useful for test scenarios
    fn create_mint_tx(
        &self,
        input: TieredMulti<SpendableNote>,
        output: Amount,
    ) -> fedimint_core::transaction::Transaction;

    /// Helper for creating a peg-in proof
    fn create_peg_in_proof(
        &self,
        txout_proof: TxOutProof,
        btc_transaction: BitcoinTransaction,
    ) -> PegInProof;

    /// Returns the config of the client
    fn config(&self) -> ClientConfig;

    /// Fetches epoch history for testing
    fn fetch_epoch_history(&self, epoch: u64, epoch_pk: PublicKey) -> SignedEpochOutcome;

    /// Creates a LN tx useful for test scenarios
    fn create_offer_tx(
        &self,
        amount: Amount,
        payment_hash: Sha256Hash,
        payment_secret: Preimage,
        expiry_time: Option<u64>,
    ) -> fedimint_core::transaction::Transaction;
}
