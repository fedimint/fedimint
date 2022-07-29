// TODO: once user and mint client are merged, make this private again
pub mod db;
pub mod incoming;
pub mod outgoing;

use crate::api::ApiError;
use crate::ln::db::{OutgoingPaymentKey, OutgoingPaymentKeyPrefix};
use crate::ln::incoming::IncomingContractAccount;
use crate::ln::outgoing::{OutgoingContractAccount, OutgoingContractData};
use crate::utils::BorrowedClientContext;
use bitcoin_hashes::sha256::Hash as Sha256Hash;
use lightning_invoice::Invoice;
use minimint_api::db::batch::BatchTx;
use minimint_api::Amount;
use minimint_core::modules::ln::config::LightningModuleClientConfig;
use minimint_core::modules::ln::contracts::incoming::{EncryptedPreimage, IncomingContractOffer};
use minimint_core::modules::ln::contracts::outgoing::OutgoingContract;
use minimint_core::modules::ln::contracts::{
    Contract, ContractId, FundedContract, IdentifyableContract,
};
use minimint_core::modules::ln::{
    ContractAccount, ContractInput, ContractOrOfferOutput, ContractOutput, LightningGateway,
};
use rand::{CryptoRng, RngCore};
use std::time::Duration;
use thiserror::Error;

use self::db::ConfirmedInvoiceKey;
use self::incoming::ConfirmedInvoice;

pub struct LnClient<'c> {
    pub context: BorrowedClientContext<'c, LightningModuleClientConfig>,
}

#[allow(dead_code)]
impl<'c> LnClient<'c> {
    /// Create an output that incentivizes a Lighning gateway to pay an invoice for us. It has time
    /// till the block height defined by `timelock`, after that we can claim our money back.
    pub async fn create_outgoing_output<'a>(
        &'a self,
        mut batch: BatchTx<'a>,
        invoice: Invoice,
        gateway: &LightningGateway,
        timelock: u32,
        mut rng: impl RngCore + CryptoRng + 'a,
    ) -> Result<ContractOrOfferOutput> {
        let contract_amount = {
            let invoice_amount_msat = invoice
                .amount_milli_satoshis()
                .ok_or(LnClientError::MissingInvoiceAmount)?;
            // TODO: better define fee handling
            // Add 1% fee margin
            let contract_amount_msat = invoice_amount_msat + (invoice_amount_msat / 100);
            Amount::from_msat(contract_amount_msat)
        };

        let user_sk = bitcoin::KeyPair::new(self.context.secp, &mut rng);

        let contract = OutgoingContract {
            hash: *invoice.payment_hash(),
            gateway_key: gateway.mint_pub_key,
            timelock,
            user_key: user_sk.public_key(),
            invoice: invoice.to_string(),
        };

        let outgoing_payment = OutgoingContractData {
            recovery_key: user_sk,
            contract_account: OutgoingContractAccount {
                amount: contract_amount,
                contract: contract.clone(),
            },
        };

        batch.append_insert_new(OutgoingPaymentKey(contract.contract_id()), outgoing_payment);

        batch.commit();
        Ok(ContractOrOfferOutput::Contract(ContractOutput {
            amount: contract_amount,
            contract: Contract::Outgoing(contract),
        }))
    }

    pub async fn get_contract_account(&self, id: ContractId) -> Result<ContractAccount> {
        self.context
            .api
            .await_contract(id, Duration::from_secs(10))
            .await
            .map_err(LnClientError::ApiError)
    }

    pub async fn get_outgoing_contract(&self, id: ContractId) -> Result<OutgoingContractAccount> {
        let account = self.get_contract_account(id).await?;
        match account.contract {
            FundedContract::Outgoing(c) => Ok(OutgoingContractAccount {
                amount: account.amount,
                contract: c,
            }),
            _ => Err(LnClientError::WrongAccountType),
        }
    }

    pub async fn get_incoming_contract(&self, id: ContractId) -> Result<IncomingContractAccount> {
        let account = self.get_contract_account(id).await?;
        match account.contract {
            FundedContract::Incoming(c) => Ok(IncomingContractAccount {
                amount: account.amount,
                contract: c.contract,
            }),
            _ => Err(LnClientError::WrongAccountType),
        }
    }
    pub fn refundable_outgoing_contracts(&self, block_height: u64) -> Vec<OutgoingContractData> {
        // TODO: unify block height type
        self.context
            .db
            .find_by_prefix(&OutgoingPaymentKeyPrefix)
            .filter_map(|res| {
                let (_key, outgoing_data) = res.expect("DB error");
                if outgoing_data.contract_account.contract.timelock as u64 <= block_height {
                    Some(outgoing_data)
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn create_refund_outgoing_contract_input<'a>(
        &self,
        contract_data: &'a OutgoingContractData,
    ) -> (&'a bitcoin::KeyPair, ContractInput) {
        (
            &contract_data.recovery_key,
            contract_data.contract_account.refund(),
        )
    }

    pub fn create_offer_output(
        &self,
        amount: Amount,
        payment_hash: Sha256Hash,
        payment_secret: [u8; 32],
    ) -> ContractOrOfferOutput {
        ContractOrOfferOutput::Offer(IncomingContractOffer {
            amount,
            hash: payment_hash,
            encrypted_preimage: EncryptedPreimage::new(
                payment_secret,
                &self.context.config.threshold_pub_key,
            ),
        })
    }

    pub async fn get_offer(&self, payment_hash: Sha256Hash) -> Result<IncomingContractOffer> {
        self.context
            .api
            .await_offer(payment_hash, Duration::from_secs(10))
            .await
            .map_err(LnClientError::ApiError)
    }

    pub fn save_confirmed_invoice(&self, invoice: &ConfirmedInvoice) {
        self.context
            .db
            .insert_entry(&ConfirmedInvoiceKey(invoice.contract_id()), invoice)
            .expect("Db error");
    }

    pub fn get_confirmed_invoice(&self, contract_id: ContractId) -> Result<ConfirmedInvoice> {
        let confirmed_invoice = self
            .context
            .db
            .get_value(&ConfirmedInvoiceKey(contract_id))
            .expect("Db error")
            .ok_or(LnClientError::NoConfirmedInvoice(contract_id))?;
        Ok(confirmed_invoice)
    }
}

pub type Result<T> = std::result::Result<T, LnClientError>;

#[derive(Debug, Error)]
pub enum LnClientError {
    #[error("We can't pay an amountless invoice")]
    MissingInvoiceAmount,
    #[error("Mint API error: {0}")]
    ApiError(ApiError),
    #[error("Mint returned unexpected account type")]
    WrongAccountType,
    #[error("No ConfirmedOffer found for contract ID {0}")]
    NoConfirmedInvoice(ContractId),
}

#[cfg(test)]
mod tests {
    use crate::api::FederationApi;
    use crate::ln::LnClient;
    use crate::OwnedClientContext;
    use async_trait::async_trait;
    use bitcoin::Address;
    use lightning_invoice::Invoice;
    use minimint_api::db::batch::DbBatch;
    use minimint_api::db::mem_impl::MemDatabase;
    use minimint_api::module::testing::FakeFed;
    use minimint_api::{Amount, OutPoint, TransactionId};
    use minimint_core::modules::ln::config::LightningModuleClientConfig;
    use minimint_core::modules::ln::contracts::incoming::IncomingContractOffer;
    use minimint_core::modules::ln::contracts::{ContractId, IdentifyableContract};
    use minimint_core::modules::ln::{ContractAccount, LightningModule};
    use minimint_core::modules::ln::{ContractOrOfferOutput, LightningGateway};
    use minimint_core::modules::wallet::PegOutFees;
    use minimint_core::outcome::{OutputOutcome, TransactionStatus};
    use minimint_core::transaction::Transaction;
    use std::sync::Arc;

    type Fed = FakeFed<LightningModule, LightningModuleClientConfig>;

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
                outputs: vec![OutputOutcome::LN(
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
            contract: ContractId,
        ) -> crate::api::Result<ContractAccount> {
            Ok(self
                .mint
                .lock()
                .await
                .fetch_from_all(|m| m.get_contract_account(contract))
                .unwrap())
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
    }

    async fn new_mint_and_client() -> (
        Arc<tokio::sync::Mutex<Fed>>,
        OwnedClientContext<LightningModuleClientConfig>,
    ) {
        let fed = Arc::new(tokio::sync::Mutex::new(
            FakeFed::<LightningModule, LightningModuleClientConfig>::new(
                4,
                1,
                |cfg, db| async { LightningModule::new(cfg, Arc::new(db)) },
                &(),
            )
            .await,
        ));
        let api = FakeApi { mint: fed.clone() };

        let client_context = OwnedClientContext {
            config: fed.lock().await.client_cfg().clone(),
            db: Box::new(MemDatabase::new()),
            api: Box::new(api),
            secp: secp256k1_zkp::Secp256k1::new(),
        };

        (fed, client_context)
    }

    #[test_log::test(tokio::test)]
    async fn test_outgoing() {
        let mut rng = rand::thread_rng();
        let (fed, client_context) = new_mint_and_client().await;

        let client = LnClient {
            context: client_context.borrow_with_module_config(|x| x),
        };

        fed.lock().await.set_block_height(1);

        let out_point = OutPoint {
            txid: Default::default(),
            out_idx: 0,
        };

        let invoice: Invoice =
            "lnbcrt1u1pslya9jpp58005t06rezrqx2g6e84j44gs0aalcxfc47nzu97040fjzfrl\
        cmasdq8w3jhxaqxqyjw5qcqp2sp5huz0lzk5v47kfdd58d0k96gm06kr2rkedgr5j8488jaqk44puz6s9qyyssqexyz\
        s9rzrhu73625ag4ndtw4fqmstrnuaukh3z427la6mn2m2u25zy7j2jfk36pcsz5hl4m07ehcmhvh729424tjagv4lx2\
        vgdsgy3sqphsc92"
                .parse()
                .unwrap();
        let invoice_amt_msat = invoice.amount_milli_satoshis().unwrap();
        let gateway = {
            let mint_pub_key = secp256k1_zkp::XOnlyPublicKey::from_slice(&[42; 32][..]).unwrap();
            let node_pub_key = secp256k1_zkp::PublicKey::from_slice(&[2; 33][..]).unwrap();
            LightningGateway {
                mint_pub_key,
                node_pub_key,
                api: "".to_string(),
            }
        };
        let timelock = 42;

        let mut batch = DbBatch::new();
        let output = client
            .create_outgoing_output(
                batch.transaction(),
                invoice.clone(),
                &gateway,
                timelock,
                &mut rng,
            )
            .await
            .unwrap();
        client_context.db.apply_batch(batch).unwrap();

        let contract = match &output {
            ContractOrOfferOutput::Contract(c) => &c.contract,
            _ => unreachable!(),
        };

        fed.lock()
            .await
            .consensus_round(&[], &[(out_point, output.clone())])
            .await;

        let contract_acc = client
            .get_outgoing_contract(contract.contract_id())
            .await
            .unwrap();

        assert_eq!(contract_acc.contract.contract_id(), contract.contract_id());
        assert_eq!(contract_acc.contract.invoice, invoice.to_string());
        assert_eq!(contract_acc.contract.timelock, timelock);
        assert_eq!(contract_acc.contract.hash, *invoice.payment_hash());
        assert_eq!(contract_acc.contract.gateway_key, gateway.mint_pub_key);
        // TODO: test that the client has its key

        let expected_amount_msat = invoice_amt_msat + (invoice_amt_msat / 100);
        let expected_amount = Amount::from_msat(expected_amount_msat);
        assert_eq!(contract_acc.amount, expected_amount);

        // We need to compensate for the wallet's confirmation target
        fed.lock().await.set_block_height((timelock - 1) as u64);

        assert!(client
            .refundable_outgoing_contracts((timelock - 1) as u64)
            .is_empty());
        let refund_inputs = client.refundable_outgoing_contracts((timelock) as u64);
        assert_eq!(refund_inputs.len(), 1);
        let contract_data = refund_inputs.into_iter().next().unwrap();
        let (refund_key, refund_input) =
            client.create_refund_outgoing_contract_input(&contract_data);
        assert!(fed.lock().await.verify_input(&refund_input).is_err());

        // We need to compensate for the wallet's confirmation target
        fed.lock().await.set_block_height(timelock as u64);

        let meta = fed.lock().await.verify_input(&refund_input).unwrap();
        let refund_pk = secp256k1_zkp::XOnlyPublicKey::from_keypair(refund_key);
        assert_eq!(meta.keys, vec![refund_pk]);
        assert_eq!(meta.amount, expected_amount);

        fed.lock().await.consensus_round(&[refund_input], &[]).await;

        let account = client
            .get_outgoing_contract(contract.contract_id())
            .await
            .unwrap();
        assert_eq!(account.amount, Amount::ZERO);
    }
}
