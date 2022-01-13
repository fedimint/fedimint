mod db;
pub mod gateway;
mod outgoing;

use crate::api::FederationApi;
use crate::ln::db::OutgoingPaymentKey;
use crate::ln::gateway::LightningGateway;
use crate::ln::outgoing::{OutgoingContractAccount, OutgoingContractData};
use crate::ApiError;
use lightning_invoice::Invoice;
use minimint::modules::ln;
use minimint::modules::ln::contracts::outgoing::OutgoingContract;
use minimint::modules::ln::contracts::{
    Contract, ContractId, FundedContract, IdentifyableContract,
};
use minimint::modules::ln::{ContractAccount, ContractOrOfferOutput, ContractOutput};
use minimint_api::db::batch::BatchTx;
use minimint_api::db::RawDatabase;
use minimint_api::Amount;
use rand::{CryptoRng, RngCore};
use std::sync::Arc;
use thiserror::Error;

pub struct LnClient {
    pub db: Arc<dyn RawDatabase>,
    pub cfg: ln::config::LightningModuleClientConfig,
    pub api: Arc<dyn FederationApi>,
    pub secp: secp256k1_zkp::Secp256k1<secp256k1_zkp::All>,
}

#[allow(dead_code)]
impl LnClient {
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

        let user_sk = secp256k1_zkp::schnorrsig::KeyPair::new(&self.secp, &mut rng);

        let contract = OutgoingContract {
            hash: *invoice.payment_hash(),
            gateway_key: gateway.mint_pub_key,
            timelock,
            user_key: secp256k1_zkp::schnorrsig::PublicKey::from_keypair(&self.secp, &user_sk),
            invoice: invoice.to_string(),
        };

        let outgoing_payment = OutgoingContractData {
            recovery_key: user_sk,
            contract: contract.clone(),
        };

        batch.append_insert_new(OutgoingPaymentKey(contract.contract_id()), outgoing_payment);

        Ok(ContractOrOfferOutput::Contract(ContractOutput {
            amount: contract_amount,
            contract: Contract::Outgoing(contract),
        }))
    }

    pub async fn get_contract_account(&self, id: ContractId) -> Result<ContractAccount> {
        self.api
            .fetch_contract(id)
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
}

#[cfg(test)]
mod tests {
    use crate::api::FederationApi;
    use crate::ln::gateway::LightningGateway;
    use crate::ln::LnClient;
    use async_trait::async_trait;
    use lightning::routing::network_graph::RoutingFees;
    use lightning_invoice::Invoice;
    use minimint::modules::ln::config::LightningModuleClientConfig;
    use minimint::modules::ln::contracts::{ContractId, IdentifyableContract};
    use minimint::modules::ln::ContractOrOfferOutput;
    use minimint::modules::ln::{ContractAccount, LightningModule};
    use minimint::outcome::{OutputOutcome, TransactionStatus};
    use minimint::transaction::Transaction;
    use minimint_api::db::batch::DbBatch;
    use minimint_api::db::mem_impl::MemDatabase;
    use minimint_api::db::{Database, RawDatabase};
    use minimint_api::module::testing::FakeFed;
    use minimint_api::{Amount, OutPoint, TransactionId};
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
    }

    async fn new_mint_and_client() -> (Arc<tokio::sync::Mutex<Fed>>, LnClient, Arc<dyn RawDatabase>)
    {
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

        let client_db: Arc<dyn RawDatabase> = Arc::new(MemDatabase::new());
        let client = LnClient {
            db: client_db.clone(),
            cfg: fed.lock().await.client_cfg().clone(),
            api: Arc::new(api),
            secp: secp256k1_zkp::Secp256k1::new(),
        };

        (fed, client, client_db)
    }

    #[tokio::test]
    async fn test_fund_outgoing() {
        let mut rng = rand::thread_rng();
        let (fed, client, client_db) = new_mint_and_client().await;

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
            let mint_pub_key =
                secp256k1_zkp::schnorrsig::PublicKey::from_slice(&[42; 32][..]).unwrap();
            let node_pub_key = secp256k1_zkp::PublicKey::from_slice(&[2; 33][..]).unwrap();
            LightningGateway {
                mint_pub_key,
                node_pub_key,
                api: "".to_string(),
                // FIXME: GW fees don't really make sense without client side routing, we just overpay and hope for the best
                fees: RoutingFees {
                    base_msat: 0,
                    proportional_millionths: 0,
                },
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
        client_db.apply_batch(batch).unwrap();

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
        assert_eq!(contract_acc.amount, Amount::from_msat(expected_amount_msat))
    }
}
