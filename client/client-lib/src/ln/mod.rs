// TODO: once user and mint client are merged, make this private again
pub mod db;
pub mod incoming;
pub mod outgoing;

use std::sync::Arc;
use std::time::Duration;

use bitcoin_hashes::sha256::Hash as Sha256Hash;
use fedimint_core::api::FederationError;
use fedimint_core::config::FederationId;
use fedimint_core::core::client::ClientModule;
use fedimint_core::core::Decoder;
use fedimint_core::db::DatabaseTransaction;
use fedimint_core::module::TransactionItemAmount;
use fedimint_core::task::timeout;
use fedimint_core::{Amount, ServerModule};
use futures::StreamExt;
use lightning_invoice::Invoice;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use self::db::ConfirmedInvoiceKey;
use self::incoming::ConfirmedInvoice;
use crate::api::{LnFederationApi, WalletFederationApi};
use crate::ln::db::{OutgoingPaymentKey, OutgoingPaymentKeyPrefix};
use crate::ln::incoming::IncomingContractAccount;
use crate::ln::outgoing::{OutgoingContractAccount, OutgoingContractData};
use crate::modules::ln::config::LightningClientConfig;
use crate::modules::ln::contracts::incoming::IncomingContractOffer;
use crate::modules::ln::contracts::outgoing::OutgoingContract;
use crate::modules::ln::contracts::{
    Contract, ContractId, EncryptedPreimage, FundedContract, IdentifyableContract, Preimage,
};
use crate::modules::ln::{
    ContractAccount, ContractOutput, Lightning, LightningGateway, LightningInput, LightningOutput,
};
use crate::utils::ClientContext;

#[derive(Debug)]
pub struct LnClient {
    pub config: LightningClientConfig,
    pub context: Arc<ClientContext>,
}

impl ClientModule for LnClient {
    const KIND: &'static str = "ln";
    type Module = Lightning;

    fn decoder(&self) -> Decoder {
        <Self::Module as ServerModule>::decoder()
    }

    fn input_amount(&self, input: &LightningInput) -> TransactionItemAmount {
        TransactionItemAmount {
            amount: input.amount,
            fee: self.config.fee_consensus.contract_input,
        }
    }

    fn output_amount(&self, output: &LightningOutput) -> TransactionItemAmount {
        match output {
            LightningOutput::Contract(account_output) => TransactionItemAmount {
                amount: account_output.amount,
                fee: self.config.fee_consensus.contract_output,
            },
            LightningOutput::Offer(_) | LightningOutput::CancelOutgoing { .. } => {
                TransactionItemAmount {
                    amount: Amount::ZERO,
                    fee: Amount::ZERO,
                }
            }
        }
    }
}

#[allow(dead_code)]
impl LnClient {
    /// Create an output that incentivizes a Lighning gateway to pay an invoice
    /// for us. It has time till the block height defined by `timelock`,
    /// after that we can claim our money back.
    pub async fn create_outgoing_output<'a, 'b>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'b>,
        invoice: Invoice,
        gateway: &LightningGateway,
        timelock: u32,
        mut rng: impl RngCore + CryptoRng + 'a,
    ) -> Result<LightningOutput> {
        let contract_amount = {
            let invoice_amount_msat = invoice
                .amount_milli_satoshis()
                .ok_or(LnClientError::MissingInvoiceAmount)?;
            // TODO: better define fee handling
            // Add 1% fee margin
            let contract_amount_msat = invoice_amount_msat + (invoice_amount_msat / 100);
            Amount::from_msats(contract_amount_msat)
        };

        let user_sk = bitcoin::KeyPair::new(&self.context.secp, &mut rng);

        let contract = OutgoingContract {
            hash: *invoice.payment_hash(),
            gateway_key: gateway.mint_pub_key,
            timelock,
            user_key: user_sk.x_only_public_key().0,
            invoice,
            cancelled: false,
        };

        let outgoing_payment = OutgoingContractData {
            recovery_key: user_sk,
            contract_account: OutgoingContractAccount {
                amount: contract_amount,
                contract: contract.clone(),
            },
        };

        dbtx.insert_new_entry(
            &OutgoingPaymentKey(contract.contract_id()),
            &outgoing_payment,
        )
        .await
        .expect("DB Error");

        Ok(LightningOutput::Contract(ContractOutput {
            amount: contract_amount,
            contract: Contract::Outgoing(contract),
        }))
    }

    pub async fn get_contract_account(&self, id: ContractId) -> Result<ContractAccount> {
        timeout(Duration::from_secs(30), self.context.api.fetch_contract(id))
            .await
            .map_err(|_e| LnClientError::Timeout)?
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

    /// Determines if an outgoing contract can be refunded
    pub async fn is_outgoing_contract_refundable(&self, id: ContractId) -> Result<bool> {
        let contract = self.get_outgoing_contract(id).await?;

        // If the contract was cancelled by the LN gateway we can get a refund instantly
        // …
        if contract.contract.cancelled {
            return Ok(true);
        }

        // … otherwise we have to wait till the timeout hits
        let consensus_block_height = self
            .context
            .api
            .fetch_consensus_block_height()
            .await
            .map_err(LnClientError::ApiError)?;
        if contract.contract.timelock as u64 <= consensus_block_height {
            return Ok(true);
        }

        Ok(false)
    }

    /// Waits for an outgoing contract to become refundable
    pub async fn await_outgoing_refundable(&self, id: ContractId) -> Result<()> {
        while !self.is_outgoing_contract_refundable(id).await? {
            crate::sleep(Duration::from_secs(1)).await;
        }
        Ok(())
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
    pub async fn refundable_outgoing_contracts(
        &self,
        block_height: u64,
    ) -> Vec<OutgoingContractData> {
        // TODO: unify block height type
        self.context
            .db
            .begin_transaction()
            .await
            .find_by_prefix(&OutgoingPaymentKeyPrefix)
            .await
            .filter_map(|res| async {
                let (_key, outgoing_data) = res.expect("DB error");
                let cancelled = outgoing_data.contract_account.contract.cancelled;
                let timed_out =
                    outgoing_data.contract_account.contract.timelock as u64 <= block_height;
                if cancelled || timed_out {
                    Some(outgoing_data)
                } else {
                    None
                }
            })
            .collect::<Vec<OutgoingContractData>>()
            .await
    }

    pub fn create_refund_outgoing_contract_input<'a>(
        &self,
        contract_data: &'a OutgoingContractData,
    ) -> (&'a bitcoin::KeyPair, LightningInput) {
        (
            &contract_data.recovery_key,
            contract_data.contract_account.refund(),
        )
    }

    pub fn create_offer_output(
        &self,
        amount: Amount,
        payment_hash: Sha256Hash,
        payment_secret: Preimage,
        expiry_time: Option<u64>,
    ) -> LightningOutput {
        LightningOutput::Offer(IncomingContractOffer {
            amount,
            hash: payment_hash,
            encrypted_preimage: EncryptedPreimage::new(
                payment_secret,
                &self.config.threshold_pub_key,
            ),
            expiry_time,
        })
    }

    pub async fn get_offer(&self, payment_hash: Sha256Hash) -> Result<IncomingContractOffer> {
        timeout(
            Duration::from_secs(10),
            self.context.api.fetch_offer(payment_hash),
        )
        .await
        .map_err(|_e| LnClientError::Timeout)?
        .map_err(LnClientError::ApiError)
    }

    pub async fn offer_exists(&self, payment_hash: Sha256Hash) -> Result<bool> {
        self.context
            .api
            .offer_exists(payment_hash)
            .await
            .map_err(LnClientError::ApiError)
    }

    pub async fn save_confirmed_invoice(&self, invoice: &ConfirmedInvoice) {
        let mut dbtx = self.context.db.begin_transaction().await;
        dbtx.insert_entry(&ConfirmedInvoiceKey(invoice.contract_id()), invoice)
            .await
            .expect("Db error");
        dbtx.commit_tx().await.expect("DB Error");
    }

    pub async fn get_confirmed_invoice(&self, contract_id: ContractId) -> Result<ConfirmedInvoice> {
        let confirmed_invoice = self
            .context
            .db
            .begin_transaction()
            .await
            .get_value(&ConfirmedInvoiceKey(contract_id))
            .await
            .expect("Db error")
            .ok_or(LnClientError::NoConfirmedInvoice(contract_id))?;
        Ok(confirmed_invoice)
    }

    /// Used by gateway to prematurely return funds to the user if the payment
    /// failed
    pub fn create_cancel_outgoing_output(
        &self,
        contract_id: ContractId,
        signature: secp256k1_zkp::schnorr::Signature,
    ) -> LightningOutput {
        LightningOutput::CancelOutgoing {
            contract: contract_id,
            gateway_signature: signature,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PayInvoicePayload {
    pub federation_id: FederationId,
    pub contract_id: ContractId,
}

impl PayInvoicePayload {
    pub fn new(federation_id: FederationId, contract_id: ContractId) -> Self {
        Self {
            contract_id,
            federation_id,
        }
    }
}

pub type Result<T> = std::result::Result<T, LnClientError>;

#[derive(Debug, Error)]
pub enum LnClientError {
    #[error("We can't pay an amountless invoice")]
    MissingInvoiceAmount,
    #[error("Mint API error: {0}")]
    ApiError(FederationError),
    #[error("Timeout")]
    Timeout,
    #[error("Mint returned unexpected account type")]
    WrongAccountType,
    #[error("No ConfirmedOffer found for contract ID {0}")]
    NoConfirmedInvoice(ContractId),
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::SystemTime;

    use bitcoin::hashes::{sha256, Hash};
    use fedimint_core::config::ConfigGenParams;
    use fedimint_core::core::{
        DynOutputOutcome, ModuleInstanceId, LEGACY_HARDCODED_INSTANCE_ID_LN,
    };
    use fedimint_core::db::mem_impl::MemDatabase;
    use fedimint_core::db::Database;
    use fedimint_core::module::registry::ModuleDecoderRegistry;
    use fedimint_core::outcome::{SerdeOutputOutcome, TransactionStatus};
    use fedimint_core::{Amount, OutPoint, ServerModule, TransactionId};
    use fedimint_testing::FakeFed;
    use lightning_invoice::Invoice;
    use tokio::sync::Mutex;
    use url::Url;

    use crate::api::fake::FederationApiFaker;
    use crate::ln::LnClient;
    use crate::modules::ln::config::LightningClientConfig;
    use crate::modules::ln::contracts::{ContractId, IdentifyableContract};
    use crate::modules::ln::{Lightning, LightningGateway, LightningGen, LightningOutput};
    use crate::{module_decode_stubs, ClientContext};

    type Fed = FakeFed<Lightning>;

    async fn make_test_mint_fed(
        module_id: ModuleInstanceId,
        fed: Arc<Mutex<FakeFed<Lightning>>>,
    ) -> FederationApiFaker<tokio::sync::Mutex<FakeFed<Lightning>>> {
        let members = fed
            .lock()
            .await
            .members
            .iter()
            .map(|(peer_id, _, _, _)| *peer_id)
            .collect();
        FederationApiFaker::new(fed, members)
            // TODO: is the output here is supposed to be a mint or wallet?
            .with(
                "/fetch_transaction",
                move |mint: Arc<Mutex<FakeFed<Lightning>>>, tx: TransactionId| async move {
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
            .with(
                format!("/module/{module_id}/account"),
                |mint: Arc<Mutex<FakeFed<Lightning>>>, contract: ContractId| async move {
                    Ok(mint
                        .lock()
                        .await
                        .fetch_from_all(|m, db, module_instance_id| async {
                            m.get_contract_account(
                                &mut db
                                    .begin_transaction()
                                    .await
                                    .with_module_prefix(*module_instance_id),
                                contract,
                            )
                            .await
                        })
                        .await
                        .unwrap())
                },
            )
    }

    async fn new_mint_and_client() -> (
        Arc<tokio::sync::Mutex<Fed>>,
        LightningClientConfig,
        ClientContext,
    ) {
        let module_id = LEGACY_HARDCODED_INSTANCE_ID_LN;
        let fed = Arc::new(tokio::sync::Mutex::new(
            FakeFed::<Lightning>::new(
                4,
                |cfg, _db| async move { Ok(Lightning::new(cfg.to_typed()?)) },
                &ConfigGenParams::new(),
                &LightningGen,
                module_id,
            )
            .await
            .unwrap(),
        ));
        let api = make_test_mint_fed(module_id, fed.clone()).await;
        let client_config = fed.lock().await.client_cfg().clone();

        let client_context = ClientContext {
            decoders: ModuleDecoderRegistry::from_iter([(
                LEGACY_HARDCODED_INSTANCE_ID_LN,
                <Lightning as ServerModule>::decoder(),
            )]),
            module_gens: Default::default(),
            db: Database::new(MemDatabase::new(), module_decode_stubs()),
            api: api.into(),
            secp: secp256k1_zkp::Secp256k1::new(),
        };

        (fed, client_config.cast().unwrap(), client_context)
    }

    #[test_log::test(tokio::test)]
    async fn test_outgoing() {
        let mut rng = rand::thread_rng();
        let (fed, client_config, client_context) = new_mint_and_client().await;

        let client = LnClient {
            config: client_config,
            context: Arc::new(client_context),
        };

        fed.lock().await.set_block_height(1);

        let out_point = OutPoint {
            txid: sha256::Hash::hash(b"txid").into(),
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
                mint_channel_id: 0,
                mint_pub_key,
                node_pub_key,
                api: Url::parse("http://example.com")
                    .expect("Could not parse URL to generate GatewayClientConfig API endpoint"),
                route_hints: vec![],
                valid_until: SystemTime::now(),
            }
        };
        let timelock = 42;

        let mut dbtx = client.context.db.begin_transaction().await;
        let output = client
            .create_outgoing_output(&mut dbtx, invoice.clone(), &gateway, timelock, &mut rng)
            .await
            .unwrap();

        dbtx.commit_tx().await.expect("DB Error");

        let contract = match &output {
            LightningOutput::Contract(c) => &c.contract,
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
        assert_eq!(contract_acc.contract.invoice, invoice);
        assert_eq!(contract_acc.contract.timelock, timelock);
        assert_eq!(contract_acc.contract.hash, *invoice.payment_hash());
        assert_eq!(contract_acc.contract.gateway_key, gateway.mint_pub_key);
        // TODO: test that the client has its key

        let expected_amount_msat = invoice_amt_msat + (invoice_amt_msat / 100);
        let expected_amount = Amount::from_msats(expected_amount_msat);
        assert_eq!(contract_acc.amount, expected_amount);

        // We need to compensate for the wallet's confirmation target
        fed.lock().await.set_block_height((timelock - 1) as u64);

        assert!(client
            .refundable_outgoing_contracts((timelock - 1) as u64)
            .await
            .is_empty());
        let refund_inputs = client
            .refundable_outgoing_contracts((timelock) as u64)
            .await;
        assert_eq!(refund_inputs.len(), 1);
        let contract_data = refund_inputs.into_iter().next().unwrap();
        let (refund_key, refund_input) =
            client.create_refund_outgoing_contract_input(&contract_data);
        assert!(fed.lock().await.verify_input(&refund_input).await.is_err());

        // We need to compensate for the wallet's confirmation target
        fed.lock().await.set_block_height(timelock as u64);

        let meta = fed.lock().await.verify_input(&refund_input).await.unwrap();
        let refund_pk = secp256k1_zkp::XOnlyPublicKey::from_keypair(refund_key).0;
        assert_eq!(meta.keys, vec![refund_pk]);
        assert_eq!(meta.amount.amount, expected_amount);

        fed.lock().await.consensus_round(&[refund_input], &[]).await;

        let account = client
            .get_outgoing_contract(contract.contract_id())
            .await
            .unwrap();
        assert_eq!(account.amount, Amount::ZERO);
    }
}
