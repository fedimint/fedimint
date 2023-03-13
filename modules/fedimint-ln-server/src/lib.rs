use std::collections::{BTreeMap, HashMap, HashSet};
use std::ffi::OsString;
use std::ops::Sub;

use bitcoin_hashes::Hash as BitcoinHash;
use fedimint_core::config::{
    ConfigGenParams, DkgResult, ModuleConfigResponse, ServerModuleConfig, TypedServerModuleConfig,
    TypedServerModuleConsensusConfig,
};
use fedimint_core::core::{ModuleInstanceId, LEGACY_HARDCODED_INSTANCE_ID_WALLET};
use fedimint_core::db::{Database, DatabaseVersion, ModuleDatabaseTransaction};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::audit::Audit;
use fedimint_core::module::interconnect::ModuleInterconect;
use fedimint_core::module::{
    api_endpoint, ApiEndpoint, ApiError, ApiRequestErased, ApiVersion, ConsensusProposal,
    CoreConsensusVersion, ExtendsCommonModuleGen, InputMeta, IntoModuleError,
    ModuleConsensusVersion, ModuleError, PeerHandle, ServerModuleGen, TransactionItemAmount,
};
use fedimint_core::server::DynServerModule;
use fedimint_core::task::TaskGroup;
use fedimint_core::{
    apply, async_trait_maybe_send, push_db_pair_items, Amount, NumPeers, OutPoint, PeerId,
    ServerModule,
};
pub use fedimint_ln_common as common;
use fedimint_ln_common::config::{
    FeeConsensus, LightningConfig, LightningConfigConsensus, LightningConfigPrivate,
};
use fedimint_ln_common::contracts::incoming::IncomingContractOffer;
use fedimint_ln_common::contracts::{
    Contract, ContractId, ContractOutcome, DecryptedPreimage, EncryptedPreimage, FundedContract,
    IdentifiableContract, Preimage, PreimageDecryptionShare,
};
use fedimint_ln_common::db::{
    AgreedDecryptionShareKey, AgreedDecryptionShareKeyPrefix, ContractKey, ContractKeyPrefix,
    ContractUpdateKey, ContractUpdateKeyPrefix, DbKeyPrefix, LightningGatewayKey,
    LightningGatewayKeyPrefix, OfferKey, OfferKeyPrefix, ProposeDecryptionShareKey,
    ProposeDecryptionShareKeyPrefix,
};
use fedimint_ln_common::{
    ContractAccount, LightningCommonGen, LightningConsensusItem, LightningError, LightningGateway,
    LightningInput, LightningModuleTypes, LightningOutput, LightningOutputOutcome,
};
use fedimint_server::config::distributedgen::PeerHandleOps;
use futures::StreamExt;
use itertools::Itertools;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use strum::IntoEnumIterator;
use tracing::{debug, error, info_span, instrument, trace, warn};

#[derive(Debug, Clone)]
pub struct LightningGen;

impl ExtendsCommonModuleGen for LightningGen {
    type Common = LightningCommonGen;
}

#[apply(async_trait_maybe_send!)]
impl ServerModuleGen for LightningGen {
    const DATABASE_VERSION: DatabaseVersion = DatabaseVersion(0);

    fn versions(&self, _core: CoreConsensusVersion) -> &[ModuleConsensusVersion] {
        &[ModuleConsensusVersion(0)]
    }

    async fn init(
        &self,
        cfg: ServerModuleConfig,
        _db: Database,
        _env: &BTreeMap<OsString, OsString>,
        _task_group: &mut TaskGroup,
    ) -> anyhow::Result<DynServerModule> {
        Ok(Lightning::new(cfg.to_typed()?).into())
    }

    fn trusted_dealer_gen(
        &self,
        peers: &[PeerId],
        _params: &ConfigGenParams,
    ) -> BTreeMap<PeerId, ServerModuleConfig> {
        let sks = threshold_crypto::SecretKeySet::random(peers.degree(), &mut OsRng);
        let pks = sks.public_keys();

        let server_cfg = peers
            .iter()
            .map(|&peer| {
                let sk = sks.secret_key_share(peer.to_usize());

                (
                    peer,
                    LightningConfig {
                        consensus: LightningConfigConsensus {
                            threshold_pub_keys: pks.clone(),
                            fee_consensus: FeeConsensus::default(),
                        },
                        private: LightningConfigPrivate {
                            threshold_sec_key: threshold_crypto::serde_impl::SerdeSecret(sk),
                        },
                    }
                    .to_erased(),
                )
            })
            .collect();

        server_cfg
    }

    async fn distributed_gen(
        &self,
        peers: &PeerHandle,
        _params: &ConfigGenParams,
    ) -> DkgResult<ServerModuleConfig> {
        let g1 = peers.run_dkg_g1(()).await?;

        let keys = g1[&()].threshold_crypto();

        let server = LightningConfig {
            consensus: LightningConfigConsensus {
                threshold_pub_keys: keys.public_key_set,
                fee_consensus: Default::default(),
            },
            private: LightningConfigPrivate {
                threshold_sec_key: keys.secret_key_share,
            },
        };

        Ok(server.to_erased())
    }

    fn to_config_response(
        &self,
        config: serde_json::Value,
    ) -> anyhow::Result<ModuleConfigResponse> {
        let config = serde_json::from_value::<LightningConfigConsensus>(config)?;

        Ok(ModuleConfigResponse {
            client: config.to_client_config(),
            consensus_hash: config.consensus_hash()?,
        })
    }

    fn validate_config(&self, identity: &PeerId, config: ServerModuleConfig) -> anyhow::Result<()> {
        config
            .to_typed::<LightningConfig>()?
            .validate_config(identity)
    }

    async fn dump_database(
        &self,
        dbtx: &mut ModuleDatabaseTransaction<'_, ModuleInstanceId>,
        prefix_names: Vec<String>,
    ) -> Box<dyn Iterator<Item = (String, Box<dyn erased_serde::Serialize + Send>)> + '_> {
        let mut lightning: BTreeMap<String, Box<dyn erased_serde::Serialize + Send>> =
            BTreeMap::new();
        let filtered_prefixes = DbKeyPrefix::iter().filter(|f| {
            prefix_names.is_empty() || prefix_names.contains(&f.to_string().to_lowercase())
        });
        for table in filtered_prefixes {
            match table {
                DbKeyPrefix::AgreedDecryptionShare => {
                    push_db_pair_items!(
                        dbtx,
                        AgreedDecryptionShareKeyPrefix,
                        AgreedDecryptionShareKey,
                        PreimageDecryptionShare,
                        lightning,
                        "Accepted Decryption Shares"
                    );
                }
                DbKeyPrefix::Contract => {
                    push_db_pair_items!(
                        dbtx,
                        ContractKeyPrefix,
                        ContractKey,
                        ContractAccount,
                        lightning,
                        "Contracts"
                    );
                }
                DbKeyPrefix::ContractUpdate => {
                    push_db_pair_items!(
                        dbtx,
                        ContractUpdateKeyPrefix,
                        ContractUpdateKey,
                        LightningOutputOutcome,
                        lightning,
                        "Contract Updates"
                    );
                }
                DbKeyPrefix::LightningGateway => {
                    push_db_pair_items!(
                        dbtx,
                        LightningGatewayKeyPrefix,
                        LightningGatewayKey,
                        LightningGateway,
                        lightning,
                        "Lightning Gateways"
                    );
                }
                DbKeyPrefix::Offer => {
                    push_db_pair_items!(
                        dbtx,
                        OfferKeyPrefix,
                        OfferKey,
                        IncomingContractOffer,
                        lightning,
                        "Offers"
                    );
                }
                DbKeyPrefix::ProposeDecryptionShare => {
                    push_db_pair_items!(
                        dbtx,
                        ProposeDecryptionShareKeyPrefix,
                        ProposeDecryptionShareKey,
                        PreimageDecryptionShare,
                        lightning,
                        "Proposed Decryption Shares"
                    );
                }
            }
        }

        Box::new(lightning.into_iter())
    }
}
/// The lightning module implements an account system. It does not have the
/// privacy guarantees of the e-cash mint module but instead allows for smart
/// contracting. There exist three contract types that can be used to "lock"
/// accounts:
///
///   * [Outgoing]: an account locked with an HTLC-like contract allowing to
///     incentivize an external Lightning node to make payments for the funder
///   * [Incoming]: a contract type that represents the acquisition of a
///     preimage belonging to a hash. Every incoming contract is preceded by an
///     offer that specifies how much the seller is asking for the preimage to a
///     particular hash. It also contains some threshold-encrypted data. Once
///     the contract is funded the data is decrypted. If it is a valid preimage
///     the contract's funds are now accessible to the creator of the offer, if
///     not they are accessible to the funder.
///
/// These three primitives allow to integrate the federation with the wider
/// Lightning network through a centralized but untrusted (except for
/// availability) Lightning gateway server.
///
/// [Outgoing]: fedimint_ln_common::contracts::outgoing::OutgoingContract
/// [Incoming]: fedimint_ln_common::contracts::incoming::IncomingContract
#[derive(Debug)]
pub struct Lightning {
    cfg: LightningConfig,
}

#[apply(async_trait_maybe_send!)]
impl ServerModule for Lightning {
    type Common = LightningModuleTypes;
    type Gen = LightningGen;
    type VerificationCache = LightningVerificationCache;

    fn versions(&self) -> (ModuleConsensusVersion, &[ApiVersion]) {
        (
            ModuleConsensusVersion(0),
            &[ApiVersion { major: 0, minor: 0 }],
        )
    }

    async fn await_consensus_proposal(
        &self,
        dbtx: &mut ModuleDatabaseTransaction<'_, ModuleInstanceId>,
    ) {
        if !self.consensus_proposal(dbtx).await.forces_new_epoch() {
            std::future::pending().await
        }
    }

    async fn consensus_proposal(
        &self,
        dbtx: &mut ModuleDatabaseTransaction<'_, ModuleInstanceId>,
    ) -> ConsensusProposal<LightningConsensusItem> {
        ConsensusProposal::new_auto_trigger(
            dbtx.find_by_prefix(&ProposeDecryptionShareKeyPrefix)
                .await
                .map(
                    |(ProposeDecryptionShareKey(contract_id), share)| LightningConsensusItem {
                        contract_id,
                        share,
                    },
                )
                .collect::<Vec<LightningConsensusItem>>()
                .await,
        )
    }

    async fn begin_consensus_epoch<'a, 'b>(
        &'a self,
        dbtx: &mut ModuleDatabaseTransaction<'b, ModuleInstanceId>,
        consensus_items: Vec<(PeerId, LightningConsensusItem)>,
    ) {
        for (peer, decryption_share) in consensus_items.into_iter() {
            let span = info_span!("process decryption share", %peer);
            let _guard = span.enter();

            dbtx.insert_new_entry(
                &AgreedDecryptionShareKey(decryption_share.contract_id, peer),
                &decryption_share.share,
            )
            .await;
        }
    }

    fn build_verification_cache<'a>(
        &'a self,
        _inputs: impl Iterator<Item = &'a LightningInput>,
    ) -> Self::VerificationCache {
        LightningVerificationCache
    }

    async fn validate_input<'a, 'b>(
        &self,
        interconnect: &dyn ModuleInterconect,
        dbtx: &mut ModuleDatabaseTransaction<'b, ModuleInstanceId>,
        _verification_cache: &Self::VerificationCache,
        input: &'a LightningInput,
    ) -> Result<InputMeta, ModuleError> {
        let account: ContractAccount = self
            .get_contract_account(dbtx, input.contract_id)
            .await
            .ok_or(LightningError::UnknownContract(input.contract_id))
            .into_module_error_other()?;

        if account.amount < input.amount {
            return Err(LightningError::InsufficientFunds(
                account.amount,
                input.amount,
            ))
            .into_module_error_other();
        }

        let pub_key = match account.contract {
            FundedContract::Outgoing(outgoing) => {
                if outgoing.timelock > block_height(interconnect).await && !outgoing.cancelled {
                    // If the timelock hasn't expired yet …
                    let preimage_hash = bitcoin_hashes::sha256::Hash::hash(
                        &input
                            .witness
                            .as_ref()
                            .ok_or(LightningError::MissingPreimage)
                            .into_module_error_other()?
                            .0,
                    );

                    // … and the spender provides a valid preimage …
                    if preimage_hash != outgoing.hash {
                        return Err(LightningError::InvalidPreimage).into_module_error_other();
                    }

                    // … then the contract account can be spent using the gateway key,
                    outgoing.gateway_key
                } else {
                    // otherwise the user can claim the funds back.
                    outgoing.user_key
                }
            }
            FundedContract::Incoming(incoming) => match incoming.contract.decrypted_preimage {
                // Once the preimage has been decrypted …
                DecryptedPreimage::Pending => {
                    return Err(LightningError::ContractNotReady).into_module_error_other();
                }
                // … either the user may spend the funds since they sold a valid preimage …
                DecryptedPreimage::Some(preimage) => match preimage.to_public_key() {
                    Ok(pub_key) => pub_key,
                    Err(_) => {
                        return Err(LightningError::InvalidPreimage).into_module_error_other()
                    }
                },
                // … or the gateway may claim back funds for not receiving the advertised preimage.
                DecryptedPreimage::Invalid => incoming.contract.gateway_key,
            },
        };

        Ok(InputMeta {
            amount: TransactionItemAmount {
                amount: input.amount,
                fee: self.cfg.consensus.fee_consensus.contract_input,
            },
            puk_keys: vec![pub_key],
        })
    }

    async fn apply_input<'a, 'b, 'c>(
        &'a self,
        interconnect: &'a dyn ModuleInterconect,
        dbtx: &mut ModuleDatabaseTransaction<'c, ModuleInstanceId>,
        input: &'b LightningInput,
        cache: &Self::VerificationCache,
    ) -> Result<InputMeta, ModuleError> {
        let meta = self
            .validate_input(interconnect, dbtx, cache, input)
            .await?;

        let account_db_key = ContractKey(input.contract_id);
        let mut contract_account = dbtx
            .get_value(&account_db_key)
            .await
            .expect("Should fail validation if contract account doesn't exist");
        contract_account.amount -= meta.amount.amount;
        dbtx.insert_entry(&account_db_key, &contract_account).await;

        Ok(meta)
    }

    async fn validate_output(
        &self,
        dbtx: &mut ModuleDatabaseTransaction<'_, ModuleInstanceId>,
        output: &LightningOutput,
    ) -> Result<TransactionItemAmount, ModuleError> {
        match output {
            LightningOutput::Contract(contract) => {
                // Incoming contracts are special, they need to match an offer
                if let Contract::Incoming(incoming) = &contract.contract {
                    let offer = dbtx
                        .get_value(&OfferKey(incoming.hash))
                        .await
                        .ok_or(LightningError::NoOffer(incoming.hash))
                        .into_module_error_other()?;

                    if contract.amount < offer.amount {
                        // If the account is not sufficiently funded fail the output
                        return Err(LightningError::InsufficientIncomingFunding(
                            offer.amount,
                            contract.amount,
                        ))
                        .into_module_error_other();
                    }
                }

                if contract.amount == Amount::ZERO {
                    Err(LightningError::ZeroOutput).into_module_error_other()
                } else {
                    Ok(TransactionItemAmount {
                        amount: contract.amount,
                        fee: self.cfg.consensus.fee_consensus.contract_output,
                    })
                }
            }
            LightningOutput::Offer(offer) => {
                if !offer.encrypted_preimage.0.verify() {
                    Err(LightningError::InvalidEncryptedPreimage).into_module_error_other()
                } else {
                    Ok(TransactionItemAmount::ZERO)
                }
            }
            LightningOutput::CancelOutgoing {
                contract,
                gateway_signature,
            } => {
                let contract_account = dbtx
                    .get_value(&ContractKey(*contract))
                    .await
                    .ok_or(LightningError::UnknownContract(*contract))
                    .into_module_error_other()?;

                let outgoing_contract = match &contract_account.contract {
                    FundedContract::Outgoing(contract) => contract,
                    _ => {
                        return Err(LightningError::NotOutgoingContract).into_module_error_other();
                    }
                };

                secp256k1::global::SECP256K1
                    .verify_schnorr(
                        gateway_signature,
                        &outgoing_contract.cancellation_message().into(),
                        &outgoing_contract.gateway_key,
                    )
                    .map_err(|_| LightningError::InvalidCancellationSignature)
                    .into_module_error_other()?;

                Ok(TransactionItemAmount::ZERO)
            }
        }
    }

    async fn apply_output<'a, 'b>(
        &'a self,
        dbtx: &mut ModuleDatabaseTransaction<'b, ModuleInstanceId>,
        output: &'a LightningOutput,
        out_point: OutPoint,
    ) -> Result<TransactionItemAmount, ModuleError> {
        let amount = self.validate_output(dbtx, output).await?;

        match output {
            LightningOutput::Contract(contract) => {
                let contract_db_key = ContractKey(contract.contract.contract_id());
                let updated_contract_account = dbtx
                    .get_value(&contract_db_key)
                    .await
                    .map(|mut value: ContractAccount| {
                        value.amount += amount.amount;
                        value
                    })
                    .unwrap_or_else(|| ContractAccount {
                        amount: amount.amount,
                        contract: contract.contract.clone().to_funded(out_point),
                    });
                dbtx.insert_entry(&contract_db_key, &updated_contract_account)
                    .await;

                dbtx.insert_new_entry(
                    &ContractUpdateKey(out_point),
                    &LightningOutputOutcome::Contract {
                        id: contract.contract.contract_id(),
                        outcome: contract.contract.to_outcome(),
                    },
                )
                .await;

                if let Contract::Incoming(incoming) = &contract.contract {
                    let offer = dbtx
                        .get_value(&OfferKey(incoming.hash))
                        .await
                        .expect("offer exists if output is valid");

                    let decryption_share = self
                        .cfg
                        .private
                        .threshold_sec_key
                        .decrypt_share(&incoming.encrypted_preimage.0)
                        .expect("We checked for decryption share validity on contract creation");
                    dbtx.insert_new_entry(
                        &ProposeDecryptionShareKey(contract.contract.contract_id()),
                        &PreimageDecryptionShare(decryption_share),
                    )
                    .await;
                    dbtx.remove_entry(&OfferKey(offer.hash)).await;
                }
            }
            LightningOutput::Offer(offer) => {
                dbtx.insert_new_entry(
                    &ContractUpdateKey(out_point),
                    &LightningOutputOutcome::Offer { id: offer.id() },
                )
                .await;
                // TODO: sanity-check encrypted preimage size
                dbtx.insert_new_entry(&OfferKey(offer.hash), &(*offer).clone())
                    .await;
            }
            LightningOutput::CancelOutgoing { contract, .. } => {
                let updated_contract_account = {
                    let mut contract_account = dbtx
                        .get_value(&ContractKey(*contract))
                        .await
                        .expect("Contract exists if output is valid");

                    let outgoing_contract = match &mut contract_account.contract {
                        FundedContract::Outgoing(contract) => contract,
                        _ => {
                            panic!("Contract type was checked in validate_output");
                        }
                    };

                    outgoing_contract.cancelled = true;

                    contract_account
                };

                dbtx.insert_entry(&ContractKey(*contract), &updated_contract_account)
                    .await;
            }
        }

        Ok(amount)
    }

    #[instrument(skip_all)]
    async fn end_consensus_epoch<'a, 'b>(
        &'a self,
        consensus_peers: &HashSet<PeerId>,
        dbtx: &mut ModuleDatabaseTransaction<'b, ModuleInstanceId>,
    ) -> Vec<PeerId> {
        // Decrypt preimages
        let preimage_decryption_shares = dbtx
            .find_by_prefix(&AgreedDecryptionShareKeyPrefix)
            .await
            .map(|(key, value)| (key.0, (key.1, value)))
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .into_group_map();

        let mut bad_peers = vec![];
        for (contract_id, shares) in preimage_decryption_shares {
            let peers: Vec<PeerId> = shares.iter().map(|(peer, _)| *peer).collect();
            let span = info_span!("decrypt_preimage", %contract_id);
            let _gaurd = span.enter();

            let incoming_contract = match self.get_contract_account(dbtx, contract_id).await {
                Some(ContractAccount {
                    contract: FundedContract::Incoming(incoming),
                    ..
                }) => incoming.contract,
                _ => {
                    warn!("Received decryption share for non-existent incoming contract");
                    for peer in peers {
                        dbtx.remove_entry(&AgreedDecryptionShareKey(contract_id, peer))
                            .await;
                    }
                    continue;
                }
            };

            let valid_shares: HashMap<PeerId, PreimageDecryptionShare> = shares
                .into_iter()
                .filter(|(peer, share)| {
                    self.validate_decryption_share(
                        *peer,
                        share,
                        &incoming_contract.encrypted_preimage,
                    )
                })
                .collect();

            for peer in consensus_peers.sub(&valid_shares.keys().cloned().collect()) {
                bad_peers.push(peer);
                warn!("{} did not contribute valid decryption shares", peer);
            }

            if valid_shares.len() < self.cfg.consensus.threshold() {
                warn!(
                    valid_shares = %valid_shares.len(),
                    shares_needed = %self.cfg.consensus.threshold(),
                    "Too few decryption shares"
                );
                continue;
            }
            debug!("Beginning to decrypt preimage");

            let contract = self
                .get_contract_account(dbtx, contract_id)
                .await
                .expect("decryption shares without contracts should be discarded earlier"); // FIXME: verify

            let (incoming_contract, out_point) = match contract.contract {
                FundedContract::Incoming(incoming) => (incoming.contract, incoming.out_point),
                _ => panic!(
                    "decryption shares without incoming contracts should be discarded earlier"
                ),
            };

            if !matches!(
                incoming_contract.decrypted_preimage,
                DecryptedPreimage::Pending
            ) {
                warn!("Tried to decrypt the same preimage twice, this should not happen.");
                continue;
            }

            let preimage_vec = match self.cfg.consensus.threshold_pub_keys.decrypt(
                valid_shares
                    .iter()
                    .map(|(peer, share)| (peer.to_usize(), &share.0)),
                &incoming_contract.encrypted_preimage.0,
            ) {
                Ok(preimage_vec) => preimage_vec,
                Err(_) => {
                    // TODO: check if that can happen even though shares are verified before
                    error!(contract_hash = %incoming_contract.hash, "Failed to decrypt preimage");
                    continue;
                }
            };

            // Delete decryption shares once we've decrypted the preimage
            dbtx.remove_entry(&ProposeDecryptionShareKey(contract_id))
                .await;
            for peer in peers {
                dbtx.remove_entry(&AgreedDecryptionShareKey(contract_id, peer))
                    .await;
            }

            let decrypted_preimage = if preimage_vec.len() == 32
                && incoming_contract.hash == bitcoin_hashes::sha256::Hash::hash(&preimage_vec)
            {
                let preimage = Preimage(
                    preimage_vec
                        .as_slice()
                        .try_into()
                        .expect("Invalid preimage length"),
                );
                if preimage.to_public_key().is_ok() {
                    DecryptedPreimage::Some(preimage)
                } else {
                    DecryptedPreimage::Invalid
                }
            } else {
                DecryptedPreimage::Invalid
            };
            debug!(?decrypted_preimage);

            // TODO: maybe define update helper fn
            // Update contract
            let contract_db_key = ContractKey(contract_id);
            let mut contract_account = dbtx
                .get_value(&contract_db_key)
                .await
                .expect("checked before that it exists");
            let mut incoming = match &mut contract_account.contract {
                FundedContract::Incoming(incoming) => incoming,
                _ => unreachable!("previously checked that it's an incoming contrac"),
            };
            incoming.contract.decrypted_preimage = decrypted_preimage.clone();
            trace!(?contract_account, "Updating contract account");
            dbtx.insert_entry(&contract_db_key, &contract_account).await;

            // Update output outcome
            let outcome_db_key = ContractUpdateKey(out_point);
            let mut outcome = dbtx
                .get_value(&outcome_db_key)
                .await
                .expect("outcome was created on funding");
            let incoming_contract_outcome_preimage = match &mut outcome {
                LightningOutputOutcome::Contract {
                    outcome: ContractOutcome::Incoming(decryption_outcome),
                    ..
                } => decryption_outcome,
                _ => panic!("We are expeccting an incoming contract"),
            };
            *incoming_contract_outcome_preimage = decrypted_preimage.clone();
            dbtx.insert_entry(&outcome_db_key, &outcome).await;
        }

        bad_peers
    }

    async fn output_status(
        &self,
        dbtx: &mut ModuleDatabaseTransaction<'_, ModuleInstanceId>,
        out_point: OutPoint,
    ) -> Option<LightningOutputOutcome> {
        dbtx.get_value(&ContractUpdateKey(out_point)).await
    }

    async fn audit(
        &self,
        dbtx: &mut ModuleDatabaseTransaction<'_, ModuleInstanceId>,
        audit: &mut Audit,
    ) {
        audit
            .add_items(dbtx, &ContractKeyPrefix, |_, v| -(v.amount.msats as i64))
            .await;
    }

    fn api_endpoints(&self) -> Vec<ApiEndpoint<Self>> {
        vec![
            api_endpoint! {
                "/account",
                async |module: &Lightning, dbtx, contract_id: ContractId| -> ContractAccount {
                    module
                        .get_contract_account(dbtx, contract_id)
                        .await
                        .ok_or_else(|| ApiError::not_found(String::from("Contract not found")))
                }
            },
            api_endpoint! {
                "/offer",
                async |module: &Lightning, dbtx, payment_hash: bitcoin_hashes::sha256::Hash| -> IncomingContractOffer {
                    let offer = module
                        .get_offer(dbtx, payment_hash)
                        .await
                        .ok_or_else(|| ApiError::not_found(String::from("Offer not found")))?;

                    debug!(%payment_hash, "Sending offer info");
                    Ok(offer)
                }
            },
            api_endpoint! {
                "/list_gateways",
                async |module: &Lightning, dbtx, _v: ()| -> Vec<LightningGateway> {
                    Ok(module.list_gateways(dbtx).await)
                }
            },
            api_endpoint! {
                "/register_gateway",
                async |module: &Lightning, dbtx, gateway: LightningGateway| -> () {
                    module.register_gateway(dbtx, gateway).await;
                    Ok(())
                }
            },
        ]
    }
}
impl Lightning {
    pub fn new(cfg: LightningConfig) -> Self {
        Lightning { cfg }
    }

    fn validate_decryption_share(
        &self,
        peer: PeerId,
        share: &PreimageDecryptionShare,
        message: &EncryptedPreimage,
    ) -> bool {
        self.cfg
            .consensus
            .threshold_pub_keys
            .public_key_share(peer.to_usize())
            .verify_decryption_share(&share.0, &message.0)
    }

    pub async fn get_offer(
        &self,
        dbtx: &mut ModuleDatabaseTransaction<'_, ModuleInstanceId>,
        payment_hash: bitcoin_hashes::sha256::Hash,
    ) -> Option<IncomingContractOffer> {
        dbtx.get_value(&OfferKey(payment_hash)).await
    }

    pub async fn get_offers(
        &self,
        dbtx: &mut ModuleDatabaseTransaction<'_, ModuleInstanceId>,
    ) -> Vec<IncomingContractOffer> {
        dbtx.find_by_prefix(&OfferKeyPrefix)
            .await
            .map(|(_, value)| value)
            .collect::<Vec<IncomingContractOffer>>()
            .await
    }

    pub async fn get_contract_account(
        &self,
        dbtx: &mut ModuleDatabaseTransaction<'_, ModuleInstanceId>,
        contract_id: ContractId,
    ) -> Option<ContractAccount> {
        dbtx.get_value(&ContractKey(contract_id)).await
    }

    pub async fn list_gateways(
        &self,
        dbtx: &mut ModuleDatabaseTransaction<'_, ModuleInstanceId>,
    ) -> Vec<LightningGateway> {
        let stream = dbtx.find_by_prefix(&LightningGatewayKeyPrefix).await;
        stream
            .filter_map(|(_, gw)| async {
                // FIXME: actually remove from DB
                if gw.valid_until > fedimint_core::time::now() {
                    Some(gw)
                } else {
                    None
                }
            })
            .collect::<Vec<LightningGateway>>()
            .await
    }

    pub async fn register_gateway(
        &self,
        dbtx: &mut ModuleDatabaseTransaction<'_, ModuleInstanceId>,
        gateway: LightningGateway,
    ) {
        dbtx.insert_entry(&LightningGatewayKey(gateway.node_pub_key), &gateway)
            .await;
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Hash, Encodable, Decodable, Serialize, Deserialize)]
pub struct LightningVerificationCache;

impl fedimint_core::server::VerificationCache for LightningVerificationCache {}

async fn block_height(interconnect: &dyn ModuleInterconect) -> u32 {
    // This is a future because we are normally reading from a network socket. But
    // for internal calls the data is available instantly in one go, so we can
    // just block on it.
    let body = interconnect
        .call(
            LEGACY_HARDCODED_INSTANCE_ID_WALLET,
            "/block_height".to_owned(),
            ApiRequestErased::default(),
        )
        .await
        .expect("Wallet module not present or malfunctioning!");

    serde_json::from_value(body).expect("Malformed block height response from wallet module!")
}

#[cfg(test)]
mod fedimint_migration_tests {
    use std::str::FromStr;
    use std::time::SystemTime;

    use bitcoin_hashes::Hash;
    use fedimint_core::core::LEGACY_HARDCODED_INSTANCE_ID_LN;
    use fedimint_core::db::{apply_migrations, DatabaseTransaction};
    use fedimint_core::module::registry::ModuleDecoderRegistry;
    use fedimint_core::module::DynServerModuleGen;
    use fedimint_core::{OutPoint, ServerModule, TransactionId};
    use fedimint_ln_common::contracts::incoming::{
        FundedIncomingContract, IncomingContract, IncomingContractOffer, OfferId,
    };
    use fedimint_ln_common::contracts::{
        outgoing, ContractId, DecryptedPreimage, EncryptedPreimage, FundedContract, Preimage,
        PreimageDecryptionShare,
    };
    use fedimint_ln_common::db::{
        AgreedDecryptionShareKey, AgreedDecryptionShareKeyPrefix, ContractKey, ContractKeyPrefix,
        ContractUpdateKey, ContractUpdateKeyPrefix, DbKeyPrefix, LightningGatewayKey,
        LightningGatewayKeyPrefix, OfferKey, OfferKeyPrefix, ProposeDecryptionShareKey,
        ProposeDecryptionShareKeyPrefix,
    };
    use fedimint_testing::{prepare_snapshot, validate_migrations};
    use futures::StreamExt;
    use lightning_invoice::Invoice;
    use rand::distributions::Standard;
    use rand::prelude::Distribution;
    use rand::rngs::OsRng;
    use strum::IntoEnumIterator;
    use threshold_crypto::G1Projective;
    use url::Url;

    use crate::{
        ContractAccount, Lightning, LightningGateway, LightningGen, LightningOutputOutcome,
    };

    const STRING_64: &str = "0123456789012345678901234567890101234567890123456789012345678901";
    const BYTE_8: [u8; 8] = [0, 1, 2, 3, 4, 5, 6, 7];
    const BYTE_32: [u8; 32] = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
        0, 1,
    ];

    /// Create a database with version 0 data. The database produced is not
    /// intended to be real data or semantically correct. It is only
    /// intended to provide coverage when reading the database
    /// in future code versions. This function should not be updated when
    /// database keys/values change - instead a new function should be added
    /// that creates a new database backup that can be tested.
    async fn create_db_with_v0_data(mut dbtx: DatabaseTransaction<'_>) {
        let contract_id = ContractId::from_str(STRING_64).unwrap();
        let amount = fedimint_core::Amount { msats: 1000 };
        let threshold_key = threshold_crypto::PublicKey::from(G1Projective::identity());
        let (_, pk) = secp256k1::generate_keypair(&mut OsRng);
        let incoming_contract = IncomingContract {
            hash: secp256k1::hashes::sha256::Hash::hash(&BYTE_8),
            encrypted_preimage: EncryptedPreimage::new(Preimage(BYTE_32), &threshold_key),
            decrypted_preimage: DecryptedPreimage::Some(Preimage(BYTE_32)),
            gateway_key: pk.x_only_public_key().0,
        };
        let out_point = OutPoint {
            txid: TransactionId::all_zeros(),
            out_idx: 0,
        };
        let incoming_contract = FundedContract::Incoming(FundedIncomingContract {
            contract: incoming_contract,
            out_point,
        });
        dbtx.insert_new_entry(
            &ContractKey(contract_id),
            &ContractAccount {
                amount,
                contract: incoming_contract,
            },
        )
        .await;
        let invoice = str::parse::<Invoice>("lnbc10u1pjq37rgsp5cry9r0qqdzp0tl0m27jedvxtrazq0v8xh5rfvzuhm7yxydg50m9qpp5r0cjzjzt7pjwae8trp6dtteh6hstdakzv68atpqx0zshaexghpwsdqqcqpjrzjqfzekav6v27ra0lf3geqmg3hj3xvfu652cuyhk8aa7naqdqvwh6x7zagh5qqy3qqqyqqqqqpqqqqqqgq9q9qyysgq6vf5z83a2q2ua9nwanmc7pql26pwt8smt2xzwp7kjd0mgplmy925s5yz6nlfxt99p2dlffw82gw8kte7lv87pcf4nahslg2vyhhkzwqqxuqmgp");
        let outgoing_contract = FundedContract::Outgoing(outgoing::OutgoingContract {
            hash: secp256k1::hashes::sha256::Hash::hash(&[0, 2, 3, 4, 5, 6, 7, 8]),
            gateway_key: pk.x_only_public_key().0,
            timelock: 1000000,
            user_key: pk.x_only_public_key().0,
            invoice: invoice.unwrap(),
            cancelled: false,
        });
        dbtx.insert_new_entry(
            &ContractKey(contract_id),
            &ContractAccount {
                amount,
                contract: outgoing_contract,
            },
        )
        .await;

        let incoming_offer = IncomingContractOffer {
            amount: fedimint_core::Amount { msats: 1000 },
            hash: secp256k1::hashes::sha256::Hash::hash(&BYTE_8),
            encrypted_preimage: EncryptedPreimage::new(Preimage(BYTE_32), &threshold_key),
            expiry_time: None,
        };
        dbtx.insert_new_entry(&OfferKey(incoming_offer.hash), &incoming_offer)
            .await;

        let contract_update_key = ContractUpdateKey(OutPoint {
            txid: TransactionId::from_slice(&BYTE_32).unwrap(),
            out_idx: 0,
        });
        let lightning_output_outcome = LightningOutputOutcome::Offer {
            id: OfferId::from_str(STRING_64).unwrap(),
        };
        dbtx.insert_new_entry(&contract_update_key, &lightning_output_outcome)
            .await;

        let preimage_decryption_share = PreimageDecryptionShare(Standard.sample(&mut OsRng));
        dbtx.insert_new_entry(
            &ProposeDecryptionShareKey(contract_id),
            &preimage_decryption_share,
        )
        .await;

        dbtx.insert_new_entry(
            &AgreedDecryptionShareKey(contract_id, 0.into()),
            &preimage_decryption_share,
        )
        .await;

        let gateway = LightningGateway {
            mint_channel_id: 100,
            mint_pub_key: pk.x_only_public_key().0,
            node_pub_key: pk,
            api: Url::parse("http://example.com")
                .expect("Could not parse URL to generate GatewayClientConfig API endpoint"),
            route_hints: vec![],
            valid_until: SystemTime::now(),
        };
        dbtx.insert_new_entry(&LightningGatewayKey(pk), &gateway)
            .await;

        dbtx.commit_tx().await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn prepare_migration_snapshots() {
        prepare_snapshot(
            "lightning-v0",
            |dbtx| {
                Box::pin(async move {
                    create_db_with_v0_data(dbtx).await;
                })
            },
            ModuleDecoderRegistry::from_iter([(
                LEGACY_HARDCODED_INSTANCE_ID_LN,
                <Lightning as ServerModule>::decoder(),
            )]),
        )
        .await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_migrations() {
        validate_migrations(
            |db| async move {
                let module = DynServerModuleGen::from(LightningGen);
                apply_migrations(
                    &db,
                    module.module_kind().to_string(),
                    module.database_version(),
                    module.get_database_migrations(),
                )
                .await
                .expect("Error applying migrations to temp database");

                // Verify that all of the data from the lightning namespace can be read. If a
                // database migration failed or was not properly supplied,
                // the struct will fail to be read.
                let mut dbtx = db.begin_transaction().await;

                for prefix in DbKeyPrefix::iter() {
                    match prefix {
                        DbKeyPrefix::Contract => {
                            let contracts = dbtx
                                .find_by_prefix(&ContractKeyPrefix)
                                .await
                                .collect::<Vec<_>>()
                                .await;
                            let num_contracts = contracts.len();
                            assert!(
                                num_contracts > 0,
                                "validate_migrations was not able to read any contracts"
                            );
                        }
                        DbKeyPrefix::AgreedDecryptionShare => {
                            let agreed_decryption_shares = dbtx
                                .find_by_prefix(&AgreedDecryptionShareKeyPrefix)
                                .await
                                .collect::<Vec<_>>()
                                .await;
                            let num_shares = agreed_decryption_shares.len();
                            assert!(
                            num_shares > 0,
                            "validate_migrations was not able to read any AgreedDecryptionShares"
                        );
                        }
                        DbKeyPrefix::ContractUpdate => {
                            let contract_updates = dbtx
                                .find_by_prefix(&ContractUpdateKeyPrefix)
                                .await
                                .collect::<Vec<_>>()
                                .await;
                            let num_updates = contract_updates.len();
                            assert!(
                                num_updates > 0,
                                "validate_migrations was not able to read any ContractUpdates"
                            );
                        }
                        DbKeyPrefix::LightningGateway => {
                            let gateways = dbtx
                                .find_by_prefix(&LightningGatewayKeyPrefix)
                                .await
                                .collect::<Vec<_>>()
                                .await;
                            let num_gateways = gateways.len();
                            assert!(
                                num_gateways > 0,
                                "validate_migrations was not able to read any LightningGateways"
                            );
                        }
                        DbKeyPrefix::Offer => {
                            let offers = dbtx
                                .find_by_prefix(&OfferKeyPrefix)
                                .await
                                .collect::<Vec<_>>()
                                .await;
                            let num_offers = offers.len();
                            assert!(
                                num_offers > 0,
                                "validate_migrations was not able to read any Offers"
                            );
                        }
                        DbKeyPrefix::ProposeDecryptionShare => {
                            let proposed_decryption_shares = dbtx
                                .find_by_prefix(&ProposeDecryptionShareKeyPrefix)
                                .await
                                .collect::<Vec<_>>()
                                .await;
                            let num_shares = proposed_decryption_shares.len();
                            assert!(
                            num_shares > 0,
                            "validate_migrations was not able to read any ProposeDecryptionShares"
                        );
                        }
                    }
                }
            },
            ModuleDecoderRegistry::from_iter([(
                LEGACY_HARDCODED_INSTANCE_ID_LN,
                <Lightning as ServerModule>::decoder(),
            )]),
        )
        .await;
    }
}
