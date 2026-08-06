#![deny(clippy::pedantic)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::too_many_lines)]

pub mod db;
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use anyhow::{Context, bail};
use bitcoin_hashes::{Hash as BitcoinHash, sha256};
use fedimint_api_client::api::{DynModuleApi, FederationApiExt};
use fedimint_core::config::{
    ServerModuleConfig, ServerModuleConsensusConfig, TypedServerModuleConfig,
    TypedServerModuleConsensusConfig,
};
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::db::{DatabaseTransaction, DatabaseValue, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::encoding::Encodable;
use fedimint_core::encoding::btc::NetworkLegacyEncodingWrapper;
use fedimint_core::envs::{FM_ENABLE_MODULE_LNV1_ENV, is_env_var_set_opt, next_poll_delay};
use fedimint_core::module::audit::Audit;
use fedimint_core::module::{
    Amounts, ApiEndpoint, ApiEndpointContext, ApiError, ApiRequestErased, ApiVersion,
    CORE_CONSENSUS_VERSION, CoreConsensusVersion, InputMeta, ModuleConsensusVersion, ModuleInit,
    SupportedModuleApiVersions, TransactionItemAmounts, api_endpoint,
};
use fedimint_core::secp256k1::{Message, PublicKey, SECP256K1};
use fedimint_core::task::{TaskGroup, sleep};
use fedimint_core::util::{FmtCompact, FmtCompactAnyhow};
use fedimint_core::{
    Amount, InPoint, NumPeers, NumPeersExt, OutPoint, PeerId, apply, async_trait_maybe_send,
    push_db_pair_items,
};
pub use fedimint_ln_common as common;
use fedimint_ln_common::config::{
    FeeConsensus, LightningClientConfig, LightningConfig, LightningConfigConsensus,
    LightningConfigPrivate,
};
use fedimint_ln_common::contracts::incoming::{IncomingContractAccount, IncomingContractOffer};
use fedimint_ln_common::contracts::{
    Contract, ContractId, ContractOutcome, DecryptedPreimage, DecryptedPreimageStatus,
    EncryptedPreimage, FundedContract, IdentifiableContract, Preimage, PreimageDecryptionShare,
    PreimageKey,
};
use fedimint_ln_common::federation_endpoint_constants::{
    ACCOUNT_ENDPOINT, AWAIT_ACCOUNT_ENDPOINT, AWAIT_BLOCK_HEIGHT_ENDPOINT, AWAIT_OFFER_ENDPOINT,
    AWAIT_OUTGOING_CONTRACT_CANCELLED_ENDPOINT, AWAIT_PREIMAGE_DECRYPTION, BLOCK_COUNT_ENDPOINT,
    GET_DECRYPTED_PREIMAGE_STATUS, LIST_GATEWAYS_ENDPOINT, MODULE_CONSENSUS_VERSION_ENDPOINT,
    OFFER_ENDPOINT, REGISTER_GATEWAY_ENDPOINT, REMOVE_GATEWAY_CHALLENGE_ENDPOINT,
    REMOVE_GATEWAY_ENDPOINT, SUPPORTED_MODULE_CONSENSUS_VERSION_ENDPOINT,
};
use fedimint_ln_common::{
    CONTRACT_FUNDED_ONCE_MODULE_CONSENSUS_VERSION, ContractAccount, LightningCommonInit,
    LightningConsensusItem, LightningGatewayAnnouncement, LightningGatewayRegistration,
    LightningInput, LightningInputError, LightningModuleTypes, LightningOutput,
    LightningOutputError, LightningOutputOutcome, LightningOutputOutcomeV0, LightningOutputV0,
    MODULE_CONSENSUS_VERSION, RemoveGatewayRequest, create_gateway_registration_message,
    create_gateway_remove_message,
};
use fedimint_logging::LOG_MODULE_LN;
use fedimint_server_core::bitcoin_rpc::ServerBitcoinRpcMonitor;
use fedimint_server_core::config::PeerHandleOps;
use fedimint_server_core::{
    ConfigGenModuleArgs, ServerModule, ServerModuleInit, ServerModuleInitArgs,
};
use futures::StreamExt;
use futures::future::join_all;
use metrics::{LN_CANCEL_OUTGOING_CONTRACTS, LN_FUNDED_CONTRACT_SATS, LN_INCOMING_OFFER};
use rand::rngs::OsRng;
use strum::IntoEnumIterator;
use threshold_crypto::poly::Commitment;
use threshold_crypto::serde_impl::SerdeSecret;
use threshold_crypto::{PublicKeySet, SecretKeyShare};
use tokio::sync::watch;
use tracing::{debug, error, info, info_span, trace, warn};

use crate::db::{
    AgreedDecryptionShareContractIdPrefix, AgreedDecryptionShareKey,
    AgreedDecryptionShareKeyPrefix, BlockCountVoteKey, BlockCountVotePrefix,
    ConsensusVersionVoteKey, ConsensusVersionVotePrefix, ContractKey, ContractKeyPrefix,
    ContractUpdateKey, ContractUpdateKeyPrefix, DbKeyPrefix, EncryptedPreimageIndexKey,
    EncryptedPreimageIndexKeyPrefix, LightningAuditItemKey, LightningAuditItemKeyPrefix,
    LightningGatewayKey, LightningGatewayKeyPrefix, OfferKey, OfferKeyPrefix,
    ProposeDecryptionShareKey, ProposeDecryptionShareKeyPrefix,
};

mod metrics;

#[derive(Debug, Clone)]
pub struct LightningInit;

impl ModuleInit for LightningInit {
    type Common = LightningCommonInit;

    async fn dump_database(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
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
                        LightningOutputOutcomeV0,
                        lightning,
                        "Contract Updates"
                    );
                }
                DbKeyPrefix::LightningGateway => {
                    push_db_pair_items!(
                        dbtx,
                        LightningGatewayKeyPrefix,
                        LightningGatewayKey,
                        LightningGatewayRegistration,
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
                DbKeyPrefix::BlockCountVote => {
                    push_db_pair_items!(
                        dbtx,
                        BlockCountVotePrefix,
                        BlockCountVoteKey,
                        u64,
                        lightning,
                        "Block Count Votes"
                    );
                }
                DbKeyPrefix::EncryptedPreimageIndex => {
                    push_db_pair_items!(
                        dbtx,
                        EncryptedPreimageIndexKeyPrefix,
                        EncryptedPreimageIndexKey,
                        (),
                        lightning,
                        "Encrypted Preimage Hashes"
                    );
                }
                DbKeyPrefix::LightningAuditItem => {
                    push_db_pair_items!(
                        dbtx,
                        LightningAuditItemKeyPrefix,
                        LightningAuditItemKey,
                        Amount,
                        lightning,
                        "Lightning Audit Items"
                    );
                }
                DbKeyPrefix::ConsensusVersionVote => {
                    push_db_pair_items!(
                        dbtx,
                        ConsensusVersionVotePrefix,
                        ConsensusVersionVoteKey,
                        ModuleConsensusVersion,
                        lightning,
                        "Consensus Version Votes"
                    );
                }
            }
        }

        Box::new(lightning.into_iter())
    }
}

#[apply(async_trait_maybe_send!)]
impl ServerModuleInit for LightningInit {
    type Module = Lightning;

    fn versions(&self, _core: CoreConsensusVersion) -> &[ModuleConsensusVersion] {
        &[MODULE_CONSENSUS_VERSION]
    }

    fn supported_api_versions(&self) -> SupportedModuleApiVersions {
        SupportedModuleApiVersions::from_raw(
            (CORE_CONSENSUS_VERSION.major, CORE_CONSENSUS_VERSION.minor),
            (
                MODULE_CONSENSUS_VERSION.major,
                MODULE_CONSENSUS_VERSION.minor,
            ),
            &[(0, 1)],
        )
    }

    async fn init(&self, args: &ServerModuleInitArgs<Self>) -> anyhow::Result<Self::Module> {
        // Eagerly initialize metrics that trigger infrequently
        LN_CANCEL_OUTGOING_CONTRACTS.get();

        let peer_supported_consensus_version =
            Lightning::spawn_peer_supported_consensus_version_task(
                args.module_api().clone(),
                args.task_group(),
                args.our_peer_id(),
            );

        Ok(Lightning {
            cfg: args.cfg().to_typed()?,
            our_peer_id: args.our_peer_id(),
            num_peers: args.num_peers(),
            peer_supported_consensus_version,
            server_bitcoin_rpc_monitor: args.server_bitcoin_rpc_monitor(),
        })
    }

    fn trusted_dealer_gen(
        &self,
        peers: &[PeerId],
        args: &ConfigGenModuleArgs,
    ) -> BTreeMap<PeerId, ServerModuleConfig> {
        let sks = threshold_crypto::SecretKeySet::random(peers.to_num_peers().degree(), &mut OsRng);
        let pks = sks.public_keys();

        peers
            .iter()
            .map(|&peer| {
                let sk = sks.secret_key_share(peer.to_usize());

                (
                    peer,
                    LightningConfig {
                        consensus: LightningConfigConsensus {
                            threshold_pub_keys: pks.clone(),
                            fee_consensus: FeeConsensus::default(),
                            network: NetworkLegacyEncodingWrapper(args.network),
                        },
                        private: LightningConfigPrivate {
                            threshold_sec_key: threshold_crypto::serde_impl::SerdeSecret(sk),
                        },
                    }
                    .to_erased(),
                )
            })
            .collect()
    }

    async fn distributed_gen(
        &self,
        peers: &(dyn PeerHandleOps + Send + Sync),
        args: &ConfigGenModuleArgs,
    ) -> anyhow::Result<ServerModuleConfig> {
        let (polynomial, mut sks) = peers.run_dkg_g1().await?;

        let server = LightningConfig {
            consensus: LightningConfigConsensus {
                threshold_pub_keys: PublicKeySet::from(Commitment::from(polynomial)),
                fee_consensus: FeeConsensus::default(),
                network: NetworkLegacyEncodingWrapper(args.network),
            },
            private: LightningConfigPrivate {
                threshold_sec_key: SerdeSecret(SecretKeyShare::from_mut(&mut sks)),
            },
        };

        Ok(server.to_erased())
    }

    fn validate_config(&self, identity: &PeerId, config: ServerModuleConfig) -> anyhow::Result<()> {
        let config = config.to_typed::<LightningConfig>()?;
        if config.private.threshold_sec_key.public_key_share()
            != config
                .consensus
                .threshold_pub_keys
                .public_key_share(identity.to_usize())
        {
            bail!("Lightning private key doesn't match pubkey share");
        }
        Ok(())
    }

    fn get_client_config(
        &self,
        config: &ServerModuleConsensusConfig,
    ) -> anyhow::Result<LightningClientConfig> {
        let config = LightningConfigConsensus::from_erased(config)?;
        Ok(LightningClientConfig {
            threshold_pub_key: config.threshold_pub_keys.public_key(),
            fee_consensus: config.fee_consensus,
            network: config.network,
        })
    }

    fn used_db_prefixes(&self) -> Option<BTreeSet<u8>> {
        Some(DbKeyPrefix::iter().map(|p| p as u8).collect())
    }
}
/// The lightning module implements an account system. It does not have the
/// privacy guarantees of the e-cash mint module but instead allows for smart
/// contracting. There exist two contract types that can be used to "lock"
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
/// These two primitives allow to integrate the federation with the wider
/// Lightning network through a centralized but untrusted (except for
/// availability) Lightning gateway server.
///
/// [Outgoing]: fedimint_ln_common::contracts::outgoing::OutgoingContract
/// [Incoming]: fedimint_ln_common::contracts::incoming::IncomingContract
#[derive(Debug)]
pub struct Lightning {
    cfg: LightningConfig,
    our_peer_id: PeerId,
    num_peers: NumPeers,
    /// The highest module consensus version supported by every peer, as
    /// reported by their APIs, or `None` while any peer has yet to answer.
    peer_supported_consensus_version: watch::Receiver<Option<ModuleConsensusVersion>>,
    server_bitcoin_rpc_monitor: ServerBitcoinRpcMonitor,
}

#[apply(async_trait_maybe_send!)]
impl ServerModule for Lightning {
    type Common = LightningModuleTypes;
    type Init = LightningInit;

    async fn consensus_proposal(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
    ) -> Vec<LightningConsensusItem> {
        let mut items: Vec<LightningConsensusItem> = dbtx
            .find_by_prefix(&ProposeDecryptionShareKeyPrefix)
            .await
            .map(|(ProposeDecryptionShareKey(contract_id), share)| {
                LightningConsensusItem::DecryptPreimage(contract_id, share)
            })
            .collect()
            .await;

        if let Ok(block_count_vote) = self.get_block_count() {
            trace!(target: LOG_MODULE_LN, ?block_count_vote, "Proposing block count");
            items.push(LightningConsensusItem::BlockCount(block_count_vote));
        }

        // Consensus upgrade activation voting. There is deliberately no manual
        // override: a new consensus item variant is only understood by upgraded
        // peers, and peers that predate it skip it rather than fail, which would
        // silently fork their state. Requiring every peer to report support
        // before we ever propose the item is what keeps that from happening.
        let active_consensus_version = self.consensus_module_consensus_version(dbtx).await;

        if let Some(supported_consensus_version) = *self.peer_supported_consensus_version.borrow()
            // Only vote if the commonly supported version is higher than the
            // currently active one
            && active_consensus_version < supported_consensus_version
        {
            items.push(LightningConsensusItem::ModuleConsensusVersion(
                supported_consensus_version,
            ));
        }

        items
    }

    async fn process_consensus_item<'a, 'b>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'b>,
        consensus_item: LightningConsensusItem,
        peer_id: PeerId,
    ) -> anyhow::Result<()> {
        let span = info_span!("process decryption share", %peer_id);
        let _guard = span.enter();
        trace!(target: LOG_MODULE_LN, ?consensus_item, "Processing consensus item proposal");

        match consensus_item {
            LightningConsensusItem::DecryptPreimage(contract_id, share) => {
                if dbtx
                    .get_value(&AgreedDecryptionShareKey(contract_id, peer_id))
                    .await
                    .is_some()
                {
                    bail!("Already received a valid decryption share for this peer");
                }

                let account = dbtx
                    .get_value(&ContractKey(contract_id))
                    .await
                    .context("Contract account for this decryption share does not exist")?;

                let (contract, out_point) = match account.contract {
                    FundedContract::Incoming(contract) => (contract.contract, contract.out_point),
                    FundedContract::Outgoing(..) => {
                        bail!("Contract account for this decryption share is outgoing");
                    }
                };

                if contract.decrypted_preimage != DecryptedPreimage::Pending {
                    bail!("Contract for this decryption share is not pending");
                }

                if !self.validate_decryption_share(peer_id, &share, &contract.encrypted_preimage) {
                    bail!("Decryption share is invalid");
                }

                // we save the first ordered valid decryption share for every peer
                dbtx.insert_new_entry(&AgreedDecryptionShareKey(contract_id, peer_id), &share)
                    .await;

                // collect all valid decryption shares previously received for this contract
                let decryption_shares = dbtx
                    .find_by_prefix(&AgreedDecryptionShareContractIdPrefix(contract_id))
                    .await
                    .map(|(key, decryption_share)| (key.1, decryption_share))
                    .collect::<Vec<_>>()
                    .await;

                if decryption_shares.len() < self.cfg.consensus.threshold() {
                    return Ok(());
                }

                debug!(target: LOG_MODULE_LN, "Beginning to decrypt preimage");

                let Ok(preimage_vec) = self.cfg.consensus.threshold_pub_keys.decrypt(
                    decryption_shares
                        .iter()
                        .map(|(peer, share)| (peer.to_usize(), &share.0)),
                    &contract.encrypted_preimage.0,
                ) else {
                    // TODO: check if that can happen even though shares are verified
                    // before
                    error!(target: LOG_MODULE_LN, contract_hash = %contract.hash, "Failed to decrypt preimage");
                    return Ok(());
                };

                // Delete decryption shares once we've decrypted the preimage
                dbtx.remove_entry(&ProposeDecryptionShareKey(contract_id))
                    .await;

                dbtx.remove_by_prefix(&AgreedDecryptionShareContractIdPrefix(contract_id))
                    .await;

                let decrypted_preimage = if preimage_vec.len() == 33
                    && contract.hash
                        == sha256::Hash::hash(&sha256::Hash::hash(&preimage_vec).to_byte_array())
                {
                    let preimage = PreimageKey(
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

                debug!(target: LOG_MODULE_LN, ?decrypted_preimage);

                // TODO: maybe define update helper fn
                // Update contract
                let contract_db_key = ContractKey(contract_id);
                let mut contract_account = dbtx
                    .get_value(&contract_db_key)
                    .await
                    .expect("checked before that it exists");
                let incoming = match &mut contract_account.contract {
                    FundedContract::Incoming(incoming) => incoming,
                    FundedContract::Outgoing(_) => {
                        unreachable!("previously checked that it's an incoming contract")
                    }
                };
                incoming.contract.decrypted_preimage = decrypted_preimage.clone();
                trace!(?contract_account, "Updating contract account");
                dbtx.insert_entry(&contract_db_key, &contract_account).await;

                // Update output outcome
                let mut outcome = dbtx
                    .get_value(&ContractUpdateKey(out_point))
                    .await
                    .expect("outcome was created on funding");

                let LightningOutputOutcomeV0::Contract {
                    outcome: ContractOutcome::Incoming(incoming_contract_outcome_preimage),
                    ..
                } = &mut outcome
                else {
                    panic!("We are expecting an incoming contract")
                };
                *incoming_contract_outcome_preimage = decrypted_preimage.clone();
                dbtx.insert_entry(&ContractUpdateKey(out_point), &outcome)
                    .await;
            }
            LightningConsensusItem::BlockCount(block_count) => {
                let current_vote = dbtx
                    .get_value(&BlockCountVoteKey(peer_id))
                    .await
                    .unwrap_or(0);

                if block_count < current_vote {
                    bail!("Block count vote decreased");
                }

                if block_count == current_vote {
                    bail!("Block height vote is redundant");
                }

                dbtx.insert_entry(&BlockCountVoteKey(peer_id), &block_count)
                    .await;
            }
            LightningConsensusItem::ModuleConsensusVersion(module_consensus_version) => {
                let current_vote = dbtx
                    .get_value(&ConsensusVersionVoteKey(peer_id))
                    .await
                    .unwrap_or(ModuleConsensusVersion::new(2, 0));

                if module_consensus_version <= current_vote {
                    bail!("Module consensus version vote is redundant");
                }

                dbtx.insert_entry(&ConsensusVersionVoteKey(peer_id), &module_consensus_version)
                    .await;

                assert!(
                    self.consensus_module_consensus_version(dbtx).await <= MODULE_CONSENSUS_VERSION,
                    "Lightning module does not support new consensus version, please upgrade the module"
                );
            }
            LightningConsensusItem::Default { variant, .. } => {
                bail!("Unknown lightning consensus item received, variant={variant}");
            }
        }

        Ok(())
    }

    async fn process_input<'a, 'b, 'c>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'c>,
        input: &'b LightningInput,
        _in_point: InPoint,
    ) -> Result<InputMeta, LightningInputError> {
        let input = input.ensure_v0_ref()?;

        let mut account = dbtx
            .get_value(&ContractKey(input.contract_id))
            .await
            .ok_or(LightningInputError::UnknownContract(input.contract_id))?;

        if account.amount < input.amount {
            return Err(LightningInputError::InsufficientFunds(
                account.amount,
                input.amount,
            ));
        }

        let consensus_block_count = self.consensus_block_count(dbtx).await;

        let pub_key = match &account.contract {
            FundedContract::Outgoing(outgoing) => {
                if u64::from(outgoing.timelock) + 1 > consensus_block_count && !outgoing.cancelled {
                    // If the timelock hasn't expired yet …
                    let preimage_hash = bitcoin_hashes::sha256::Hash::hash(
                        &input
                            .witness
                            .as_ref()
                            .ok_or(LightningInputError::MissingPreimage)?
                            .0,
                    );

                    // … and the spender provides a valid preimage …
                    if preimage_hash != outgoing.hash {
                        return Err(LightningInputError::InvalidPreimage);
                    }

                    // … then the contract account can be spent using the gateway key,
                    outgoing.gateway_key
                } else {
                    // otherwise the user can claim the funds back.
                    outgoing.user_key
                }
            }
            FundedContract::Incoming(incoming) => match &incoming.contract.decrypted_preimage {
                // Once the preimage has been decrypted …
                DecryptedPreimage::Pending => {
                    return Err(LightningInputError::ContractNotReady);
                }
                // … either the user may spend the funds since they sold a valid preimage …
                DecryptedPreimage::Some(preimage) => match preimage.to_public_key() {
                    Ok(pub_key) => pub_key,
                    Err(_) => return Err(LightningInputError::InvalidPreimage),
                },
                // … or the gateway may claim back funds for not receiving the advertised preimage.
                DecryptedPreimage::Invalid => incoming.contract.gateway_key,
            },
        };

        account.amount -= input.amount;

        dbtx.insert_entry(&ContractKey(input.contract_id), &account)
            .await;

        // When a contract reaches a terminal state, the associated amount will be
        // updated to 0. At this point, the contract no longer needs to be tracked
        // for auditing liabilities, so we can safely remove the audit key.
        let audit_key = LightningAuditItemKey::from_funded_contract(&account.contract);
        if account.amount.msats == 0 {
            dbtx.remove_entry(&audit_key).await;
        } else {
            dbtx.insert_entry(&audit_key, &account.amount).await;
        }

        Ok(InputMeta {
            amount: TransactionItemAmounts {
                amounts: Amounts::new_bitcoin(input.amount),
                fees: Amounts::new_bitcoin(self.cfg.consensus.fee_consensus.contract_input),
            },
            pub_key,
        })
    }

    async fn process_output<'a, 'b>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'b>,
        output: &'a LightningOutput,
        out_point: OutPoint,
    ) -> Result<TransactionItemAmounts, LightningOutputError> {
        let output = output.ensure_v0_ref()?;

        match output {
            LightningOutputV0::Contract(contract) => {
                // From consensus version 2.1 on, a contract account is funded
                // exactly once. Contract ids do not commit to the full contract
                // state, so before this version a second funding output for the
                // same id topped up the existing account while keeping its
                // state; for an incoming contract whose preimage decryption
                // already reached a terminal state, the first contract's
                // gateway or preimage holder could sweep the new funds. The
                // pre-2.1 top-up path below must remain reachable so historic
                // sessions replay identically.
                if self.is_contract_funded_once_active(dbtx).await
                    && dbtx
                        .get_value(&ContractKey(contract.contract.contract_id()))
                        .await
                        .is_some()
                {
                    return Err(LightningOutputError::ContractAlreadyFunded(
                        contract.contract.contract_id(),
                    ));
                }

                // Incoming contracts are special, they need to match an offer
                if let Contract::Incoming(incoming) = &contract.contract {
                    // An incoming contract's id is only its payment hash, so a second
                    // funding lands on the account created by the first one. While that
                    // account is still waiting on a decryption proposal, funding it
                    // again would overwrite the pending proposal, so reject it.
                    if dbtx
                        .get_value(&ProposeDecryptionShareKey(incoming.contract_id()))
                        .await
                        .is_some()
                    {
                        return Err(LightningOutputError::ContractAlreadyFunded(
                            incoming.contract_id(),
                        ));
                    }

                    let offer = dbtx
                        .get_value(&OfferKey(incoming.hash))
                        .await
                        .ok_or(LightningOutputError::NoOffer(incoming.hash))?;

                    if contract.amount < offer.amount {
                        // If the account is not sufficiently funded fail the output
                        return Err(LightningOutputError::InsufficientIncomingFunding(
                            offer.amount,
                            contract.amount,
                        ));
                    }

                    // The offer's ciphertext is verified when the offer is created, but the
                    // contract carries its own copy, which consensus decoding only checks
                    // for valid point encodings. `decrypt_share` below returns `None` for
                    // exactly the ciphertexts that fail `verify()`.
                    if !incoming.encrypted_preimage.0.verify() {
                        return Err(LightningOutputError::InvalidEncryptedPreimage);
                    }
                }

                if contract.amount == Amount::ZERO {
                    return Err(LightningOutputError::ZeroOutput);
                }

                let contract_db_key = ContractKey(contract.contract.contract_id());

                let updated_contract_account = dbtx.get_value(&contract_db_key).await.map_or_else(
                    || ContractAccount {
                        amount: contract.amount,
                        contract: contract.contract.clone().to_funded(out_point),
                    },
                    |mut value: ContractAccount| {
                        value.amount += contract.amount;
                        value
                    },
                );

                dbtx.insert_entry(
                    &LightningAuditItemKey::from_funded_contract(
                        &updated_contract_account.contract,
                    ),
                    &updated_contract_account.amount,
                )
                .await;

                if dbtx
                    .insert_entry(&contract_db_key, &updated_contract_account)
                    .await
                    .is_none()
                {
                    dbtx.on_commit(move || {
                        record_funded_contract_metric(&updated_contract_account);
                    });
                }

                dbtx.insert_new_entry(
                    &ContractUpdateKey(out_point),
                    &LightningOutputOutcomeV0::Contract {
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
                        .ok_or(LightningOutputError::InvalidEncryptedPreimage)?;

                    dbtx.insert_new_entry(
                        &ProposeDecryptionShareKey(contract.contract.contract_id()),
                        &PreimageDecryptionShare(decryption_share),
                    )
                    .await;

                    dbtx.remove_entry(&OfferKey(offer.hash)).await;
                }

                Ok(TransactionItemAmounts {
                    amounts: Amounts::new_bitcoin(contract.amount),
                    fees: Amounts::new_bitcoin(self.cfg.consensus.fee_consensus.contract_output),
                })
            }
            LightningOutputV0::Offer(offer) => {
                // From consensus version 2.1 on, no offer can be created for a
                // payment hash whose incoming contract account already exists:
                // funding it could only top up that account (rejected above
                // once 2.1 is active), so such an offer is a dead end that
                // could still lure a gateway into accepting an HTLC it can
                // never get funded for.
                if self.is_contract_funded_once_active(dbtx).await
                    && dbtx
                        .get_value(&ContractKey(offer.contract_id()))
                        .await
                        .is_some()
                {
                    return Err(LightningOutputError::OfferForFundedContract(
                        offer.contract_id(),
                    ));
                }

                if !offer.encrypted_preimage.0.verify() {
                    return Err(LightningOutputError::InvalidEncryptedPreimage);
                }

                // Check that each preimage is only offered for sale once, see #1397
                if dbtx
                    .insert_entry(
                        &EncryptedPreimageIndexKey(offer.encrypted_preimage.consensus_hash()),
                        &(),
                    )
                    .await
                    .is_some()
                {
                    return Err(LightningOutputError::DuplicateEncryptedPreimage);
                }

                dbtx.insert_new_entry(
                    &ContractUpdateKey(out_point),
                    &LightningOutputOutcomeV0::Offer { id: offer.id() },
                )
                .await;

                // TODO: sanity-check encrypted preimage size
                if dbtx
                    .insert_entry(&OfferKey(offer.hash), &(*offer).clone())
                    .await
                    .is_some()
                {
                    // Technically the error isn't due to a duplicate encrypted preimage but due to
                    // a duplicate payment hash, practically it's the same problem though: re-using
                    // the invoice key. Since we can't eaily extend the error enum we just re-use
                    // this variant.
                    return Err(LightningOutputError::DuplicateEncryptedPreimage);
                }

                dbtx.on_commit(|| {
                    LN_INCOMING_OFFER.inc();
                });

                Ok(TransactionItemAmounts::ZERO)
            }
            LightningOutputV0::CancelOutgoing {
                contract,
                gateway_signature,
            } => {
                let contract_account = dbtx
                    .get_value(&ContractKey(*contract))
                    .await
                    .ok_or(LightningOutputError::UnknownContract(*contract))?;

                let outgoing_contract = match &contract_account.contract {
                    FundedContract::Outgoing(contract) => contract,
                    FundedContract::Incoming(_) => {
                        return Err(LightningOutputError::NotOutgoingContract);
                    }
                };

                SECP256K1
                    .verify_schnorr(
                        gateway_signature,
                        &Message::from_digest(*outgoing_contract.cancellation_message().as_ref()),
                        &outgoing_contract.gateway_key.x_only_public_key().0,
                    )
                    .map_err(|_| LightningOutputError::InvalidCancellationSignature)?;

                let updated_contract_account = {
                    let mut contract_account = dbtx
                        .get_value(&ContractKey(*contract))
                        .await
                        .expect("Contract exists if output is valid");

                    let outgoing_contract = match &mut contract_account.contract {
                        FundedContract::Outgoing(contract) => contract,
                        FundedContract::Incoming(_) => {
                            panic!("Contract type was checked in validate_output");
                        }
                    };

                    outgoing_contract.cancelled = true;

                    contract_account
                };

                dbtx.insert_entry(&ContractKey(*contract), &updated_contract_account)
                    .await;

                dbtx.insert_new_entry(
                    &ContractUpdateKey(out_point),
                    &LightningOutputOutcomeV0::CancelOutgoingContract { id: *contract },
                )
                .await;

                dbtx.on_commit(|| {
                    LN_CANCEL_OUTGOING_CONTRACTS.inc();
                });

                Ok(TransactionItemAmounts::ZERO)
            }
        }
    }

    async fn output_status(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        out_point: OutPoint,
    ) -> Option<LightningOutputOutcome> {
        dbtx.get_value(&ContractUpdateKey(out_point))
            .await
            .map(LightningOutputOutcome::V0)
    }

    /// Reject funding a contract that already has an account, and creating an
    /// offer for a payment hash whose incoming contract account already exists.
    ///
    /// Contract ids do not commit to the full contract state — an incoming
    /// contract's id commits to the payment hash alone — so a second funding
    /// output for the same id does not create a new account: it tops up the
    /// existing one, which keeps the first contract's `decrypted_preimage`,
    /// `encrypted_preimage` and `gateway_key`. If that state is already
    /// terminal the new funds are immediately spendable by the *first*
    /// contract's gateway, and no further decryption can take place.
    ///
    /// These are the same rules [`ServerModule::process_output`] enforces in
    /// consensus from module consensus version 2.1 on. Enforcing them here as
    /// well protects federations that have not activated 2.1 yet, with policy
    /// strength only: it is only as strong as the weakest guardian and cannot
    /// see intra-session ordering, so it does not cover two fundings submitted
    /// in the same session.
    #[doc(hidden)]
    async fn verify_output_submission<'a, 'b>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'b>,
        output: &'a LightningOutput,
        _out_point: OutPoint,
    ) -> Result<(), LightningOutputError> {
        match output.ensure_v0_ref()? {
            LightningOutputV0::Contract(contract) => {
                let contract_id = contract.contract.contract_id();

                if dbtx.get_value(&ContractKey(contract_id)).await.is_some() {
                    return Err(LightningOutputError::ContractAlreadyFunded(contract_id));
                }
            }
            LightningOutputV0::Offer(offer) => {
                if dbtx
                    .get_value(&ContractKey(offer.contract_id()))
                    .await
                    .is_some()
                {
                    return Err(LightningOutputError::OfferForFundedContract(
                        offer.contract_id(),
                    ));
                }
            }
            LightningOutputV0::CancelOutgoing { .. } => {}
        }

        Ok(())
    }

    async fn audit(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        audit: &mut Audit,
        module_instance_id: ModuleInstanceId,
    ) {
        audit
            .add_items(
                dbtx,
                module_instance_id,
                &LightningAuditItemKeyPrefix,
                // Both incoming and outgoing contracts represent liabilities to the federation
                // since they are obligations to issue notes.
                |_, v| -(v.msats as i64),
            )
            .await;
    }

    fn api_endpoints(&self) -> Vec<ApiEndpoint<Self>> {
        vec![
            api_endpoint! {
                BLOCK_COUNT_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &Lightning, context, _v: ()| -> Option<u64> {
                    let db = context.db();
                    let mut dbtx = db.begin_transaction_nc().await;
                    Ok(Some(module.consensus_block_count(&mut dbtx).await))
                }
            },
            api_endpoint! {
                MODULE_CONSENSUS_VERSION_ENDPOINT,
                ApiVersion::new(0, 1),
                async |module: &Lightning, context, _params: ()| -> ModuleConsensusVersion {
                    let db = context.db();
                    let mut dbtx = db.begin_transaction_nc().await;
                    Ok(module.consensus_module_consensus_version(&mut dbtx).await)
                }
            },
            api_endpoint! {
                SUPPORTED_MODULE_CONSENSUS_VERSION_ENDPOINT,
                ApiVersion::new(0, 1),
                async |_module: &Lightning, _context, _params: ()| -> ModuleConsensusVersion {
                    Ok(MODULE_CONSENSUS_VERSION)
                }
            },
            api_endpoint! {
                ACCOUNT_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &Lightning, context, contract_id: ContractId| -> Option<ContractAccount> {
                    let db = context.db();
                    let mut dbtx = db.begin_transaction_nc().await;
                    Ok(module
                        .get_contract_account(&mut dbtx, contract_id)
                        .await)
                }
            },
            api_endpoint! {
                AWAIT_ACCOUNT_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &Lightning, context, contract_id: ContractId| -> ContractAccount {
                    Ok(module
                        .wait_contract_account(context, contract_id)
                        .await)
                }
            },
            api_endpoint! {
                AWAIT_BLOCK_HEIGHT_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &Lightning, context, block_height: u64| -> () {
                    let db = context.db();
                    let mut dbtx = db.begin_transaction_nc().await;
                    module.wait_block_height(block_height, &mut dbtx).await;
                    Ok(())
                }
            },
            api_endpoint! {
                AWAIT_OUTGOING_CONTRACT_CANCELLED_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &Lightning, context, contract_id: ContractId| -> ContractAccount {
                    Ok(module.wait_outgoing_contract_account_cancelled(context, contract_id).await)
                }
            },
            api_endpoint! {
                GET_DECRYPTED_PREIMAGE_STATUS,
                ApiVersion::new(0, 0),
                async |module: &Lightning, context, contract_id: ContractId| -> (IncomingContractAccount, DecryptedPreimageStatus) {
                    module.get_decrypted_preimage_status(context, contract_id).await
                }
            },
            api_endpoint! {
                AWAIT_PREIMAGE_DECRYPTION,
                ApiVersion::new(0, 0),
                async |module: &Lightning, context, contract_id: ContractId| -> (IncomingContractAccount, Option<Preimage>) {
                    Ok(module.wait_preimage_decrypted(context, contract_id).await)
                }
            },
            api_endpoint! {
                OFFER_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &Lightning, context, payment_hash: bitcoin_hashes::sha256::Hash| -> Option<IncomingContractOffer> {
                    let db = context.db();
                    let mut dbtx = db.begin_transaction_nc().await;
                    Ok(module
                        .get_offer(&mut dbtx, payment_hash)
                        .await)
               }
            },
            api_endpoint! {
                AWAIT_OFFER_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &Lightning, context, payment_hash: bitcoin_hashes::sha256::Hash| -> IncomingContractOffer {
                    Ok(module
                        .wait_offer(context, payment_hash)
                        .await)
                }
            },
            api_endpoint! {
                LIST_GATEWAYS_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &Lightning, context, _v: ()| -> Vec<LightningGatewayAnnouncement> {
                    let db = context.db();
                    let mut dbtx = db.begin_transaction_nc().await;
                    Ok(module.list_gateways(&mut dbtx).await)
                }
            },
            api_endpoint! {
                REGISTER_GATEWAY_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &Lightning, context, gateway: LightningGatewayAnnouncement| -> () {
                    let db = context.db();
                    let mut dbtx = db.begin_transaction().await;
                    let gateway_id = gateway.info.gateway_id;
                    module.register_gateway(&mut dbtx.to_ref_nc(), gateway).await.map_err(|err| {
                        warn!(target: LOG_MODULE_LN, err = %err.fmt_compact_anyhow(), %gateway_id, "Rejected gateway registration");
                        ApiError::bad_request(err.to_string())
                    })?;
                    dbtx.commit_tx_result().await?;
                    Ok(())
                }
            },
            api_endpoint! {
                REMOVE_GATEWAY_CHALLENGE_ENDPOINT,
                ApiVersion::new(0, 1),
                async |module: &Lightning, context, gateway_id: PublicKey| -> Option<sha256::Hash> {
                    let db = context.db();
                    let mut dbtx = db.begin_transaction_nc().await;
                    Ok(module.get_gateway_remove_challenge(gateway_id, &mut dbtx).await)
                }
            },
            api_endpoint! {
                REMOVE_GATEWAY_ENDPOINT,
                ApiVersion::new(0, 1),
                async |module: &Lightning, context, remove_gateway_request: RemoveGatewayRequest| -> bool {
                    let db = context.db();
                    let mut dbtx = db.begin_transaction().await;
                    let result = module.remove_gateway(remove_gateway_request.clone(), &mut dbtx.to_ref_nc()).await;
                    match result {
                        Ok(()) => {
                            dbtx.commit_tx_result().await?;
                            Ok(true)
                        },
                        Err(err) => {
                            warn!(target: LOG_MODULE_LN, err = %err.fmt_compact_anyhow(), gateway_id = %remove_gateway_request.gateway_id, "Unable to remove gateway registration");
                            Ok(false)
                        },
                    }
                }
            },
        ]
    }
}

impl Lightning {
    fn get_block_count(&self) -> anyhow::Result<u64> {
        self.server_bitcoin_rpc_monitor
            .status()
            .map(|status| status.block_count)
            .context("Block count not available yet")
    }

    async fn consensus_block_count(&self, dbtx: &mut DatabaseTransaction<'_>) -> u64 {
        let peer_count = 3 * (self.cfg.consensus.threshold() / 2) + 1;

        let mut counts = dbtx
            .find_by_prefix(&BlockCountVotePrefix)
            .await
            .map(|(.., count)| count)
            .collect::<Vec<_>>()
            .await;

        assert!(counts.len() <= peer_count);

        while counts.len() < peer_count {
            counts.push(0);
        }

        counts.sort_unstable();

        counts[peer_count / 2]
    }

    async fn wait_block_height(&self, block_height: u64, dbtx: &mut DatabaseTransaction<'_>) {
        while block_height >= self.consensus_block_count(dbtx).await {
            sleep(Duration::from_secs(5)).await;
        }
    }

    async fn consensus_module_consensus_version(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
    ) -> ModuleConsensusVersion {
        let mut versions = dbtx
            .find_by_prefix(&ConsensusVersionVotePrefix)
            .await
            .map(|entry| entry.1)
            .collect::<Vec<ModuleConsensusVersion>>()
            .await;

        while versions.len() < self.num_peers.total() {
            versions.push(ModuleConsensusVersion::new(2, 0));
        }

        assert_eq!(versions.len(), self.num_peers.total());

        versions.sort_unstable();

        assert!(versions.first() <= versions.last());

        versions[self.num_peers.max_evil()]
    }

    /// Whether the funded-exactly-once rules of
    /// [`CONTRACT_FUNDED_ONCE_MODULE_CONSENSUS_VERSION`] are active, i.e. the
    /// federation has voted that version in.
    async fn is_contract_funded_once_active(&self, dbtx: &mut DatabaseTransaction<'_>) -> bool {
        CONTRACT_FUNDED_ONCE_MODULE_CONSENSUS_VERSION
            <= self.consensus_module_consensus_version(dbtx).await
    }

    /// Tracks the highest module consensus version supported by *every* peer.
    ///
    /// A vote is only ever proposed once this reports a version, which requires
    /// every peer to have answered. Peers that predate a version do not serve
    /// [`SUPPORTED_MODULE_CONSENSUS_VERSION_ENDPOINT`] at all, so they hold the
    /// federation back rather than being voted past.
    fn spawn_peer_supported_consensus_version_task(
        api_client: DynModuleApi,
        task_group: &TaskGroup,
        our_peer_id: PeerId,
    ) -> watch::Receiver<Option<ModuleConsensusVersion>> {
        let (sender, receiver) = watch::channel(None);
        task_group.spawn_cancellable("fetch-peer-consensus-versions", async move {
            loop {
                let request_futures = api_client
                    .all_peers()
                    .iter()
                    .filter(|&&peer| peer != our_peer_id)
                    .map(|&peer| {
                        let api_client = api_client.clone();

                        async move {
                            api_client
                                .request_single_peer::<ModuleConsensusVersion>(
                                    SUPPORTED_MODULE_CONSENSUS_VERSION_ENDPOINT.to_owned(),
                                    ApiRequestErased::default(),
                                    peer,
                                )
                                .await
                                .inspect_err(|err| warn!(
                                    target: LOG_MODULE_LN,
                                    %peer,
                                    err = %err.fmt_compact(),
                                    "Failed to fetch supported consensus version from peer"
                                ))
                                .ok()
                        }
                    });

                // A peer that does not answer runs a binary without version voting, so
                // collecting into an `Option` holds the federation back on any absence
                // rather than voting that peer past a version it cannot decode.
                let all_peers_supported_version = join_all(request_futures)
                    .await
                    .into_iter()
                    .collect::<Option<Vec<_>>>()
                    .map(|peer_versions| {
                        peer_versions
                            .into_iter()
                            .chain(std::iter::once(MODULE_CONSENSUS_VERSION))
                            .min()
                            .expect("Our own version is always present")
                    });

                debug!(
                    target: LOG_MODULE_LN,
                    ?all_peers_supported_version,
                    "Fetched supported consensus versions from peers"
                );

                #[allow(clippy::disallowed_methods)]
                if sender.send(all_peers_supported_version).is_err() {
                    warn!(target: LOG_MODULE_LN, "Failed to send consensus version to watch channel, stopping task");
                    break;
                }

                sleep(next_poll_delay(all_peers_supported_version.is_some())).await;
            }
        });
        receiver
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

    async fn get_offer(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        payment_hash: bitcoin_hashes::sha256::Hash,
    ) -> Option<IncomingContractOffer> {
        dbtx.get_value(&OfferKey(payment_hash)).await
    }

    async fn wait_offer(
        &self,
        context: &mut ApiEndpointContext,
        payment_hash: bitcoin_hashes::sha256::Hash,
    ) -> IncomingContractOffer {
        let future = context.wait_key_exists(OfferKey(payment_hash));
        future.await
    }

    async fn get_contract_account(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        contract_id: ContractId,
    ) -> Option<ContractAccount> {
        dbtx.get_value(&ContractKey(contract_id)).await
    }

    async fn wait_contract_account(
        &self,
        context: &mut ApiEndpointContext,
        contract_id: ContractId,
    ) -> ContractAccount {
        // not using a variable here leads to a !Send error
        let future = context.wait_key_exists(ContractKey(contract_id));
        future.await
    }

    async fn wait_outgoing_contract_account_cancelled(
        &self,
        context: &mut ApiEndpointContext,
        contract_id: ContractId,
    ) -> ContractAccount {
        let future =
            context.wait_value_matches(ContractKey(contract_id), |contract| {
                match &contract.contract {
                    FundedContract::Outgoing(c) => c.cancelled,
                    FundedContract::Incoming(_) => false,
                }
            });
        future.await
    }

    async fn get_decrypted_preimage_status(
        &self,
        context: &mut ApiEndpointContext,
        contract_id: ContractId,
    ) -> Result<(IncomingContractAccount, DecryptedPreimageStatus), ApiError> {
        let f_contract = context.wait_key_exists(ContractKey(contract_id));
        let contract = f_contract.await;
        // `ContractKey` holds either contract variant and anyone can fund an
        // outgoing contract, so the caller decides which variant we find here.
        let incoming_contract_account =
            Self::get_incoming_contract_account(contract).ok_or_else(|| {
                ApiError::bad_request("Contract is not an incoming contract".to_string())
            })?;
        Ok(
            match &incoming_contract_account.contract.decrypted_preimage {
                DecryptedPreimage::Some(key) => (
                    incoming_contract_account.clone(),
                    DecryptedPreimageStatus::Some(Preimage(
                        sha256::Hash::hash(&key.0).to_byte_array(),
                    )),
                ),
                DecryptedPreimage::Pending => {
                    (incoming_contract_account, DecryptedPreimageStatus::Pending)
                }
                DecryptedPreimage::Invalid => {
                    (incoming_contract_account, DecryptedPreimageStatus::Invalid)
                }
            },
        )
    }

    async fn wait_preimage_decrypted(
        &self,
        context: &mut ApiEndpointContext,
        contract_id: ContractId,
    ) -> (IncomingContractAccount, Option<Preimage>) {
        let future =
            context.wait_value_matches(ContractKey(contract_id), |contract| {
                match &contract.contract {
                    FundedContract::Incoming(c) => match c.contract.decrypted_preimage {
                        DecryptedPreimage::Pending => false,
                        DecryptedPreimage::Some(_) | DecryptedPreimage::Invalid => true,
                    },
                    FundedContract::Outgoing(_) => false,
                }
            });

        let decrypt_preimage = future.await;
        let incoming_contract_account = Self::get_incoming_contract_account(decrypt_preimage)
            .expect("the matcher above only resolves for incoming contracts");
        match incoming_contract_account
            .clone()
            .contract
            .decrypted_preimage
        {
            DecryptedPreimage::Some(key) => (
                incoming_contract_account,
                Some(Preimage(sha256::Hash::hash(&key.0).to_byte_array())),
            ),
            _ => (incoming_contract_account, None),
        }
    }

    fn get_incoming_contract_account(contract: ContractAccount) -> Option<IncomingContractAccount> {
        match contract.contract {
            FundedContract::Incoming(incoming) => Some(IncomingContractAccount {
                amount: contract.amount,
                contract: incoming.contract,
            }),
            FundedContract::Outgoing(_) => None,
        }
    }

    async fn list_gateways(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
    ) -> Vec<LightningGatewayAnnouncement> {
        let stream = dbtx.find_by_prefix(&LightningGatewayKeyPrefix).await;
        stream
            .filter_map(|(_, gw)| async { if gw.is_expired() { None } else { Some(gw) } })
            .collect::<Vec<LightningGatewayRegistration>>()
            .await
            .into_iter()
            .map(LightningGatewayRegistration::unanchor)
            .collect::<Vec<LightningGatewayAnnouncement>>()
    }

    /// Stores a gateway registration, rejecting announcements that are not
    /// entitled to overwrite the record currently held for their `gateway_id`.
    ///
    /// A registration carrying a valid
    /// [`fedimint_ln_common::GatewayRegistrationAuth`] outranks an
    /// unsigned one. Since only the holder of the secret key behind
    /// `gateway_id` can produce a signature, this means:
    ///
    /// - a gateway that signs cannot have its record replaced by anyone else,
    /// - a gateway that does not sign is exactly as exposed as it was before
    ///   proofs existed, and no more,
    /// - an attacker can never lock a gateway out of its own `gateway_id`,
    ///   because unsigned records never block other unsigned registrations.
    ///
    /// So gateways gain protection individually as they upgrade, with no
    /// coordinated rollout and no regression for those that have not.
    async fn register_gateway(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        mut gateway: LightningGatewayAnnouncement,
    ) -> anyhow::Result<()> {
        // Garbage collect expired gateways (since we're already writing to the DB)
        // Note: A "gotcha" of doing this here is that if two gateways are registered
        // at the same time, they will both attempt to delete the same expired gateways
        // and one of them will fail. This should be fine, since the other one will
        // succeed and the failed one will just try again.
        self.delete_expired_gateways(dbtx).await;

        let gateway_id = gateway.info.gateway_id;

        // Reject a forged proof outright rather than silently downgrading it to an
        // unsigned registration, which would hide a misconfigured gateway.
        if let Some(auth) = &gateway.auth {
            let msg = create_gateway_registration_message(
                self.cfg.consensus.threshold_pub_keys.public_key(),
                auth.nonce,
                &gateway.info,
            );

            auth.signature
                .verify(&msg, &gateway_id.x_only_public_key().0)
                .context("Invalid gateway registration signature")?;
        }

        // Registrations are garbage collected above, so anything still present is
        // live and its claim on this `gateway_id` has to be honored.
        if let Some(existing) = dbtx.get_value(&LightningGatewayKey(gateway_id)).await
            && let Some(existing_auth) = existing.auth
        {
            let auth = gateway.auth.as_ref().context(
                "Gateway registration is signed and cannot be replaced by an unsigned one",
            )?;

            // The nonce only has to move for announcements that actually change
            // something. Re-registering identical settings is the common case —
            // gateways refresh well inside the TTL — and replaying it cannot
            // achieve anything beyond extending a lifetime that is clamped
            // anyway. Exempting it keeps a gateway whose clock stepped backwards
            // from being locked out of refreshing its own registration.
            anyhow::ensure!(
                auth.nonce > existing_auth.nonce || gateway.info == existing.info,
                "Gateway registration nonce must increase to change settings, got {} but stored {}",
                auth.nonce,
                existing_auth.nonce
            );

            // The exemption must not let the ratchet fall back, or it defeats
            // itself: gateways refresh every few minutes and `auth` is served
            // publicly, so an attacker could replay an old identical-settings
            // announcement to lower the stored nonce and then replay an
            // intermediate one to restore stale settings. Keep the highest nonce
            // seen, along with the signature that goes with it, so the stored
            // proof stays self-consistent for clients that verify it.
            if auth.nonce < existing_auth.nonce {
                gateway.auth = Some(existing_auth);
            }
        }

        // Whether a gateway is vetted is the federation's judgement to make, not a
        // property a gateway gets to assert about itself.
        gateway.vetted = false;

        dbtx.insert_entry(&LightningGatewayKey(gateway_id), &gateway.anchor())
            .await;

        Ok(())
    }

    async fn delete_expired_gateways(&self, dbtx: &mut DatabaseTransaction<'_>) {
        let expired_gateway_keys = dbtx
            .find_by_prefix(&LightningGatewayKeyPrefix)
            .await
            .filter_map(|(key, gw)| async move { if gw.is_expired() { Some(key) } else { None } })
            .collect::<Vec<LightningGatewayKey>>()
            .await;

        for key in expired_gateway_keys {
            dbtx.remove_entry(&key).await;
        }
    }

    /// Returns the challenge to the gateway that must be signed by the
    /// gateway's private key in order for the gateway registration record
    /// to be removed. The challenge is the concatenation of the gateway's
    /// public key and the `valid_until` bytes. This ensures that the
    /// challenges changes every time the gateway is re-registered and ensures
    /// that the challenge is unique per-gateway.
    async fn get_gateway_remove_challenge(
        &self,
        gateway_id: PublicKey,
        dbtx: &mut DatabaseTransaction<'_>,
    ) -> Option<sha256::Hash> {
        match dbtx.get_value(&LightningGatewayKey(gateway_id)).await {
            Some(gateway) => {
                let mut valid_until_bytes = gateway.valid_until.to_bytes();
                let mut challenge_bytes = gateway_id.to_bytes();
                challenge_bytes.append(&mut valid_until_bytes);
                Some(sha256::Hash::hash(&challenge_bytes))
            }
            _ => None,
        }
    }

    /// Removes the gateway registration record. First the signature provided by
    /// the gateway is verified by checking if the gateway's challenge has
    /// been signed by the gateway's private key.
    async fn remove_gateway(
        &self,
        remove_gateway_request: RemoveGatewayRequest,
        dbtx: &mut DatabaseTransaction<'_>,
    ) -> anyhow::Result<()> {
        let fed_public_key = self.cfg.consensus.threshold_pub_keys.public_key();
        let gateway_id = remove_gateway_request.gateway_id;
        let our_peer_id = self.our_peer_id;
        let signature = remove_gateway_request
            .signatures
            .get(&our_peer_id)
            .ok_or_else(|| {
                warn!(target: LOG_MODULE_LN, "No signature provided for gateway: {gateway_id}");
                anyhow::anyhow!("No signature provided for gateway {gateway_id}")
            })?;

        // If there is no challenge, the gateway does not exist in the database and
        // there is nothing to do
        let challenge = self
            .get_gateway_remove_challenge(gateway_id, dbtx)
            .await
            .ok_or(anyhow::anyhow!(
                "Gateway {gateway_id} is not registered with peer {our_peer_id}"
            ))?;

        // Verify the supplied schnorr signature is valid
        let msg = create_gateway_remove_message(fed_public_key, our_peer_id, challenge);
        signature.verify(&msg, &gateway_id.x_only_public_key().0)?;

        dbtx.remove_entry(&LightningGatewayKey(gateway_id)).await;
        info!(target: LOG_MODULE_LN, "Successfully removed gateway: {gateway_id}");
        Ok(())
    }
}

fn record_funded_contract_metric(updated_contract_account: &ContractAccount) {
    LN_FUNDED_CONTRACT_SATS
        .with_label_values(&[match updated_contract_account.contract {
            FundedContract::Incoming(_) => "incoming",
            FundedContract::Outgoing(_) => "outgoing",
        }])
        .observe(updated_contract_account.amount.sats_f64());
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use assert_matches::assert_matches;
    use bitcoin_hashes::{Hash as BitcoinHash, sha256};
    use fedimint_core::bitcoin::{Block, BlockHash};
    use fedimint_core::db::mem_impl::MemDatabase;
    use fedimint_core::db::{
        Committable, Database, DatabaseTransaction, IDatabaseTransactionOpsCoreTyped,
    };
    use fedimint_core::encoding::{Decodable, Encodable};
    use fedimint_core::envs::BitcoinRpcConfig;
    use fedimint_core::module::registry::{ModuleDecoderRegistry, ModuleRegistry};
    use fedimint_core::module::{Amounts, ApiEndpointContext, InputMeta, TransactionItemAmounts};
    use fedimint_core::secp256k1::{Keypair, PublicKey, SECP256K1, generate_keypair};
    use fedimint_core::task::TaskGroup;
    use fedimint_core::util::SafeUrl;
    use fedimint_core::{
        Amount, Feerate, InPoint, NumPeers, OutPoint, PeerId, TransactionId,
    };
    use fedimint_ln_common::config::{LightningClientConfig, LightningConfig, Network};
    use fedimint_ln_common::contracts::incoming::{
        FundedIncomingContract, IncomingContract, IncomingContractOffer,
    };
    use fedimint_ln_common::contracts::outgoing::OutgoingContract;
    use fedimint_ln_common::contracts::{
        Contract, DecryptedPreimage, EncryptedPreimage, FundedContract, IdentifiableContract,
        Preimage, PreimageKey,
    };
    use fedimint_ln_common::{
        CONTRACT_FUNDED_ONCE_MODULE_CONSENSUS_VERSION, ContractAccount, ContractOutput,
        GatewayRegistrationAuth, LightningGateway, LightningGatewayAnnouncement, LightningInput,
        LightningOutput, LightningOutputError, MAX_GATEWAY_REGISTRATION_TTL,
    };
    use fedimint_server_core::bitcoin_rpc::{IServerBitcoinRpc, ServerBitcoinRpcMonitor};
    use fedimint_server_core::{ServerModule, ServerModuleInit};
    use rand::rngs::OsRng;
    use tokio::sync::watch;

    use crate::db::{
        ConsensusVersionVoteKey, ContractKey, LightningAuditItemKey, LightningGatewayKey, OfferKey,
    };
    use crate::{Lightning, LightningInit, create_gateway_registration_message};

    #[derive(Debug)]
    struct MockBitcoinServerRpc;

    #[async_trait::async_trait]
    impl IServerBitcoinRpc for MockBitcoinServerRpc {
        fn get_bitcoin_rpc_config(&self) -> BitcoinRpcConfig {
            BitcoinRpcConfig {
                kind: "mock".to_string(),
                url: "http://mock".parse().unwrap(),
            }
        }

        fn get_url(&self) -> SafeUrl {
            "http://mock".parse().unwrap()
        }

        async fn get_network(&self) -> anyhow::Result<Network> {
            Err(anyhow::anyhow!("Mock network error"))
        }

        async fn get_block_count(&self) -> anyhow::Result<u64> {
            Err(anyhow::anyhow!("Mock block count error"))
        }

        async fn get_block_hash(&self, _height: u64) -> anyhow::Result<BlockHash> {
            Err(anyhow::anyhow!("Mock block hash error"))
        }

        async fn get_block(&self, _block_hash: &BlockHash) -> anyhow::Result<Block> {
            Err(anyhow::anyhow!("Mock block error"))
        }

        async fn get_feerate(&self) -> anyhow::Result<Option<Feerate>> {
            Err(anyhow::anyhow!("Mock feerate error"))
        }

        async fn submit_transaction(&self, _transaction: fedimint_core::bitcoin::Transaction) {
            // No-op for mock
        }

        async fn get_sync_progress(&self) -> anyhow::Result<Option<f64>> {
            Err(anyhow::anyhow!("Mock sync percentage error"))
        }
    }

    const MINTS: u16 = 4;

    fn build_configs() -> (Vec<LightningConfig>, LightningClientConfig) {
        let peers = (0..MINTS).map(PeerId::from).collect::<Vec<_>>();
        let args = fedimint_server_core::ConfigGenModuleArgs {
            network: Network::Regtest,
            disable_base_fees: false,
        };
        let server_cfg = ServerModuleInit::trusted_dealer_gen(&LightningInit, &peers, &args);

        let client_cfg = ServerModuleInit::get_client_config(
            &LightningInit,
            &server_cfg[&PeerId::from(0)].consensus,
        )
        .unwrap();

        let server_cfg = server_cfg
            .into_values()
            .map(|config| {
                config
                    .to_typed()
                    .expect("Config was just generated by the same configgen")
            })
            .collect::<Vec<LightningConfig>>();

        (server_cfg, client_cfg)
    }

    fn random_pub_key() -> PublicKey {
        generate_keypair(&mut OsRng).1
    }

    #[test_log::test(tokio::test)]
    async fn encrypted_preimage_only_usable_once() {
        let task_group = TaskGroup::new();
        let (server_cfg, client_cfg) = build_configs();

        let server = mock_server(&server_cfg[0], &task_group);

        let preimage = [42u8; 32];
        let encrypted_preimage = EncryptedPreimage(client_cfg.threshold_pub_key.encrypt([42; 32]));

        let hash = preimage.consensus_hash();
        let offer = IncomingContractOffer {
            amount: Amount::from_sats(10),
            hash,
            encrypted_preimage: encrypted_preimage.clone(),
            expiry_time: None,
        };
        let output = LightningOutput::new_v0_offer(offer);
        let out_point = OutPoint {
            txid: TransactionId::all_zeros(),
            out_idx: 0,
        };

        let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
        let mut dbtx = db.begin_transaction_nc().await;

        server
            .process_output(
                &mut dbtx.to_ref_with_prefix_module_id(42).0.into_nc(),
                &output,
                out_point,
            )
            .await
            .expect("First time works");

        let hash2 = [21u8, 32].consensus_hash();
        let offer2 = IncomingContractOffer {
            amount: Amount::from_sats(1),
            hash: hash2,
            encrypted_preimage,
            expiry_time: None,
        };
        let output2 = LightningOutput::new_v0_offer(offer2);
        let out_point2 = OutPoint {
            txid: TransactionId::all_zeros(),
            out_idx: 1,
        };

        assert_matches!(
            server
                .process_output(
                    &mut dbtx.to_ref_with_prefix_module_id(42).0.into_nc(),
                    &output2,
                    out_point2
                )
                .await,
            Err(_)
        );
    }

    fn mock_server(cfg: &LightningConfig, task_group: &TaskGroup) -> Lightning {
        Lightning {
            cfg: cfg.clone(),
            our_peer_id: 0.into(),
            num_peers: NumPeers::from(usize::from(MINTS)),
            // No peer has reported a supported version, so no upgrade is ever
            // proposed. None of these tests exercise version voting.
            peer_supported_consensus_version: watch::channel(None).1,
            server_bitcoin_rpc_monitor: ServerBitcoinRpcMonitor::new(
                MockBitcoinServerRpc.into_dyn(),
                Duration::from_secs(1),
                task_group,
            ),
        }
    }

    fn offer_output(hash: sha256::Hash, encrypted_preimage: &EncryptedPreimage) -> LightningOutput {
        LightningOutput::new_v0_offer(IncomingContractOffer {
            amount: Amount::from_msats(1),
            hash,
            encrypted_preimage: encrypted_preimage.clone(),
            expiry_time: None,
        })
    }

    fn incoming_contract_output(
        hash: sha256::Hash,
        encrypted_preimage: &EncryptedPreimage,
    ) -> LightningOutput {
        LightningOutput::new_v0_contract(ContractOutput {
            amount: Amount::from_msats(1),
            contract: Contract::Incoming(IncomingContract {
                hash,
                encrypted_preimage: encrypted_preimage.clone(),
                decrypted_preimage: DecryptedPreimage::Pending,
                gateway_key: random_pub_key(),
            }),
        })
    }

    /// Apply `outputs` as if they were the outputs of one transaction.
    async fn fund(
        server: &Lightning,
        dbtx: &mut fedimint_core::db::DatabaseTransaction<'_, Committable>,
        outputs: &[LightningOutput],
        txid_byte: u8,
    ) -> Result<(), LightningOutputError> {
        for (idx, output) in outputs.iter().enumerate() {
            server
                .process_output(
                    &mut dbtx.to_ref_with_prefix_module_id(42).0.into_nc(),
                    output,
                    OutPoint {
                        txid: TransactionId::from_byte_array([txid_byte; 32]),
                        out_idx: idx as u64,
                    },
                )
                .await?;
        }

        Ok(())
    }

    /// Encryption is randomized and `EncryptedPreimage::verify` does not bind
    /// the ciphertext to the payment hash, so distinct ciphertexts for one
    /// hash are free to construct and the offer dedup index does not catch
    /// them.
    fn ciphertexts<const N: usize>(
        cfg: &LightningClientConfig,
        preimage: [u8; 32],
    ) -> [EncryptedPreimage; N] {
        std::array::from_fn(|_| EncryptedPreimage(cfg.threshold_pub_key.encrypt(preimage)))
    }

    /// Funding a payment hash twice within one transaction: the first funding
    /// consumes the offer, so a second offer is accepted, and without the guard
    /// the second funding would overwrite the pending decryption proposal.
    #[test_log::test(tokio::test)]
    async fn incoming_funding_rejected_while_decryption_pending() {
        let task_group = TaskGroup::new();
        let (server_cfg, client_cfg) = build_configs();
        let server = mock_server(&server_cfg[0], &task_group);

        let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
        let mut dbtx = db.begin_transaction().await;

        let preimage = [42u8; 32];
        let hash = preimage.consensus_hash();
        let [ct1, ct2] = ciphertexts(&client_cfg, preimage);

        fund(
            &server,
            &mut dbtx,
            &[
                offer_output(hash, &ct1),
                incoming_contract_output(hash, &ct1),
                offer_output(hash, &ct2),
            ],
            0x01,
        )
        .await
        .expect("the first offer/contract pair and the second offer are valid");

        // A distinct txid, so the second funding reaches the pending-decryption
        // guard rather than colliding on the first transaction's
        // `ContractUpdateKey` outpoint and passing for the wrong reason.
        assert_matches!(
            fund(
                &server,
                &mut dbtx,
                &[incoming_contract_output(hash, &ct2)],
                0x02
            )
            .await,
            Err(LightningOutputError::ContractAlreadyFunded(_)),
            "funding again while the decryption proposal is pending must be rejected"
        );
    }

    /// Two separately submitted transactions can both pass submission-mode
    /// validation while neither is committed yet, because the consensus data
    /// provider never re-validates. The guard therefore has to hold when
    /// consensus applies them in order, not just within one transaction.
    #[test_log::test(tokio::test)]
    async fn incoming_funding_rejected_across_transactions() {
        let task_group = TaskGroup::new();
        let (server_cfg, client_cfg) = build_configs();
        let server = mock_server(&server_cfg[0], &task_group);

        let db = Database::new(MemDatabase::new(), ModuleRegistry::default());

        let preimage = [42u8; 32];
        let hash = preimage.consensus_hash();
        let [ct1, ct2] = ciphertexts(&client_cfg, preimage);

        let tx_a = [
            offer_output(hash, &ct1),
            incoming_contract_output(hash, &ct1),
        ];
        let tx_b = [
            offer_output(hash, &ct2),
            incoming_contract_output(hash, &ct2),
        ];

        // both are validated against the same committed state, as neither has been
        // ordered yet, and both are queued for consensus
        for (outputs, txid_byte) in [(&tx_a, 0xaa), (&tx_b, 0xbb)] {
            let mut dbtx = db.begin_transaction().await;
            dbtx.ignore_uncommitted();
            fund(&server, &mut dbtx, outputs, txid_byte)
                .await
                .expect("both transactions are valid against the pre-funding state");
        }

        let mut dbtx = db.begin_transaction().await;
        fund(&server, &mut dbtx, &tx_a, 0xaa)
            .await
            .expect("the first transaction is accepted");
        dbtx.commit_tx().await;

        let mut dbtx = db.begin_transaction().await;
        assert_matches!(
            fund(&server, &mut dbtx, &tx_b, 0xbb).await,
            Err(LightningOutputError::ContractAlreadyFunded(_)),
            "the second transaction must be rejected instead of panicking"
        );
    }

    /// Every funding is gated on an offer and consumes it, so a payment hash
    /// can never be funded twice without a fresh offer being created in
    /// between. This bounds how fast an attacker can reach a second
    /// funding, and is what makes the funder-side check in the client
    /// race-free.
    #[test_log::test(tokio::test)]
    async fn incoming_offer_is_consumed_by_funding() {
        let task_group = TaskGroup::new();
        let (server_cfg, client_cfg) = build_configs();
        let server = mock_server(&server_cfg[0], &task_group);

        let db = Database::new(MemDatabase::new(), ModuleRegistry::default());

        let preimage = [42u8; 32];
        let hash = preimage.consensus_hash();
        let [ct1] = ciphertexts(&client_cfg, preimage);

        let mut dbtx = db.begin_transaction().await;
        fund(
            &server,
            &mut dbtx,
            &[
                offer_output(hash, &ct1),
                incoming_contract_output(hash, &ct1),
            ],
            0x01,
        )
        .await
        .expect("offer and funding accepted");

        assert!(
            dbtx.to_ref_with_prefix_module_id(42)
                .0
                .into_nc()
                .get_value(&OfferKey(hash))
                .await
                .is_none(),
            "a funding must consume the offer that gated it"
        );
    }

    /// The tightest race available to an attacker: poison the account and
    /// re-arm an offer in a single transaction, so that a funder's
    /// transaction ordered immediately afterwards still finds an offer. The
    /// poisoned contract is necessarily still pending at that point, so the
    /// guard catches it.
    #[test_log::test(tokio::test)]
    async fn poisoning_and_rearming_an_offer_leaves_the_contract_pending() {
        let task_group = TaskGroup::new();
        let (server_cfg, client_cfg) = build_configs();
        let server = mock_server(&server_cfg[0], &task_group);

        let db = Database::new(MemDatabase::new(), ModuleRegistry::default());

        let preimage = [42u8; 32];
        let hash = preimage.consensus_hash();
        let [ct1, ct2, ct3] = ciphertexts(&client_cfg, preimage);

        let mut dbtx = db.begin_transaction().await;
        fund(&server, &mut dbtx, &[offer_output(hash, &ct1)], 0x01)
            .await
            .expect("offer accepted");
        dbtx.commit_tx().await;

        let mut dbtx = db.begin_transaction().await;
        fund(
            &server,
            &mut dbtx,
            &[
                incoming_contract_output(hash, &ct1),
                offer_output(hash, &ct2),
            ],
            0x02,
        )
        .await
        .expect("poisoning funding and re-armed offer accepted");
        dbtx.commit_tx().await;

        let mut dbtx = db.begin_transaction().await;
        assert_matches!(
            fund(
                &server,
                &mut dbtx,
                &[incoming_contract_output(hash, &ct3)],
                0x03
            )
            .await,
            Err(LightningOutputError::ContractAlreadyFunded(_)),
            "a funder ordered right after the re-arm must not top up the poisoned account"
        );
    }

    /// An incoming contract carries its own ciphertext, which used to reach
    /// `decrypt_share` unvalidated and panic the guardian mid-consensus.
    #[test_log::test(tokio::test)]
    async fn incoming_contract_with_unverifiable_ciphertext_is_rejected() {
        let task_group = TaskGroup::new();
        let (server_cfg, client_cfg) = build_configs();

        let server = mock_server(&server_cfg[0], &task_group);

        let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
        let mut dbtx = db.begin_transaction_nc().await;

        let preimage = PreimageKey(generate_keypair(&mut OsRng).1.serialize());
        let hash = sha256::Hash::hash(&sha256::Hash::hash(&preimage.0).to_byte_array());
        let valid_preimage = EncryptedPreimage(client_cfg.threshold_pub_key.encrypt(preimage.0));

        server
            .process_output(
                &mut dbtx.to_ref_with_prefix_module_id(42).0.into_nc(),
                &LightningOutput::new_v0_offer(IncomingContractOffer {
                    amount: Amount::from_sats(10),
                    hash,
                    encrypted_preimage: valid_preimage.clone(),
                    expiry_time: None,
                }),
                OutPoint {
                    txid: TransactionId::all_zeros(),
                    out_idx: 0,
                },
            )
            .await
            .expect("offer with a valid ciphertext is accepted");

        // Mutate the ciphertext and round-trip it through the consensus
        // encoding, so the poisoned value is one a peer could receive on the
        // wire rather than one only constructible in-process.
        let encoded = valid_preimage.consensus_encode_to_vec();
        let unverifiable = (0..encoded.len())
            .flat_map(|pos| (0..8u8).map(move |bit| (pos, bit)))
            .find_map(|(pos, bit)| {
                let mut mutated = encoded.clone();
                mutated[pos] ^= 1 << bit;
                EncryptedPreimage::consensus_decode_whole(
                    &mutated,
                    &ModuleDecoderRegistry::default(),
                )
                .ok()
                .filter(|decoded| !decoded.0.verify())
            })
            .expect("a decodable but unverifiable ciphertext exists");

        let output = LightningOutput::new_v0_contract(ContractOutput {
            amount: Amount::from_sats(10),
            contract: Contract::Incoming(IncomingContract {
                hash,
                encrypted_preimage: unverifiable,
                decrypted_preimage: DecryptedPreimage::Pending,
                gateway_key: random_pub_key(),
            }),
        });

        assert_matches!(
            server
                .process_output(
                    &mut dbtx.to_ref_with_prefix_module_id(42).0.into_nc(),
                    &output,
                    OutPoint {
                        txid: TransactionId::all_zeros(),
                        out_idx: 1,
                    },
                )
                .await,
            Err(LightningOutputError::InvalidEncryptedPreimage)
        );
    }

    /// Funding an incoming contract that already has an account is rejected at
    /// submission time, so the stale-state top-up from the security report
    /// cannot be reached through the transaction submission API.
    #[test_log::test(tokio::test)]
    async fn submission_rejects_refunding_an_incoming_contract() {
        let task_group = TaskGroup::new();
        let (server_cfg, client_cfg) = build_configs();
        let server = mock_server(&server_cfg[0], &task_group);

        let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
        let mut dbtx = db.begin_transaction().await;

        let op = |i: u64| OutPoint {
            txid: TransactionId::all_zeros(),
            out_idx: i,
        };

        let preimage = PreimageKey(generate_keypair(&mut OsRng).1.serialize());
        let hash = sha256::Hash::hash(&sha256::Hash::hash(&preimage.0).to_byte_array());
        let ct_1 = EncryptedPreimage(client_cfg.threshold_pub_key.encrypt([0xAAu8; 33]));
        let ct_2 = EncryptedPreimage(client_cfg.threshold_pub_key.encrypt(preimage.0));

        server
            .process_output(
                &mut dbtx.to_ref_with_prefix_module_id(42).0.into_nc(),
                &LightningOutput::new_v0_offer(IncomingContractOffer {
                    amount: Amount::from_msats(1),
                    hash,
                    encrypted_preimage: ct_1.clone(),
                    expiry_time: None,
                }),
                op(0),
            )
            .await
            .expect("offer #1 accepted");

        let first_contract = Contract::Incoming(IncomingContract {
            hash,
            encrypted_preimage: ct_1,
            decrypted_preimage: DecryptedPreimage::Pending,
            gateway_key: random_pub_key(),
        });
        let contract_id = first_contract.contract_id();

        server
            .process_output(
                &mut dbtx.to_ref_with_prefix_module_id(42).0.into_nc(),
                &LightningOutput::new_v0_contract(ContractOutput {
                    amount: Amount::from_msats(1),
                    contract: first_contract,
                }),
                op(1),
            )
            .await
            .expect("contract #1 funded");

        // pre-2.1 consensus still accepts a second offer for the same payment
        // hash, but the submission policy rejects it
        let second_offer = LightningOutput::new_v0_offer(IncomingContractOffer {
            amount: Amount::from_msats(100_000),
            hash,
            encrypted_preimage: ct_2.clone(),
            expiry_time: None,
        });

        assert_eq!(
            server
                .verify_output_submission(
                    &mut dbtx.to_ref_with_prefix_module_id(42).0.into_nc(),
                    &second_offer,
                    op(2),
                )
                .await,
            Err(LightningOutputError::OfferForFundedContract(contract_id))
        );

        server
            .process_output(
                &mut dbtx.to_ref_with_prefix_module_id(42).0.into_nc(),
                &second_offer,
                op(2),
            )
            .await
            .expect("offer #2 accepted");

        let second_funding = LightningOutput::new_v0_contract(ContractOutput {
            amount: Amount::from_msats(100_000),
            contract: Contract::Incoming(IncomingContract {
                hash,
                encrypted_preimage: ct_2,
                decrypted_preimage: DecryptedPreimage::Pending,
                gateway_key: random_pub_key(),
            }),
        });

        assert_eq!(
            server
                .verify_output_submission(
                    &mut dbtx.to_ref_with_prefix_module_id(42).0.into_nc(),
                    &second_funding,
                    op(3),
                )
                .await,
            Err(LightningOutputError::ContractAlreadyFunded(contract_id))
        );
    }

    /// A first funding of any contract passes the submission check; a second
    /// funding of the same contract id is rejected for outgoing contracts as
    /// well, since their id does not commit to the amount either.
    #[test_log::test(tokio::test)]
    async fn submission_allows_only_first_fundings() {
        let task_group = TaskGroup::new();
        let (server_cfg, client_cfg) = build_configs();
        let server = mock_server(&server_cfg[0], &task_group);

        let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
        let mut dbtx = db.begin_transaction().await;

        let op = |i: u64| OutPoint {
            txid: TransactionId::all_zeros(),
            out_idx: i,
        };

        let preimage = PreimageKey(generate_keypair(&mut OsRng).1.serialize());
        let hash = sha256::Hash::hash(&sha256::Hash::hash(&preimage.0).to_byte_array());
        let encrypted_preimage =
            EncryptedPreimage(client_cfg.threshold_pub_key.encrypt(preimage.0));

        let first_funding = LightningOutput::new_v0_contract(ContractOutput {
            amount: Amount::from_msats(100_000),
            contract: Contract::Incoming(IncomingContract {
                hash,
                encrypted_preimage: encrypted_preimage.clone(),
                decrypted_preimage: DecryptedPreimage::Pending,
                gateway_key: random_pub_key(),
            }),
        });

        server
            .verify_output_submission(
                &mut dbtx.to_ref_with_prefix_module_id(42).0.into_nc(),
                &first_funding,
                op(1),
            )
            .await
            .expect("first funding of an incoming contract is allowed");

        let outgoing_contract = OutgoingContract {
            hash,
            gateway_key: random_pub_key(),
            timelock: 1_000_000,
            user_key: random_pub_key(),
            cancelled: false,
        };
        let outgoing = LightningOutput::new_v0_contract(ContractOutput {
            amount: Amount::from_msats(1000),
            contract: Contract::Outgoing(outgoing_contract.clone()),
        });

        server
            .verify_output_submission(
                &mut dbtx.to_ref_with_prefix_module_id(42).0.into_nc(),
                &outgoing,
                op(2),
            )
            .await
            .expect("first funding of an outgoing contract is allowed");

        server
            .process_output(
                &mut dbtx.to_ref_with_prefix_module_id(42).0.into_nc(),
                &outgoing,
                op(2),
            )
            .await
            .expect("outgoing contract funded");

        assert_eq!(
            server
                .verify_output_submission(
                    &mut dbtx.to_ref_with_prefix_module_id(42).0.into_nc(),
                    &outgoing,
                    op(3),
                )
                .await,
            Err(LightningOutputError::ContractAlreadyFunded(
                outgoing_contract.contract_id()
            ))
        );
    }

    /// Once the federation has voted in consensus version 2.1, re-funding an
    /// existing contract and creating an offer for an already funded incoming
    /// contract are rejected by consensus itself, not just submission policy.
    ///
    /// The incoming account is seeded in the stale terminal state from the
    /// security report (`DecryptedPreimage::Invalid`, no pending decryption
    /// proposal), which the pre-2.1 consensus rules would happily top up.
    #[test_log::test(tokio::test)]
    async fn consensus_v21_rejects_refunding_and_offers_for_funded_contracts() {
        let task_group = TaskGroup::new();
        let (server_cfg, client_cfg) = build_configs();
        let server = mock_server(&server_cfg[0], &task_group);

        let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
        let mut dbtx = db.begin_transaction().await;
        let mut module_dbtx = dbtx.to_ref_with_prefix_module_id(42).0.into_nc();

        // Three of four peers vote for 2.1, so the max_evil()-th lowest vote
        // (index 1 of the sorted votes, with the fourth peer padded to 2.0)
        // reaches 2.1 and activates the funded-exactly-once rules.
        for peer in 0..3u16 {
            module_dbtx
                .insert_new_entry(
                    &ConsensusVersionVoteKey(PeerId::from(peer)),
                    &CONTRACT_FUNDED_ONCE_MODULE_CONSENSUS_VERSION,
                )
                .await;
        }

        let op = |i: u64| OutPoint {
            txid: TransactionId::all_zeros(),
            out_idx: i,
        };

        let preimage = PreimageKey(generate_keypair(&mut OsRng).1.serialize());
        let hash = sha256::Hash::hash(&sha256::Hash::hash(&preimage.0).to_byte_array());
        let ct_1 = EncryptedPreimage(client_cfg.threshold_pub_key.encrypt([0xAAu8; 33]));
        let ct_2 = EncryptedPreimage(client_cfg.threshold_pub_key.encrypt(preimage.0));

        let stale_contract = IncomingContract {
            hash,
            encrypted_preimage: ct_1,
            decrypted_preimage: DecryptedPreimage::Invalid,
            gateway_key: random_pub_key(),
        };
        let contract_id = stale_contract.contract_id();

        module_dbtx
            .insert_new_entry(
                &ContractKey(contract_id),
                &ContractAccount {
                    amount: Amount::from_msats(1),
                    contract: FundedContract::Incoming(FundedIncomingContract {
                        contract: stale_contract,
                        out_point: op(0),
                    }),
                },
            )
            .await;

        // an offer for the funded contract's payment hash is rejected
        assert_eq!(
            server
                .process_output(
                    &mut module_dbtx.to_ref_nc(),
                    &LightningOutput::new_v0_offer(IncomingContractOffer {
                        amount: Amount::from_msats(100_000),
                        hash,
                        encrypted_preimage: ct_2.clone(),
                        expiry_time: None,
                    }),
                    op(1),
                )
                .await
                .expect_err("offer for a funded contract must be rejected"),
            LightningOutputError::OfferForFundedContract(contract_id)
        );

        // and so is a second funding of the same contract id
        assert_eq!(
            server
                .process_output(
                    &mut module_dbtx.to_ref_nc(),
                    &LightningOutput::new_v0_contract(ContractOutput {
                        amount: Amount::from_msats(100_000),
                        contract: Contract::Incoming(IncomingContract {
                            hash,
                            encrypted_preimage: ct_2,
                            decrypted_preimage: DecryptedPreimage::Pending,
                            gateway_key: random_pub_key(),
                        }),
                    }),
                    op(2),
                )
                .await
                .expect_err("re-funding a funded contract must be rejected"),
            LightningOutputError::ContractAlreadyFunded(contract_id)
        );

        // outgoing contracts: the first funding passes, a second one is
        // rejected as well
        let outgoing_contract = OutgoingContract {
            hash,
            gateway_key: random_pub_key(),
            timelock: 1_000_000,
            user_key: random_pub_key(),
            cancelled: false,
        };
        let outgoing = LightningOutput::new_v0_contract(ContractOutput {
            amount: Amount::from_msats(1000),
            contract: Contract::Outgoing(outgoing_contract.clone()),
        });

        server
            .process_output(&mut module_dbtx.to_ref_nc(), &outgoing, op(3))
            .await
            .expect("first funding of an outgoing contract is accepted");

        assert_eq!(
            server
                .process_output(&mut module_dbtx.to_ref_nc(), &outgoing, op(4))
                .await
                .expect_err("re-funding an outgoing contract must be rejected"),
            LightningOutputError::ContractAlreadyFunded(outgoing_contract.contract_id())
        );
    }

    #[test_log::test(tokio::test)]
    async fn process_input_for_valid_incoming_contracts() {
        let task_group = TaskGroup::new();
        let (server_cfg, client_cfg) = build_configs();
        let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
        let mut dbtx = db.begin_transaction_nc().await;
        let mut module_dbtx = dbtx.to_ref_with_prefix_module_id(42).0;

        let server = mock_server(&server_cfg[0], &task_group);

        let preimage = PreimageKey(generate_keypair(&mut OsRng).1.serialize());
        let funded_incoming_contract = FundedContract::Incoming(FundedIncomingContract {
            contract: IncomingContract {
                hash: sha256::Hash::hash(&sha256::Hash::hash(&preimage.0).to_byte_array()),
                encrypted_preimage: EncryptedPreimage(
                    client_cfg.threshold_pub_key.encrypt(preimage.0),
                ),
                decrypted_preimage: DecryptedPreimage::Some(preimage.clone()),
                gateway_key: random_pub_key(),
            },
            out_point: OutPoint {
                txid: TransactionId::all_zeros(),
                out_idx: 0,
            },
        });

        let contract_id = funded_incoming_contract.contract_id();
        let audit_key = LightningAuditItemKey::from_funded_contract(&funded_incoming_contract);
        let amount = Amount { msats: 1000 };
        let lightning_input = LightningInput::new_v0(contract_id, amount, None);

        module_dbtx.insert_new_entry(&audit_key, &amount).await;
        module_dbtx
            .insert_new_entry(
                &ContractKey(contract_id),
                &ContractAccount {
                    amount,
                    contract: funded_incoming_contract,
                },
            )
            .await;

        let processed_input_meta = server
            .process_input(
                &mut module_dbtx.to_ref_nc(),
                &lightning_input,
                InPoint {
                    txid: TransactionId::all_zeros(),
                    in_idx: 0,
                },
            )
            .await
            .expect("should process valid incoming contract");
        let expected_input_meta = InputMeta {
            amount: TransactionItemAmounts {
                amounts: Amounts::new_bitcoin(amount),
                fees: Amounts::ZERO,
            },
            pub_key: preimage
                .to_public_key()
                .expect("should create Schnorr pubkey from preimage"),
        };

        assert_eq!(processed_input_meta, expected_input_meta);

        let audit_item = module_dbtx.get_value(&audit_key).await;
        assert_eq!(audit_item, None);
    }

    #[test_log::test(tokio::test)]
    async fn process_input_for_valid_outgoing_contracts() {
        let task_group = TaskGroup::new();
        let (server_cfg, _) = build_configs();
        let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
        let mut dbtx = db.begin_transaction_nc().await;
        let mut module_dbtx = dbtx.to_ref_with_prefix_module_id(42).0;

        let server = mock_server(&server_cfg[0], &task_group);

        let preimage = Preimage([42u8; 32]);
        let gateway_key = random_pub_key();
        let outgoing_contract = FundedContract::Outgoing(OutgoingContract {
            hash: preimage.consensus_hash(),
            gateway_key,
            timelock: 1_000_000,
            user_key: random_pub_key(),
            cancelled: false,
        });
        let contract_id = outgoing_contract.contract_id();
        let audit_key = LightningAuditItemKey::from_funded_contract(&outgoing_contract);
        let amount = Amount { msats: 1000 };
        let lightning_input = LightningInput::new_v0(contract_id, amount, Some(preimage.clone()));

        module_dbtx.insert_new_entry(&audit_key, &amount).await;
        module_dbtx
            .insert_new_entry(
                &ContractKey(contract_id),
                &ContractAccount {
                    amount,
                    contract: outgoing_contract,
                },
            )
            .await;

        let processed_input_meta = server
            .process_input(
                &mut module_dbtx.to_ref_nc(),
                &lightning_input,
                InPoint {
                    txid: TransactionId::all_zeros(),
                    in_idx: 0,
                },
            )
            .await
            .expect("should process valid outgoing contract");

        let expected_input_meta = InputMeta {
            amount: TransactionItemAmounts {
                amounts: Amounts::new_bitcoin(amount),
                fees: Amounts::ZERO,
            },
            pub_key: gateway_key,
        };

        assert_eq!(processed_input_meta, expected_input_meta);

        let audit_item = module_dbtx.get_value(&audit_key).await;
        assert_eq!(audit_item, None);
    }

    /// `GET_DECRYPTED_PREIMAGE_STATUS` is unauthenticated and looks the
    /// contract up by `ContractKey`, which holds either contract variant.
    /// Anyone can fund an outgoing contract for a single msat and then point
    /// the endpoint at it, so a non-incoming contract has to be answered with
    /// an error rather than a panic.
    #[test_log::test(tokio::test)]
    async fn decrypted_preimage_status_rejects_an_outgoing_contract() {
        let (server, db, _task_group) = build_server();

        let outgoing_contract = FundedContract::Outgoing(OutgoingContract {
            hash: Preimage([42u8; 32]).consensus_hash(),
            gateway_key: random_pub_key(),
            timelock: 1_000_000,
            user_key: random_pub_key(),
            cancelled: false,
        });
        let contract_id = outgoing_contract.contract_id();

        let mut dbtx = db.begin_transaction().await;
        dbtx.insert_new_entry(
            &ContractKey(contract_id),
            &ContractAccount {
                amount: Amount { msats: 1 },
                contract: outgoing_contract,
            },
        )
        .await;
        dbtx.commit_tx().await;

        let mut context = ApiEndpointContext::new(db, false, None);
        let error = server
            .get_decrypted_preimage_status(&mut context, contract_id)
            .await
            .expect_err("an outgoing contract has no decrypted preimage status");

        assert_eq!(error.code, 400);
    }

    /// Builds a `Lightning` server module backed by an in-memory database.
    fn build_server() -> (Lightning, Database, TaskGroup) {
        let task_group = TaskGroup::new();
        let (server_cfg, _) = build_configs();
        let server = mock_server(&server_cfg[0], &task_group);
        let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
        (server, db, task_group)
    }

    fn announcement(gateway_id: PublicKey, api: &str) -> LightningGatewayAnnouncement {
        LightningGatewayAnnouncement {
            info: LightningGateway {
                federation_index: 1,
                gateway_redeem_key: random_pub_key(),
                node_pub_key: random_pub_key(),
                lightning_alias: "gw".to_string(),
                api: api.parse().expect("valid url"),
                route_hints: vec![],
                fees: fedimint_ln_common::lightning_invoice::RoutingFees {
                    base_msat: 1000,
                    proportional_millionths: 100,
                },
                gateway_id,
                supports_private_payments: true,
            },
            vetted: false,
            ttl: Duration::from_secs(600),
            auth: None,
        }
    }

    /// Signs `announcement` the way an upgraded gateway would.
    fn sign(
        server: &Lightning,
        keypair: &Keypair,
        nonce: u64,
        mut announcement: LightningGatewayAnnouncement,
    ) -> LightningGatewayAnnouncement {
        let msg = create_gateway_registration_message(
            server.cfg.consensus.threshold_pub_keys.public_key(),
            nonce,
            &announcement.info,
        );
        announcement.auth = Some(GatewayRegistrationAuth {
            nonce,
            signature: keypair.sign_schnorr(msg),
        });
        announcement
    }

    async fn stored_api(
        server: &Lightning,
        dbtx: &mut DatabaseTransaction<'_>,
        id: PublicKey,
    ) -> String {
        server
            .list_gateways(dbtx)
            .await
            .into_iter()
            .find(|gw| gw.info.gateway_id == id)
            .expect("gateway is registered")
            .info
            .api
            .to_string()
    }

    /// The core of the fix: once a gateway proves it holds the key behind its
    /// `gateway_id`, nobody else can take that identity over.
    #[test_log::test(tokio::test)]
    async fn signed_registration_cannot_be_overwritten_by_unsigned_one() {
        let (server, db, _tg) = build_server();
        let mut dbtx = db.begin_transaction().await;
        let mut dbtx = dbtx.to_ref_with_prefix_module_id(42).0;

        let victim = Keypair::new(SECP256K1, &mut OsRng);
        let gateway_id = victim.public_key();

        let honest = sign(
            &server,
            &victim,
            1,
            announcement(gateway_id, "https://honest.gw/v1"),
        );
        server
            .register_gateway(&mut dbtx.to_ref_nc(), honest)
            .await
            .expect("honest gateway registers");

        // Same `gateway_id`, attacker-chosen everything else, but no proof.
        let hijack = announcement(gateway_id, "https://attacker.example/v1");
        let err = server
            .register_gateway(&mut dbtx.to_ref_nc(), hijack)
            .await
            .expect_err("unsigned announcement must not replace a signed one");
        assert!(
            err.to_string()
                .contains("cannot be replaced by an unsigned one")
        );

        assert_eq!(
            stored_api(&server, &mut dbtx.to_ref_nc(), gateway_id).await,
            "https://honest.gw/v1"
        );
    }

    /// The upgrade path: a gateway that starts signing takes back its own
    /// `gateway_id`, even if someone squatted it first.
    #[test_log::test(tokio::test)]
    async fn signed_registration_overwrites_unsigned_squat() {
        let (server, db, _tg) = build_server();
        let mut dbtx = db.begin_transaction().await;
        let mut dbtx = dbtx.to_ref_with_prefix_module_id(42).0;

        let victim = Keypair::new(SECP256K1, &mut OsRng);
        let gateway_id = victim.public_key();

        // Attacker gets there first, while the gateway is still un-upgraded.
        server
            .register_gateway(
                &mut dbtx.to_ref_nc(),
                announcement(gateway_id, "https://attacker.example/v1"),
            )
            .await
            .expect("unsigned squat is accepted, as it is today");

        let honest = sign(
            &server,
            &victim,
            1,
            announcement(gateway_id, "https://honest.gw/v1"),
        );
        server
            .register_gateway(&mut dbtx.to_ref_nc(), honest)
            .await
            .expect("signed registration reclaims the identity");

        assert_eq!(
            stored_api(&server, &mut dbtx.to_ref_nc(), gateway_id).await,
            "https://honest.gw/v1"
        );
    }

    /// Backwards compatibility: gateways that have not upgraded keep working
    /// exactly as they do today. They are no better protected, but crucially no
    /// worse off, and an attacker cannot use the new rule to lock them out of
    /// their own `gateway_id`.
    #[test_log::test(tokio::test)]
    async fn unsigned_registrations_still_overwrite_each_other() {
        let (server, db, _tg) = build_server();
        let mut dbtx = db.begin_transaction().await;
        let mut dbtx = dbtx.to_ref_with_prefix_module_id(42).0;

        let gateway_id = random_pub_key();

        // An attacker squats the identity of a legacy gateway before it first
        // registers. The legacy gateway must still be able to register.
        server
            .register_gateway(
                &mut dbtx.to_ref_nc(),
                announcement(gateway_id, "https://attacker.example/v1"),
            )
            .await
            .expect("first unsigned registration accepted");
        server
            .register_gateway(
                &mut dbtx.to_ref_nc(),
                announcement(gateway_id, "https://legacy.gw/v1"),
            )
            .await
            .expect("legacy gateway must not be locked out of its own identity");

        assert_eq!(
            stored_api(&server, &mut dbtx.to_ref_nc(), gateway_id).await,
            "https://legacy.gw/v1"
        );
    }

    #[test_log::test(tokio::test)]
    async fn registration_with_forged_signature_is_rejected() {
        let (server, db, _tg) = build_server();
        let mut dbtx = db.begin_transaction().await;
        let mut dbtx = dbtx.to_ref_with_prefix_module_id(42).0;

        let victim = Keypair::new(SECP256K1, &mut OsRng);
        let attacker = Keypair::new(SECP256K1, &mut OsRng);
        let gateway_id = victim.public_key();

        // Attacker signs the victim's `gateway_id` with their own key.
        let forged = sign(
            &server,
            &attacker,
            1,
            announcement(gateway_id, "https://attacker.example/v1"),
        );
        let err = server
            .register_gateway(&mut dbtx.to_ref_nc(), forged)
            .await
            .expect_err("signature by the wrong key must be rejected");
        assert!(
            err.to_string()
                .contains("Invalid gateway registration signature")
        );

        assert!(server.list_gateways(&mut dbtx.to_ref_nc()).await.is_empty());
    }

    /// A captured proof must not be replayable to roll a gateway back to
    /// settings it has since moved off.
    #[test_log::test(tokio::test)]
    async fn replayed_registration_is_rejected() {
        let (server, db, _tg) = build_server();
        let mut dbtx = db.begin_transaction().await;
        let mut dbtx = dbtx.to_ref_with_prefix_module_id(42).0;

        let victim = Keypair::new(SECP256K1, &mut OsRng);
        let gateway_id = victim.public_key();

        let stale = sign(
            &server,
            &victim,
            1,
            announcement(gateway_id, "https://old.gw/v1"),
        );
        let current = sign(
            &server,
            &victim,
            2,
            announcement(gateway_id, "https://new.gw/v1"),
        );

        server
            .register_gateway(&mut dbtx.to_ref_nc(), stale.clone())
            .await
            .expect("first registration accepted");
        server
            .register_gateway(&mut dbtx.to_ref_nc(), current)
            .await
            .expect("newer registration accepted");

        let err = server
            .register_gateway(&mut dbtx.to_ref_nc(), stale)
            .await
            .expect_err("replay of the older signed announcement must be rejected");
        assert!(err.to_string().contains("nonce must increase"));

        assert_eq!(
            stored_api(&server, &mut dbtx.to_ref_nc(), gateway_id).await,
            "https://new.gw/v1"
        );
    }

    /// A proof is bound to one federation, so it cannot be lifted from a
    /// federation the attacker runs and replayed at the victim's.
    #[test_log::test(tokio::test)]
    async fn registration_proof_is_federation_bound() {
        let (server, db, _tg) = build_server();
        let (other_server, _other_db, _tg2) = build_server();
        let mut dbtx = db.begin_transaction().await;
        let mut dbtx = dbtx.to_ref_with_prefix_module_id(42).0;

        let victim = Keypair::new(SECP256K1, &mut OsRng);
        let gateway_id = victim.public_key();

        assert_ne!(
            server.cfg.consensus.threshold_pub_keys.public_key(),
            other_server.cfg.consensus.threshold_pub_keys.public_key(),
            "test federations must differ for this to prove anything"
        );

        // Validly signed, but for a different federation.
        let foreign = sign(
            &other_server,
            &victim,
            1,
            announcement(gateway_id, "https://gw/v1"),
        );
        server
            .register_gateway(&mut dbtx.to_ref_nc(), foreign)
            .await
            .expect_err("proof from another federation must not verify here");
    }

    /// `vetted` is the federation's judgement, not something a registrant may
    /// assert about itself.
    #[test_log::test(tokio::test)]
    async fn self_asserted_vetted_flag_is_cleared() {
        let (server, db, _tg) = build_server();
        let mut dbtx = db.begin_transaction().await;
        let mut dbtx = dbtx.to_ref_with_prefix_module_id(42).0;

        let gateway_id = random_pub_key();
        let mut ann = announcement(gateway_id, "https://attacker.example/v1");
        ann.vetted = true;

        server
            .register_gateway(&mut dbtx.to_ref_nc(), ann)
            .await
            .expect("registration accepted");

        let stored = dbtx
            .to_ref_nc()
            .get_value(&LightningGatewayKey(gateway_id))
            .await
            .expect("registration exists");
        assert!(
            !stored.vetted,
            "guardian must not store a self-asserted vetted flag"
        );
    }

    /// An unbounded TTL previously let a record outlive any expiry sweep, and a
    /// large enough one overflowed `SystemTime` outright.
    #[test_log::test(tokio::test)]
    async fn oversized_ttl_is_clamped_and_does_not_overflow() {
        let (server, db, _tg) = build_server();
        let mut dbtx = db.begin_transaction().await;
        let mut dbtx = dbtx.to_ref_with_prefix_module_id(42).0;

        let gateway_id = random_pub_key();
        let mut ann = announcement(gateway_id, "https://gw/v1");
        ann.ttl = Duration::from_secs(u64::MAX);

        server
            .register_gateway(&mut dbtx.to_ref_nc(), ann)
            .await
            .expect("must not panic on an absurd TTL");

        let stored = dbtx
            .to_ref_nc()
            .get_value(&LightningGatewayKey(gateway_id))
            .await
            .expect("registration exists");
        assert!(
            stored.valid_until <= fedimint_core::time::now() + MAX_GATEWAY_REGISTRATION_TTL,
            "TTL must be clamped"
        );
    }

    /// A gateway refreshing identical settings must not be locked out by its
    /// own stale nonce, e.g. after an NTP correction stepped its clock
    /// backwards.
    #[test_log::test(tokio::test)]
    async fn unchanged_registration_may_be_refreshed_with_a_stale_nonce() {
        let (server, db, _tg) = build_server();
        let mut dbtx = db.begin_transaction().await;
        let mut dbtx = dbtx.to_ref_with_prefix_module_id(42).0;

        let gateway = Keypair::new(SECP256K1, &mut OsRng);
        let gateway_id = gateway.public_key();
        let ann = announcement(gateway_id, "https://gw/v1");

        server
            .register_gateway(
                &mut dbtx.to_ref_nc(),
                sign(&server, &gateway, 500, ann.clone()),
            )
            .await
            .expect("initial registration accepted");

        // Same settings, lower nonce: a refresh, not a rollback.
        server
            .register_gateway(&mut dbtx.to_ref_nc(), sign(&server, &gateway, 400, ann))
            .await
            .expect("identical settings may be refreshed regardless of nonce");

        // But a *change* still requires the nonce to move forward.
        let err = server
            .register_gateway(
                &mut dbtx.to_ref_nc(),
                sign(
                    &server,
                    &gateway,
                    400,
                    announcement(gateway_id, "https://other.gw/v1"),
                ),
            )
            .await
            .expect_err("changing settings with a stale nonce must be rejected");
        assert!(err.to_string().contains("nonce must increase"));

        assert_eq!(
            stored_api(&server, &mut dbtx.to_ref_nc(), gateway_id).await,
            "https://gw/v1"
        );
    }
}
