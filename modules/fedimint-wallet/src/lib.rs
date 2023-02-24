use std::collections::{BTreeMap, HashMap, HashSet};
use std::convert::{Infallible, TryInto};
use std::ffi::{OsStr, OsString};
use std::hash::Hasher;
use std::ops::Sub;
#[cfg(not(target_family = "wasm"))]
use std::time::Duration;

use anyhow::format_err;
use bitcoin::hashes::hex::ToHex;
use bitcoin::hashes::{sha256, Hash as BitcoinHash, HashEngine, Hmac, HmacEngine};
use bitcoin::secp256k1::{All, Secp256k1, Verification};
use bitcoin::util::psbt::raw::ProprietaryKey;
use bitcoin::util::psbt::{Input, PartiallySignedTransaction};
use bitcoin::util::sighash::SighashCache;
use bitcoin::{
    Address, Amount, BlockHash, EcdsaSig, EcdsaSighashType, Network, PackedLockTime, Script,
    Sequence, Transaction, TxIn, TxOut, Txid,
};
use config::WalletConfigConsensus;
use db::DbKeyPrefix;
use fedimint_bitcoind::DynBitcoindRpc;
use fedimint_core::bitcoin_rpc::{
    select_bitcoin_backend_from_envs, BitcoinRpcBackendType, FM_BITCOIND_RPC_ENV,
    FM_ELECTRUM_RPC_ENV, FM_ESPLORA_RPC_ENV,
};
use fedimint_core::config::{
    ConfigGenParams, DkgPeerMsg, DkgResult, ModuleConfigResponse, ModuleGenParams,
    ServerModuleConfig, TypedServerModuleConfig, TypedServerModuleConsensusConfig,
};
use fedimint_core::core::{Decoder, ModuleInstanceId, ModuleKind};
use fedimint_core::db::{Database, DatabaseTransaction, DatabaseVersion};
use fedimint_core::encoding::{Decodable, Encodable, UnzipConsensus};
use fedimint_core::module::__reexports::serde_json;
use fedimint_core::module::audit::Audit;
use fedimint_core::module::interconnect::ModuleInterconect;
use fedimint_core::module::{
    api_endpoint, ApiEndpoint, ApiVersion, ConsensusProposal, CoreConsensusVersion, InputMeta,
    IntoModuleError, ModuleCommon, ModuleConsensusVersion, ModuleError, ModuleGen,
    TransactionItemAmount,
};
use fedimint_core::net::peers::MuxPeerConnections;
use fedimint_core::server::DynServerModule;
#[cfg(not(target_family = "wasm"))]
use fedimint_core::task::sleep;
use fedimint_core::task::{TaskGroup, TaskHandle};
use fedimint_core::{
    apply, async_trait_maybe_send, plugin_types_trait_impl, push_db_key_items, push_db_pair_items,
    Feerate, NumPeers, OutPoint, PeerId, ServerModule,
};
use futures::{stream, StreamExt};
use impl_tools::autoimpl;
use miniscript::psbt::PsbtExt;
use miniscript::{Descriptor, TranslatePk};
use rand::rngs::OsRng;
use rand::Rng;
use secp256k1::{Message, Scalar};
use serde::{Deserialize, Serialize};
use strum::IntoEnumIterator;
use thiserror::Error;
use tracing::{debug, error, info, instrument, trace, warn};

use crate::config::{WalletClientConfig, WalletConfig};
use crate::db::{
    BlockHashKey, BlockHashKeyPrefix, PegOutBitcoinTransaction, PegOutBitcoinTransactionPrefix,
    PegOutTxSignatureCI, PegOutTxSignatureCIPrefix, PendingTransactionKey,
    PendingTransactionPrefixKey, RoundConsensusKey, UTXOKey, UTXOPrefixKey, UnsignedTransactionKey,
    UnsignedTransactionPrefixKey,
};
use crate::keys::CompressedPublicKey;
use crate::tweakable::Tweakable;
use crate::txoproof::{PegInProof, PegInProofError};

pub mod config;
pub mod db;
pub mod keys;
pub mod tweakable;
pub mod txoproof;

const KIND: ModuleKind = ModuleKind::from_static_str("wallet");

pub const CONFIRMATION_TARGET: u16 = 10;

pub type PartialSig = Vec<u8>;

pub type PegInDescriptor = Descriptor<CompressedPublicKey>;

#[derive(
    Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, UnzipConsensus, Encodable, Decodable,
)]
pub enum WalletConsensusItem {
    RoundConsensus(RoundConsensusItem),
    PegOutSignature(PegOutSignatureItem),
}

impl std::fmt::Display for WalletConsensusItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WalletConsensusItem::RoundConsensus(rc) => {
                write!(f, "Wallet Block Height {}", rc.block_height)
            }
            WalletConsensusItem::PegOutSignature(sig) => {
                write!(f, "Wallet PegOut signature for Bitcoin TxId {}", sig.txid)
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct RoundConsensusItem {
    pub block_height: u32, /* FIXME: use block hash instead, but needs more complicated
                            * verification logic */
    pub fee_rate: Feerate,
    pub randomness: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize, Encodable, Decodable)]
pub struct PegOutSignatureItem {
    pub txid: Txid,
    pub signature: Vec<secp256k1::ecdsa::Signature>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct RoundConsensus {
    pub block_height: u32,
    pub fee_rate: Feerate,
    pub randomness_beacon: [u8; 32],
}

#[derive(Debug)]
pub struct Wallet {
    cfg: WalletConfig,
    secp: Secp256k1<All>,
    btc_rpc: DynBitcoindRpc,
}

#[derive(Clone, Debug, Serialize, Deserialize, Encodable, Decodable)]
pub struct SpendableUTXO {
    pub tweak: [u8; 32],
    #[serde(with = "bitcoin::util::amount::serde::as_sat")]
    pub amount: bitcoin::Amount,
}

/// A peg-out tx that is ready to be broadcast with a tweak for the change UTXO
#[derive(Clone, Debug, Encodable, Decodable)]
pub struct PendingTransaction {
    pub tx: Transaction,
    pub tweak: [u8; 32],
    pub change: bitcoin::Amount,
}

impl Serialize for PendingTransaction {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut bytes = Vec::new();
        self.consensus_encode(&mut bytes).unwrap();

        if serializer.is_human_readable() {
            serializer.serialize_str(&bytes.to_hex())
        } else {
            serializer.serialize_bytes(&bytes)
        }
    }
}

/// A PSBT that is awaiting enough signatures from the federation to becoming a
/// `PendingTransaction`
#[derive(Clone, Debug, Eq, PartialEq, Encodable, Decodable)]
pub struct UnsignedTransaction {
    pub psbt: PartiallySignedTransaction,
    pub signatures: Vec<(PeerId, PegOutSignatureItem)>,
    pub change: bitcoin::Amount,
    pub fees: PegOutFees,
}

impl Serialize for UnsignedTransaction {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut bytes = Vec::new();
        self.consensus_encode(&mut bytes).unwrap();

        if serializer.is_human_readable() {
            serializer.serialize_str(&bytes.to_hex())
        } else {
            serializer.serialize_bytes(&bytes)
        }
    }
}

struct StatelessWallet<'a> {
    descriptor: &'a Descriptor<CompressedPublicKey>,
    secret_key: &'a secp256k1::SecretKey,
    secp: &'a secp256k1::Secp256k1<secp256k1::All>,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct PegOutFees {
    pub fee_rate: Feerate,
    pub total_weight: u64,
}

impl PegOutFees {
    pub fn amount(&self) -> Amount {
        self.fee_rate.calculate_fee(self.total_weight)
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct PegOut {
    pub recipient: bitcoin::Address,
    #[serde(with = "bitcoin::util::amount::serde::as_sat")]
    pub amount: bitcoin::Amount,
    pub fees: PegOutFees,
}

/// Contains the Bitcoin transaction id of the transaction created by the
/// withdraw request
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct WalletOutputOutcome(pub bitcoin::Txid);

impl std::fmt::Display for WalletOutputOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Wallet PegOut Bitcoin TxId {}", self.0)
    }
}

#[derive(Debug)]
pub struct WalletGen;

#[apply(async_trait_maybe_send!)]
impl ModuleGen for WalletGen {
    const KIND: ModuleKind = KIND;
    const DATABASE_VERSION: DatabaseVersion = DatabaseVersion(0);

    fn decoder(&self) -> Decoder {
        <Wallet as ServerModule>::decoder()
    }

    fn versions(&self, _core: CoreConsensusVersion) -> &[ModuleConsensusVersion] {
        &[ModuleConsensusVersion(0)]
    }

    async fn init(
        &self,
        cfg: ServerModuleConfig,
        db: Database,
        env: &BTreeMap<OsString, OsString>,
        task_group: &mut TaskGroup,
    ) -> anyhow::Result<DynServerModule> {
        Ok(Wallet::new(cfg.to_typed()?, db, env, task_group)
            .await?
            .into())
    }

    fn trusted_dealer_gen(
        &self,
        peers: &[PeerId],
        params: &ConfigGenParams,
    ) -> BTreeMap<PeerId, ServerModuleConfig> {
        let params = params
            .get::<WalletGenParams>()
            .expect("Invalid wallet params");

        let secp = secp256k1::Secp256k1::new();

        let btc_pegin_keys = peers
            .iter()
            .map(|&id| (id, secp.generate_keypair(&mut OsRng)))
            .collect::<Vec<_>>();

        let wallet_cfg: BTreeMap<PeerId, WalletConfig> = btc_pegin_keys
            .iter()
            .map(|(id, (sk, _))| {
                let cfg = WalletConfig::new(
                    btc_pegin_keys
                        .iter()
                        .map(|(peer_id, (_, pk))| (*peer_id, CompressedPublicKey { key: *pk }))
                        .collect(),
                    *sk,
                    peers.threshold(),
                    params.network,
                    params.finality_delay,
                );
                (*id, cfg)
            })
            .collect();

        wallet_cfg
            .into_iter()
            .map(|(k, v)| (k, v.to_erased()))
            .collect()
    }

    async fn distributed_gen(
        &self,
        connections: &MuxPeerConnections<ModuleInstanceId, DkgPeerMsg>,
        our_id: &PeerId,
        module_instance_id: ModuleInstanceId,
        peers: &[PeerId],
        params: &ConfigGenParams,
    ) -> DkgResult<ServerModuleConfig> {
        let params = params
            .get::<WalletGenParams>()
            .expect("Invalid wallet params");

        let secp = secp256k1::Secp256k1::new();
        let (sk, pk) = secp.generate_keypair(&mut OsRng);
        let our_key = CompressedPublicKey { key: pk };
        let mut peer_peg_in_keys: BTreeMap<PeerId, CompressedPublicKey> = BTreeMap::new();

        connections
            .send(
                peers,
                module_instance_id,
                DkgPeerMsg::PublicKey(our_key.key),
            )
            .await?;

        peer_peg_in_keys.insert(*our_id, our_key);
        while peer_peg_in_keys.len() < peers.len() {
            match connections.receive(module_instance_id).await? {
                (peer, DkgPeerMsg::PublicKey(key)) => {
                    peer_peg_in_keys.insert(peer, CompressedPublicKey { key });
                }
                (peer, msg) => {
                    return Err(
                        format_err!("Invalid message received from: {peer}: {msg:?}").into(),
                    );
                }
            }
        }

        let wallet_cfg = WalletConfig::new(
            peer_peg_in_keys,
            sk,
            peers.threshold(),
            params.network,
            params.finality_delay,
        );

        Ok(wallet_cfg.to_erased())
    }

    fn to_config_response(
        &self,
        config: serde_json::Value,
    ) -> anyhow::Result<ModuleConfigResponse> {
        let config = serde_json::from_value::<WalletConfigConsensus>(config)?;

        Ok(ModuleConfigResponse {
            client: config.to_client_config(),
            consensus_hash: config.consensus_hash()?,
        })
    }

    fn validate_config(&self, identity: &PeerId, config: ServerModuleConfig) -> anyhow::Result<()> {
        config.to_typed::<WalletConfig>()?.validate_config(identity)
    }

    fn hash_client_module(&self, config: serde_json::Value) -> anyhow::Result<sha256::Hash> {
        serde_json::from_value::<WalletClientConfig>(config)?.consensus_hash()
    }

    async fn dump_database(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        prefix_names: Vec<String>,
    ) -> Box<dyn Iterator<Item = (String, Box<dyn erased_serde::Serialize + Send>)> + '_> {
        let mut wallet: BTreeMap<String, Box<dyn erased_serde::Serialize + Send>> = BTreeMap::new();
        let filtered_prefixes = DbKeyPrefix::iter().filter(|f| {
            prefix_names.is_empty() || prefix_names.contains(&f.to_string().to_lowercase())
        });
        for table in filtered_prefixes {
            match table {
                DbKeyPrefix::BlockHash => {
                    push_db_key_items!(dbtx, BlockHashKeyPrefix, BlockHashKey, wallet, "Blocks");
                }
                DbKeyPrefix::PegOutBitcoinOutPoint => {
                    push_db_pair_items!(
                        dbtx,
                        PegOutBitcoinTransactionPrefix,
                        PegOutBitcoinTransaction,
                        WalletOutputOutcome,
                        wallet,
                        "Peg Out Bitcoin Transaction"
                    );
                }
                DbKeyPrefix::PegOutTxSigCi => {
                    push_db_pair_items!(
                        dbtx,
                        PegOutTxSignatureCIPrefix,
                        PegOutTxSignatureCI,
                        Vec<secp256k1::ecdsa::Signature>,
                        wallet,
                        "Peg Out Transaction Signatures"
                    );
                }
                DbKeyPrefix::PendingTransaction => {
                    push_db_pair_items!(
                        dbtx,
                        PendingTransactionPrefixKey,
                        PendingTransactionKey,
                        PendingTransaction,
                        wallet,
                        "Pending Transactions"
                    );
                }
                DbKeyPrefix::RoundConsensus => {
                    let round_consensus = dbtx.get_value(&RoundConsensusKey).await.unwrap();
                    if let Some(round_consensus) = round_consensus {
                        wallet.insert("Round Consensus".to_string(), Box::new(round_consensus));
                    }
                }
                DbKeyPrefix::UnsignedTransaction => {
                    push_db_pair_items!(
                        dbtx,
                        UnsignedTransactionPrefixKey,
                        UnsignedTransactionKey,
                        UnsignedTransaction,
                        wallet,
                        "Unsigned Transactions"
                    );
                }
                DbKeyPrefix::Utxo => {
                    push_db_pair_items!(
                        dbtx,
                        UTXOPrefixKey,
                        UTXOKey,
                        SpendableUTXO,
                        wallet,
                        "UTXOs"
                    );
                }
            }
        }

        Box::new(wallet.into_iter())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletGenParams {
    pub network: bitcoin::network::constants::Network,
    pub finality_delay: u32,
}

impl ModuleGenParams for WalletGenParams {
    const MODULE_NAME: &'static str = "wallet";
}

#[autoimpl(Deref, DerefMut using self.0)]
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct WalletInput(pub Box<PegInProof>);

impl std::fmt::Display for WalletInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Wallet PegIn with Bitcoin TxId {}",
            self.0.outpoint().txid
        )
    }
}

#[autoimpl(Deref, DerefMut using self.0)]
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct WalletOutput(pub PegOut);

impl std::fmt::Display for WalletOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Wallet PegOut {} to {}", self.0.amount, self.0.recipient)
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct WalletVerificationCache;

pub struct WalletModuleTypes;

impl ModuleCommon for WalletModuleTypes {
    type Input = WalletInput;
    type Output = WalletOutput;
    type OutputOutcome = WalletOutputOutcome;
    type ConsensusItem = WalletConsensusItem;
}

#[apply(async_trait_maybe_send!)]
impl ServerModule for Wallet {
    type Common = WalletModuleTypes;
    type Gen = WalletGen;
    type VerificationCache = WalletVerificationCache;

    fn versions(&self) -> (ModuleConsensusVersion, &[ApiVersion]) {
        (
            ModuleConsensusVersion(0),
            &[ApiVersion { major: 0, minor: 0 }],
        )
    }

    async fn await_consensus_proposal(&self, dbtx: &mut DatabaseTransaction<'_>) {
        while !self.consensus_proposal(dbtx).await.forces_new_epoch() {
            // FIXME: remove after modularization finishes
            #[cfg(not(target_family = "wasm"))]
            sleep(Duration::from_millis(1000)).await;
        }
    }

    async fn consensus_proposal<'a>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'_>,
    ) -> ConsensusProposal<WalletConsensusItem> {
        // TODO: implement retry logic in case bitcoind is temporarily unreachable
        let our_target_height = self.target_height().await;

        // In case the wallet just got created the height is not committed to the DB yet
        // but will be set to 0 first, so we can assume that here.
        let last_consensus_height = self.consensus_height(dbtx).await.unwrap_or(0);

        let proposed_height = if our_target_height >= last_consensus_height {
            our_target_height
        } else {
            warn!(
                "The block height shrunk, new proposal would be {}, but we are sticking to the last consensus height {}.",
                our_target_height,
                last_consensus_height
            );
            last_consensus_height
        };

        let fee_rate = self
            .btc_rpc
            .get_fee_rate(CONFIRMATION_TARGET)
            .await
            .expect("bitcoind rpc failed")
            .unwrap_or(self.cfg.consensus.default_fee);

        let round_ci = WalletConsensusItem::RoundConsensus(RoundConsensusItem {
            block_height: proposed_height,
            fee_rate,
            randomness: OsRng.gen(),
        });

        let items = dbtx
            .find_by_prefix(&PegOutTxSignatureCIPrefix)
            .await
            .map(|res| {
                let (key, val) = res.expect("FB error");
                WalletConsensusItem::PegOutSignature(PegOutSignatureItem {
                    txid: key.0,
                    signature: val,
                })
            })
            .chain(stream::once(async { round_ci }))
            .collect::<Vec<WalletConsensusItem>>()
            .await;

        // We force new epochs only if height changed, or we have peg-outs (more than
        // just round_ci item)
        if last_consensus_height < proposed_height || 1 < items.len() {
            ConsensusProposal::Trigger(items)
        } else {
            ConsensusProposal::Contribute(items)
        }
    }

    async fn begin_consensus_epoch<'a, 'b>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'b>,
        consensus_items: Vec<(PeerId, WalletConsensusItem)>,
    ) {
        trace!(?consensus_items, "Received consensus proposals");

        // Separate round consensus items from signatures for peg-out tx. While
        // signatures can be processed separately, all round consensus items
        // need to be available at once.
        let UnzipWalletConsensusItem {
            peg_out_signature: peg_out_signatures,
            round_consensus,
        } = consensus_items.into_iter().unzip_wallet_consensus_item();

        // Save signatures to the database
        self.save_peg_out_signatures(dbtx, peg_out_signatures).await;

        // FIXME: also warn on less than 1/3, that should never happen
        // Make sure we have enough contributions to continue
        if round_consensus.is_empty() {
            panic!("No proposals were submitted this round");
        }

        let fee_proposals = round_consensus.iter().map(|(_, rc)| rc.fee_rate).collect();
        let fee_rate = self.process_fee_proposals(fee_proposals).await;

        let height_proposals = round_consensus
            .iter()
            .map(|(_, rc)| rc.block_height)
            .collect();
        let block_height = self
            .process_block_height_proposals(dbtx, height_proposals)
            .await;

        let randomness_contributions = round_consensus
            .iter()
            .map(|(_, rc)| rc.randomness)
            .collect();
        let randomness_beacon = self.process_randomness_contributions(randomness_contributions);

        let round_consensus = RoundConsensus {
            block_height,
            fee_rate,
            randomness_beacon,
        };

        dbtx.insert_entry(&RoundConsensusKey, &round_consensus)
            .await
            .expect("DB Error");
    }

    fn build_verification_cache<'a>(
        &'a self,
        _inputs: impl Iterator<Item = &'a WalletInput>,
    ) -> Self::VerificationCache {
        WalletVerificationCache
    }

    async fn validate_input<'a, 'b>(
        &self,
        _interconnect: &dyn ModuleInterconect,
        dbtx: &mut DatabaseTransaction<'b>,
        _verification_cache: &Self::VerificationCache,
        input: &'a WalletInput,
    ) -> Result<InputMeta, ModuleError> {
        if !self.block_is_known(dbtx, input.proof_block()).await {
            return Err(WalletError::UnknownPegInProofBlock(input.proof_block()))
                .into_module_error_other();
        }

        input
            .verify(&self.secp, &self.cfg.consensus.peg_in_descriptor)
            .into_module_error_other()?;

        if dbtx
            .get_value(&UTXOKey(input.outpoint()))
            .await
            .expect("DB error")
            .is_some()
        {
            return Err(WalletError::PegInAlreadyClaimed).into_module_error_other();
        }

        Ok(InputMeta {
            amount: TransactionItemAmount {
                amount: fedimint_core::Amount::from_sats(input.tx_output().value),
                fee: self.cfg.consensus.fee_consensus.peg_in_abs,
            },
            puk_keys: vec![*input.tweak_contract_key()],
        })
    }

    async fn apply_input<'a, 'b, 'c>(
        &'a self,
        interconnect: &'a dyn ModuleInterconect,
        dbtx: &mut DatabaseTransaction<'c>,
        input: &'b WalletInput,
        cache: &Self::VerificationCache,
    ) -> Result<InputMeta, ModuleError> {
        let meta = self
            .validate_input(interconnect, dbtx, cache, input)
            .await?;
        debug!(outpoint = %input.outpoint(), amount = %meta.amount.amount, "Claiming peg-in");

        dbtx.insert_new_entry(
            &UTXOKey(input.outpoint()),
            &SpendableUTXO {
                tweak: input.tweak_contract_key().serialize(),
                amount: bitcoin::Amount::from_sat(input.tx_output().value),
            },
        )
        .await
        .expect("DB Error");

        Ok(meta)
    }

    async fn validate_output(
        &self,
        dbtx: &mut DatabaseTransaction,
        output: &WalletOutput,
    ) -> Result<TransactionItemAmount, ModuleError> {
        if !output
            .recipient
            .is_valid_for_network(self.cfg.consensus.network)
        {
            return Err(WalletError::WrongNetwork(
                self.cfg.consensus.network,
                output.recipient.network,
            ))
            .into_module_error_other();
        }
        let consensus_fee_rate = self.current_round_consensus(dbtx).await.unwrap().fee_rate;
        if output.fees.fee_rate < consensus_fee_rate {
            return Err(WalletError::PegOutFeeRate(
                output.fees.fee_rate,
                consensus_fee_rate,
            ))
            .into_module_error_other();
        }
        if let Err(err) = self.create_peg_out_tx(dbtx, output).await {
            return Err(err).into_module_error_other();
        }
        Ok(TransactionItemAmount {
            amount: (output.amount + output.fees.amount()).into(),
            fee: self.cfg.consensus.fee_consensus.peg_out_abs,
        })
    }

    async fn apply_output<'a, 'b>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'b>,
        output: &'a WalletOutput,
        out_point: fedimint_core::OutPoint,
    ) -> Result<TransactionItemAmount, ModuleError> {
        let amount = self.validate_output(dbtx, output).await?;
        debug!(
            amount = %output.amount, recipient = %output.recipient,
            "Queuing peg-out",
        );

        let mut tx = self
            .create_peg_out_tx(dbtx, output)
            .await
            .expect("Should have been validated");
        self.offline_wallet().sign_psbt(&mut tx.psbt);
        let txid = tx.psbt.unsigned_tx.txid();
        info!(
            %txid,
            "Signing peg out",
        );

        let sigs = tx
            .psbt
            .inputs
            .iter_mut()
            .map(|input| {
                assert_eq!(
                    input.partial_sigs.len(),
                    1,
                    "There was already more than one (our) or no signatures in input"
                );

                // TODO: don't put sig into PSBT in the first place
                // We actually take out our own signature so everyone finalizes the tx in the
                // same epoch.
                let sig = std::mem::take(&mut input.partial_sigs)
                    .into_values()
                    .next()
                    .expect("asserted previously");

                // We drop SIGHASH_ALL, because we always use that and it is only present in the
                // PSBT for compatibility with other tools.
                secp256k1::ecdsa::Signature::from_der(&sig.to_vec()[..sig.to_vec().len() - 1])
                    .expect("we serialized it ourselves that way")
            })
            .collect::<Vec<_>>();

        // Delete used UTXOs
        for input in tx.psbt.unsigned_tx.input.iter() {
            dbtx.remove_entry(&UTXOKey(input.previous_output))
                .await
                .expect("DB Error");
        }

        dbtx.insert_new_entry(&UnsignedTransactionKey(txid), &tx)
            .await
            .expect("DB Error");
        dbtx.insert_new_entry(&PegOutTxSignatureCI(txid), &sigs)
            .await
            .expect("DB Error");
        dbtx.insert_new_entry(
            &PegOutBitcoinTransaction(out_point),
            &WalletOutputOutcome(txid),
        )
        .await
        .expect("DB Error");
        Ok(amount)
    }

    async fn end_consensus_epoch<'a, 'b>(
        &'a self,
        consensus_peers: &HashSet<PeerId>,
        dbtx: &mut DatabaseTransaction<'b>,
    ) -> Vec<PeerId> {
        // Sign and finalize any unsigned transactions that have signatures
        let unsigned_txs = dbtx
            .find_by_prefix(&UnsignedTransactionPrefixKey)
            .await
            .map(|res| {
                let (key, val) = res.expect("DB error");
                (key, val)
            })
            .collect::<Vec<(UnsignedTransactionKey, UnsignedTransaction)>>()
            .await;

        let unsigned_txs = unsigned_txs
            .into_iter()
            .filter(|(_, unsigned)| !unsigned.signatures.is_empty());

        let mut drop_peers = Vec::<PeerId>::new();
        for (key, unsigned) in unsigned_txs {
            let UnsignedTransaction {
                mut psbt,
                signatures,
                change,
                ..
            } = unsigned;

            let signers: HashSet<PeerId> = signatures
                .iter()
                .filter_map(
                    |(peer, sig)| match self.sign_peg_out_psbt(&mut psbt, peer, sig) {
                        Ok(_) => Some(*peer),
                        Err(error) => {
                            warn!("Error with {} partial sig {:?}", peer, error);
                            None
                        }
                    },
                )
                .collect();

            for peer in consensus_peers.sub(&signers) {
                error!("Dropping {:?} for not contributing sigs to PSBT", peer);
                drop_peers.push(peer);
            }

            match self.finalize_peg_out_psbt(&mut psbt, change) {
                Ok(pending_tx) => {
                    // We were able to finalize the transaction, so we will delete the PSBT and
                    // instead keep the extracted tx for periodic transmission
                    // and to accept the change into our wallet eventually once
                    // it confirms.
                    dbtx.insert_new_entry(&PendingTransactionKey(key.0), &pending_tx)
                        .await
                        .expect("DB Error");
                    dbtx.remove_entry(&PegOutTxSignatureCI(key.0))
                        .await
                        .expect("DB Error");
                    dbtx.remove_entry(&key).await.expect("DB Error");
                }
                Err(e) => {
                    warn!("Unable to finalize PSBT due to {:?}", e)
                }
            }
        }
        drop_peers
    }

    async fn output_status(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        out_point: OutPoint,
    ) -> Option<WalletOutputOutcome> {
        dbtx.get_value(&PegOutBitcoinTransaction(out_point))
            .await
            .expect("DB error")
    }

    async fn audit(&self, dbtx: &mut DatabaseTransaction<'_>, audit: &mut Audit) {
        audit
            .add_items(dbtx, &UTXOPrefixKey, |_, v| v.amount.to_sat() as i64 * 1000)
            .await;
        audit
            .add_items(dbtx, &UnsignedTransactionPrefixKey, |_, v| {
                v.change.to_sat() as i64 * 1000
            })
            .await;
        audit
            .add_items(dbtx, &PendingTransactionPrefixKey, |_, v| {
                v.change.to_sat() as i64 * 1000
            })
            .await;
    }

    fn api_endpoints(&self) -> Vec<ApiEndpoint<Self>> {
        vec![
            api_endpoint! {
                "/block_height",
                async |module: &Wallet, dbtx, _params: ()| -> u32 {
                    Ok(module.consensus_height(dbtx).await.unwrap_or(0))
                }
            },
            api_endpoint! {
                "/peg_out_fees",
                async |module: &Wallet, dbtx, params: (Address, u64)| -> Option<PegOutFees> {
                    let (address, sats) = params;
                    let consensus = module.current_round_consensus(dbtx).await.unwrap();
                    let tx = module.offline_wallet().create_tx(
                        bitcoin::Amount::from_sat(sats),
                        address.script_pubkey(),
                        module.available_utxos(dbtx).await,
                        consensus.fee_rate,
                        &consensus.randomness_beacon
                    );

                    Ok(tx.map(|tx| tx.fees).ok())
                }
            },
        ]
    }
}

impl Wallet {
    #[cfg(feature = "native")]
    pub async fn new(
        cfg: WalletConfig,
        db: Database,
        env: &BTreeMap<OsString, OsString>,
        task_group: &mut TaskGroup,
    ) -> anyhow::Result<Wallet> {
        let bitcoin_backend = select_bitcoin_backend_from_envs(
            env.get(OsStr::new(FM_BITCOIND_RPC_ENV))
                .map(OsString::as_os_str),
            env.get(OsStr::new(FM_ELECTRUM_RPC_ENV))
                .map(OsString::as_os_str),
            env.get(OsStr::new(FM_ESPLORA_RPC_ENV))
                .map(OsString::as_os_str),
        )?;

        let btc_rpc = fedimint_bitcoind::bitcoincore_rpc::make_bitcoin_rpc_backend(
            &bitcoin_backend,
            task_group.make_handle(),
        )?;

        Ok(Self::new_with_bitcoind(cfg, db, btc_rpc, task_group).await?)
    }

    #[cfg(not(feature = "native"))]
    pub async fn new(
        cfg: WalletConfig,
        db: Database,
        env: &BTreeMap<OsString, OsString>,
        task_group: &mut TaskGroup,
    ) -> anyhow::Result<Wallet> {
        panic!("Native cargo feature not enabled, can't initialize modules")
    }

    pub async fn new_with_bitcoind(
        cfg: WalletConfig,
        db: Database,
        bitcoind: DynBitcoindRpc,
        task_group: &mut TaskGroup,
    ) -> Result<Wallet, WalletError> {
        let broadcaster_bitcoind_rpc = bitcoind.clone();
        let broadcaster_db = db.clone();
        task_group
            .spawn("broadcast pending", |handle| async move {
                run_broadcast_pending_tx(broadcaster_db, broadcaster_bitcoind_rpc, &handle).await;
            })
            .await;

        let bitcoind_rpc = bitcoind;

        let bitcoind_net = bitcoind_rpc
            .get_network()
            .await
            .map_err(WalletError::RpcError)?;
        if bitcoind_net != cfg.consensus.network {
            return Err(WalletError::WrongNetwork(
                cfg.consensus.network,
                bitcoind_net,
            ));
        }

        match bitcoind_rpc.get_block_height().await {
            Ok(height) => info!(height, "Connected to bitcoind"),
            Err(err) => warn!("Bitcoin node is not ready or configured properly. Modules relying on it may not function correctly: {:?}", err),
        }

        match bitcoind_rpc.get_fee_rate(1).await {
            Ok(feerate) => {
                match feerate {
                    Some(fr) => info!(feerate = fr.sats_per_kvb, "Bitcoind feerate available"),
                    None => info!(feerate = 0, "Bitcoind feerate available"),
                }
            },
            Err(err) => warn!("Bitcoin fee estimation failed. Please configure your nodes to enable fee estimation: {:?}", err),
        }

        let wallet = Wallet {
            cfg,
            secp: Default::default(),
            btc_rpc: bitcoind_rpc,
        };

        Ok(wallet)
    }

    pub fn process_randomness_contributions(&self, randomness: Vec<[u8; 32]>) -> [u8; 32] {
        fn xor(mut lhs: [u8; 32], rhs: [u8; 32]) -> [u8; 32] {
            lhs.iter_mut().zip(rhs).for_each(|(lhs, rhs)| *lhs ^= rhs);
            lhs
        }

        randomness.into_iter().fold([0; 32], xor)
    }

    async fn save_peg_out_signatures<'a>(
        &self,
        dbtx: &mut DatabaseTransaction<'a>,
        signatures: Vec<(PeerId, PegOutSignatureItem)>,
    ) {
        let mut cache: BTreeMap<Txid, UnsignedTransaction> = dbtx
            .find_by_prefix(&UnsignedTransactionPrefixKey)
            .await
            .map(|res| {
                let (key, val) = res.expect("DB error");
                (key.0, val)
            })
            .collect()
            .await;

        for (peer, sig) in signatures.into_iter() {
            match cache.get_mut(&sig.txid) {
                Some(unsigned) => unsigned.signatures.push((peer, sig)),
                None => warn!(
                    "{} sent peg-out signature for unknown PSBT {}",
                    peer, sig.txid
                ),
            }
        }

        for (txid, unsigned) in cache.into_iter() {
            dbtx.insert_entry(&UnsignedTransactionKey(txid), &unsigned)
                .await
                .expect("DB Error");
        }
    }

    /// Try to attach signatures to a pending peg-out tx.
    fn sign_peg_out_psbt(
        &self,
        psbt: &mut PartiallySignedTransaction,
        peer: &PeerId,
        signature: &PegOutSignatureItem,
    ) -> Result<(), ProcessPegOutSigError> {
        let peer_key = self
            .cfg
            .consensus
            .peer_peg_in_keys
            .get(peer)
            .expect("always called with valid peer id");

        if psbt.inputs.len() != signature.signature.len() {
            return Err(ProcessPegOutSigError::WrongSignatureCount(
                psbt.inputs.len(),
                signature.signature.len(),
            ));
        }

        let mut tx_hasher = SighashCache::new(&psbt.unsigned_tx);
        for (idx, (input, signature)) in psbt
            .inputs
            .iter_mut()
            .zip(signature.signature.iter())
            .enumerate()
        {
            let tx_hash = tx_hasher
                .segwit_signature_hash(
                    idx,
                    input
                        .witness_script
                        .as_ref()
                        .expect("Missing witness script"),
                    input.witness_utxo.as_ref().expect("Missing UTXO").value,
                    EcdsaSighashType::All,
                )
                .map_err(|_| ProcessPegOutSigError::SighashError)?;

            let tweak = input
                .proprietary
                .get(&proprietary_tweak_key())
                .expect("we saved it with a tweak");

            let tweaked_peer_key = peer_key.tweak(tweak, &self.secp);
            self.secp
                .verify_ecdsa(
                    &Message::from_slice(&tx_hash[..]).unwrap(),
                    signature,
                    &tweaked_peer_key.key,
                )
                .map_err(|_| ProcessPegOutSigError::InvalidSignature)?;

            if input
                .partial_sigs
                .insert(tweaked_peer_key.into(), EcdsaSig::sighash_all(*signature))
                .is_some()
            {
                // Should never happen since peers only sign a PSBT once
                return Err(ProcessPegOutSigError::DuplicateSignature);
            }
        }
        Ok(())
    }

    fn finalize_peg_out_psbt(
        &self,
        psbt: &mut PartiallySignedTransaction,
        change: Amount,
    ) -> Result<PendingTransaction, ProcessPegOutSigError> {
        // We need to save the change output's tweak key to be able to access the funds
        // later on. The tweak is extracted here because the psbt is moved next
        // and not available anymore when the tweak is actually needed in the
        // end to be put into the batch on success.
        let change_tweak: [u8; 32] = psbt
            .outputs
            .iter()
            .flat_map(|output| output.proprietary.get(&proprietary_tweak_key()).cloned())
            .next()
            .ok_or(ProcessPegOutSigError::MissingOrMalformedChangeTweak)?
            .try_into()
            .map_err(|_| ProcessPegOutSigError::MissingOrMalformedChangeTweak)?;

        if let Err(error) = psbt.finalize_mut(&self.secp) {
            return Err(ProcessPegOutSigError::ErrorFinalizingPsbt(error));
        }

        let tx = psbt.clone().extract_tx();

        Ok(PendingTransaction {
            tx,
            tweak: change_tweak,
            change,
        })
    }

    /// # Panics
    /// * If proposals is empty
    async fn process_fee_proposals(&self, mut proposals: Vec<Feerate>) -> Feerate {
        assert!(!proposals.is_empty());

        proposals.sort();

        *proposals
            .get(proposals.len() / 2)
            .expect("We checked before that proposals aren't empty")
    }

    /// # Panics
    /// * If proposals is empty
    async fn process_block_height_proposals<'a>(
        &self,
        dbtx: &mut DatabaseTransaction<'a>,
        mut proposals: Vec<u32>,
    ) -> u32 {
        assert!(!proposals.is_empty());

        proposals.sort_unstable();
        let median_proposal = proposals[proposals.len() / 2];

        let consensus_height = self.consensus_height(dbtx).await.unwrap_or(0);

        if median_proposal >= consensus_height {
            debug!("Setting consensus block height to {}", median_proposal);
            self.sync_up_to_consensus_height(dbtx, median_proposal)
                .await;
        } else {
            panic!(
                "Median proposed consensus block height shrunk from {consensus_height} to {median_proposal}, the federation is broken"
            );
        }

        median_proposal
    }

    pub async fn current_round_consensus(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
    ) -> Option<RoundConsensus> {
        dbtx.get_value(&RoundConsensusKey).await.expect("DB error")
    }

    pub async fn target_height(&self) -> u32 {
        let our_network_height = self
            .btc_rpc
            .get_block_height()
            .await
            .expect("bitcoind rpc failed") as u32;
        our_network_height.saturating_sub(self.cfg.consensus.finality_delay)
    }

    pub async fn consensus_height(&self, dbtx: &mut DatabaseTransaction<'_>) -> Option<u32> {
        self.current_round_consensus(dbtx)
            .await
            .map(|rc| rc.block_height)
    }

    async fn sync_up_to_consensus_height<'a>(
        &self,
        dbtx: &mut DatabaseTransaction<'a>,
        new_height: u32,
    ) {
        let old_height = self
            .consensus_height(dbtx)
            .await
            .unwrap_or_else(|| new_height.saturating_sub(10));
        if new_height < old_height {
            info!(
                new_height,
                old_height, "Nothing to sync, new height is lower than old height, doing nothing."
            );
            return;
        }

        if new_height == old_height {
            debug!(height = old_height, "Height didn't change");
            return;
        }

        info!(
            new_height,
            block_to_go = new_height - old_height,
            "New consensus height, syncing up",
        );

        for height in (old_height + 1)..=(new_height) {
            if height % 100 == 0 {
                debug!("Caught up to block {}", height);
            }

            // TODO: use batching for mainnet syncing
            trace!(block = height, "Fetching block hash");
            let block_hash = self
                .btc_rpc
                .get_block_hash(height as u64)
                .await
                .expect("bitcoind rpc backend failed"); // TODO: use u64 for height everywhere

            let pending_transactions = dbtx
                .find_by_prefix(&PendingTransactionPrefixKey)
                .await
                .map(|res| {
                    let (key, transaction) = res.expect("DB error");
                    (key.0, transaction)
                })
                .collect::<HashMap<_, _>>()
                .await;

            match self.btc_rpc.backend_type() {
                BitcoinRpcBackendType::Bitcoind | BitcoinRpcBackendType::Esplora => {
                    if !pending_transactions.is_empty() {
                        let block = self
                            .btc_rpc
                            .get_block(&block_hash)
                            .await
                            .expect("bitcoin rpc failed");
                        for transaction in block.txdata {
                            if let Some(pending_tx) = pending_transactions.get(&transaction.txid())
                            {
                                self.recognize_change_utxo(dbtx, pending_tx).await;
                            }
                        }
                    }
                }
                BitcoinRpcBackendType::Electrum => {
                    for transaction in &pending_transactions {
                        if self
                            .btc_rpc
                            .was_transaction_confirmed_in(&transaction.1.tx, height as u64)
                            .await
                            .expect("bitcoin electrum rpc backend failed")
                        {
                            self.recognize_change_utxo(dbtx, transaction.1).await;
                        }
                    }
                }
            }

            dbtx.insert_new_entry(
                &BlockHashKey(BlockHash::from_inner(block_hash.into_inner())),
                &(),
            )
            .await
            .expect("DB Error");
        }
    }

    /// Add a change UTXO to our spendable UTXO database after it was included
    /// in a block that we got consensus on.
    async fn recognize_change_utxo<'a>(
        &self,
        dbtx: &mut DatabaseTransaction<'a>,
        pending_tx: &PendingTransaction,
    ) {
        let script_pk = self
            .cfg
            .consensus
            .peg_in_descriptor
            .tweak(&pending_tx.tweak, &self.secp)
            .script_pubkey();
        for (idx, output) in pending_tx.tx.output.iter().enumerate() {
            if output.script_pubkey == script_pk {
                dbtx.insert_entry(
                    &UTXOKey(bitcoin::OutPoint {
                        txid: pending_tx.tx.txid(),
                        vout: idx as u32,
                    }),
                    &SpendableUTXO {
                        tweak: pending_tx.tweak,
                        amount: bitcoin::Amount::from_sat(output.value),
                    },
                )
                .await
                .expect("DB Error");

                dbtx.remove_entry(&PendingTransactionKey(pending_tx.tx.txid()))
                    .await
                    .expect("DB error");
            }
        }
    }

    async fn block_is_known(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        block_hash: BlockHash,
    ) -> bool {
        dbtx.get_value(&BlockHashKey(block_hash))
            .await
            .expect("DB error")
            .is_some()
    }

    async fn create_peg_out_tx(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        peg_out: &PegOut,
    ) -> Result<UnsignedTransaction, WalletError> {
        let change_tweak = self
            .current_round_consensus(dbtx)
            .await
            .unwrap()
            .randomness_beacon;
        self.offline_wallet().create_tx(
            peg_out.amount,
            peg_out.recipient.script_pubkey(),
            self.available_utxos(dbtx).await,
            peg_out.fees.fee_rate,
            &change_tweak,
        )
    }

    async fn available_utxos(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
    ) -> Vec<(UTXOKey, SpendableUTXO)> {
        dbtx.find_by_prefix(&UTXOPrefixKey)
            .await
            .map(|res| {
                let (key, val) = res.expect("FB error");
                (key, val)
            })
            .collect::<Vec<(UTXOKey, SpendableUTXO)>>()
            .await
    }

    pub async fn get_wallet_value(&self, dbtx: &mut DatabaseTransaction<'_>) -> bitcoin::Amount {
        let sat_sum = self
            .available_utxos(dbtx)
            .await
            .into_iter()
            .map(|(_, utxo)| utxo.amount.to_sat())
            .sum();
        bitcoin::Amount::from_sat(sat_sum)
    }

    fn offline_wallet(&self) -> StatelessWallet {
        StatelessWallet {
            descriptor: &self.cfg.consensus.peg_in_descriptor,
            secret_key: &self.cfg.private.peg_in_key,
            secp: &self.secp,
        }
    }
}

impl<'a> StatelessWallet<'a> {
    /// Attempts to create a tx ready to be signed from available UTXOs.
    /// Returns `None` if there are not enough `SpendableUTXO`
    fn create_tx(
        &self,
        peg_out_amount: bitcoin::Amount,
        destination: Script,
        mut utxos: Vec<(UTXOKey, SpendableUTXO)>,
        fee_rate: Feerate,
        change_tweak: &[u8],
    ) -> Result<UnsignedTransaction, WalletError> {
        // If the peg out amount is under the dust limit fail immediately
        if peg_out_amount < destination.dust_value() {
            return Err(WalletError::PegOutUnderDustLimit);
        }

        // When building a transaction we need to take care of two things:
        //  * We need enough input amount to fund all outputs
        //  * We need to keep an eye on the tx weight so we can factor the fees into out
        //    calculation
        // We then go on to calculate the base size of the transaction `total_weight`
        // and the maximum weight per added input which we will add every time
        // we select an input.
        let change_script = self.derive_script(change_tweak);
        let out_weight = (destination.len() * 4 + 1 + 32
            // Add change script weight, it's very likely to be needed if not we just overpay in fees
            + 1 // script len varint, 1 byte for all addresses we accept
            + change_script.len() * 4 // script len
            + 32) as u64; // value
        let mut total_weight = 16 + // version
            12 + // up to 2**16-1 inputs
            12 + // up to 2**16-1 outputs
            out_weight + // weight of all outputs
            16; // lock time
        let max_input_weight = (self
            .descriptor
            .max_satisfaction_weight()
            .expect("is satisfyable") +
            128 + // TxOutHash
            16 + // TxOutIndex
            16) as u64; // sequence

        // Finally we initialize our accumulator for selected input amounts
        let mut total_selected_value = bitcoin::Amount::from_sat(0);
        let mut selected_utxos: Vec<(UTXOKey, SpendableUTXO)> = vec![];
        let mut fees = fee_rate.calculate_fee(total_weight);

        // When selecting UTXOs we select from largest to smallest amounts
        utxos.sort_by_key(|(_, utxo)| utxo.amount);
        while total_selected_value < peg_out_amount + change_script.dust_value() + fees {
            match utxos.pop() {
                Some((utxo_key, utxo)) => {
                    total_selected_value += utxo.amount;
                    total_weight += max_input_weight;
                    fees = fee_rate.calculate_fee(total_weight);
                    selected_utxos.push((utxo_key, utxo));
                }
                _ => return Err(WalletError::NotEnoughSpendableUTXO), // Not enough UTXOs
            }
        }

        // We always pay ourselves change back to ensure that we don't lose anything due
        // to dust
        let change = total_selected_value - fees - peg_out_amount;
        let output: Vec<TxOut> = vec![
            TxOut {
                value: peg_out_amount.to_sat(),
                script_pubkey: destination,
            },
            TxOut {
                value: change.to_sat(),
                script_pubkey: change_script,
            },
        ];
        let mut change_out = bitcoin::util::psbt::Output::default();
        change_out
            .proprietary
            .insert(proprietary_tweak_key(), change_tweak.to_vec());

        info!(
            inputs = selected_utxos.len(),
            input_sats = total_selected_value.to_sat(),
            peg_out_sats = peg_out_amount.to_sat(),
            fees_sats = fees.to_sat(),
            fee_rate = fee_rate.sats_per_kvb,
            change_sats = change.to_sat(),
            "Creating peg-out tx",
        );

        let transaction = Transaction {
            version: 2,
            lock_time: PackedLockTime::ZERO,
            input: selected_utxos
                .iter()
                .map(|(utxo_key, _utxo)| TxIn {
                    previous_output: utxo_key.0,
                    script_sig: Default::default(),
                    sequence: Sequence::MAX,
                    witness: bitcoin::Witness::new(),
                })
                .collect(),
            output,
        };
        info!(txid = %transaction.txid(), "Creating peg-out tx");

        // FIXME: use custom data structure that guarantees more invariants and only
        // convert to PSBT for finalization
        let psbt = PartiallySignedTransaction {
            unsigned_tx: transaction,
            version: 0,
            xpub: Default::default(),
            proprietary: Default::default(),
            unknown: Default::default(),
            inputs: selected_utxos
                .into_iter()
                .map(|(_utxo_key, utxo)| {
                    let script_pubkey = self
                        .descriptor
                        .tweak(&utxo.tweak, self.secp)
                        .script_pubkey();
                    Input {
                        non_witness_utxo: None,
                        witness_utxo: Some(TxOut {
                            value: utxo.amount.to_sat(),
                            script_pubkey,
                        }),
                        partial_sigs: Default::default(),
                        sighash_type: None,
                        redeem_script: None,
                        witness_script: Some(
                            self.descriptor
                                .tweak(&utxo.tweak, self.secp)
                                .script_code()
                                .expect("Failed to tweak descriptor"),
                        ),
                        bip32_derivation: Default::default(),
                        final_script_sig: None,
                        final_script_witness: None,
                        ripemd160_preimages: Default::default(),
                        sha256_preimages: Default::default(),
                        hash160_preimages: Default::default(),
                        hash256_preimages: Default::default(),
                        proprietary: vec![(proprietary_tweak_key(), utxo.tweak.to_vec())]
                            .into_iter()
                            .collect(),
                        tap_key_sig: Default::default(),
                        tap_script_sigs: Default::default(),
                        tap_scripts: Default::default(),
                        tap_key_origins: Default::default(),
                        tap_internal_key: Default::default(),
                        tap_merkle_root: Default::default(),
                        unknown: Default::default(),
                    }
                })
                .collect(),
            outputs: vec![Default::default(), change_out],
        };

        Ok(UnsignedTransaction {
            psbt,
            signatures: vec![],
            change,
            fees: PegOutFees {
                fee_rate,
                total_weight,
            },
        })
    }

    fn sign_psbt(&self, psbt: &mut PartiallySignedTransaction) {
        let mut tx_hasher = SighashCache::new(&psbt.unsigned_tx);

        for (idx, (psbt_input, _tx_input)) in psbt
            .inputs
            .iter_mut()
            .zip(psbt.unsigned_tx.input.iter())
            .enumerate()
        {
            let tweaked_secret = {
                let tweak = psbt_input
                    .proprietary
                    .get(&proprietary_tweak_key())
                    .expect("Malformed PSBT: expected tweak");

                self.secret_key.tweak(tweak, self.secp)
            };

            let tx_hash = tx_hasher
                .segwit_signature_hash(
                    idx,
                    psbt_input
                        .witness_script
                        .as_ref()
                        .expect("Missing witness script"),
                    psbt_input
                        .witness_utxo
                        .as_ref()
                        .expect("Missing UTXO")
                        .value,
                    EcdsaSighashType::All,
                )
                .expect("Failed to create segwit sighash");

            let signature = self
                .secp
                .sign_ecdsa(&Message::from_slice(&tx_hash[..]).unwrap(), &tweaked_secret);

            psbt_input.partial_sigs.insert(
                bitcoin::PublicKey {
                    compressed: true,
                    inner: secp256k1::PublicKey::from_secret_key(self.secp, &tweaked_secret),
                },
                EcdsaSig::sighash_all(signature),
            );
        }
    }

    fn derive_script(&self, tweak: &[u8]) -> Script {
        struct CompressedPublicKeyTranslator<'t, 's, Ctx: Verification> {
            tweak: &'t [u8],
            secp: &'s Secp256k1<Ctx>,
        }

        impl<'t, 's, Ctx: Verification>
            miniscript::PkTranslator<CompressedPublicKey, CompressedPublicKey, Infallible>
            for CompressedPublicKeyTranslator<'t, 's, Ctx>
        {
            fn pk(&mut self, pk: &CompressedPublicKey) -> Result<CompressedPublicKey, Infallible> {
                let hashed_tweak = {
                    let mut hasher = HmacEngine::<sha256::Hash>::new(&pk.key.serialize()[..]);
                    hasher.input(self.tweak);
                    Hmac::from_engine(hasher).into_inner()
                };

                Ok(CompressedPublicKey {
                    key: pk
                        .key
                        .add_exp_tweak(
                            self.secp,
                            &Scalar::from_be_bytes(hashed_tweak).expect("can't fail"),
                        )
                        .expect("tweaking failed"),
                })
            }

            fn pkh(
                &mut self,
                pkh: &CompressedPublicKey,
            ) -> Result<CompressedPublicKey, Infallible> {
                self.pk(pkh)
            }
        }

        let descriptor = self
            .descriptor
            .translate_pk(&mut CompressedPublicKeyTranslator {
                tweak,
                secp: self.secp,
            })
            .expect("can't fail");

        descriptor.script_pubkey()
    }
}

fn proprietary_tweak_key() -> ProprietaryKey {
    ProprietaryKey {
        prefix: b"fedimint".to_vec(),
        subtype: 0x00,
        key: vec![],
    }
}

#[instrument(level = "debug", skip_all)]
pub async fn run_broadcast_pending_tx(db: Database, rpc: DynBitcoindRpc, tg_handle: &TaskHandle) {
    while !tg_handle.is_shutting_down() {
        broadcast_pending_tx(db.begin_transaction().await, &rpc).await;
        // FIXME: remove after modularization finishes
        #[cfg(not(target_family = "wasm"))]
        fedimint_core::task::sleep(Duration::from_secs(10)).await;
    }
}

pub async fn broadcast_pending_tx(mut dbtx: DatabaseTransaction<'_>, rpc: &DynBitcoindRpc) {
    let pending_tx = dbtx
        .find_by_prefix(&PendingTransactionPrefixKey)
        .await
        .map(|res| {
            let (key, val) = res.expect("DB Error");
            (key, val)
        })
        .collect::<Vec<(_, _)>>()
        .await;

    for (_, PendingTransaction { tx, .. }) in pending_tx {
        debug!(
            tx = %tx.txid(),
            weight = tx.weight(),
            "Broadcasting peg-out",
        );
        trace!(transaction = ?tx);
        let _ = rpc.submit_transaction(tx).await;
    }
}

impl std::hash::Hash for PegOutSignatureItem {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.txid.hash(state);
        for sig in self.signature.iter() {
            sig.serialize_der().hash(state);
        }
    }
}

impl PartialEq for PegOutSignatureItem {
    fn eq(&self, other: &PegOutSignatureItem) -> bool {
        self.txid == other.txid && self.signature == other.signature
    }
}

impl Eq for PegOutSignatureItem {}

plugin_types_trait_impl!(
    WalletInput,
    WalletOutput,
    WalletOutputOutcome,
    WalletConsensusItem,
    WalletVerificationCache
);

#[derive(Debug, Error)]
pub enum WalletError {
    #[error("Connected bitcoind is on wrong network, expected {0}, got {1}")]
    WrongNetwork(Network, Network),
    #[error("Error querying bitcoind: {0}")]
    RpcError(#[from] anyhow::Error),
    #[error("Unknown bitcoin network: {0}")]
    UnknownNetwork(String),
    #[error("Unknown block hash in peg-in proof: {0}")]
    UnknownPegInProofBlock(BlockHash),
    #[error("Invalid peg-in proof: {0}")]
    PegInProofError(#[from] PegInProofError),
    #[error("The peg-in was already claimed")]
    PegInAlreadyClaimed,
    #[error("Peg-out fee rate {0:?} is set below consensus {1:?}")]
    PegOutFeeRate(Feerate, Feerate),
    #[error("Not enough SpendableUTXO")]
    NotEnoughSpendableUTXO,
    #[error("Peg out amount was under the dust limit")]
    PegOutUnderDustLimit,
}

#[derive(Debug, Error)]
pub enum ProcessPegOutSigError {
    #[error("No unsigned transaction with id {0} exists")]
    UnknownTransaction(Txid),
    #[error("Expected {0} signatures, got {1}")]
    WrongSignatureCount(usize, usize),
    #[error("Bad Sighash")]
    SighashError,
    #[error("Malformed signature: {0}")]
    MalformedSignature(secp256k1::Error),
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Duplicate signature")]
    DuplicateSignature,
    #[error("Missing change tweak")]
    MissingOrMalformedChangeTweak,
    #[error("Error finalizing PSBT {0:?}")]
    ErrorFinalizingPsbt(Vec<miniscript::psbt::Error>),
}

// FIXME: make FakeFed not require Eq
/// **WARNING**: this is only intended to be used for testing
impl PartialEq for WalletError {
    fn eq(&self, other: &Self) -> bool {
        format!("{self:?}") == format!("{other:?}")
    }
}

/// **WARNING**: this is only intended to be used for testing
impl Eq for WalletError {}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bitcoin::{Address, Amount, OutPoint};
    use fedimint_core::Feerate;
    use miniscript::descriptor::Wsh;

    use crate::{
        CompressedPublicKey, OsRng, PegInDescriptor, SpendableUTXO, StatelessWallet, UTXOKey,
        WalletError,
    };

    #[test]
    fn create_tx_should_validate_amounts() {
        let secp = secp256k1::Secp256k1::new();

        let descriptor = PegInDescriptor::Wsh(
            Wsh::new_sortedmulti(
                3,
                (0..4)
                    .map(|_| secp.generate_keypair(&mut OsRng))
                    .map(|(_, key)| CompressedPublicKey { key })
                    .collect(),
            )
            .unwrap(),
        );

        let (secret_key, _) = secp.generate_keypair(&mut OsRng);

        let wallet = StatelessWallet {
            descriptor: &descriptor,
            secret_key: &secret_key,
            secp: &secp,
        };

        let spendable = SpendableUTXO {
            tweak: [0; 32],
            amount: Amount::from_sat(2000),
        };

        let destination = Address::from_str("msFGPqHVk8rbARMd69FfGYxwcboZLemdBi")
            .unwrap()
            .script_pubkey();

        // not enough SpendableUTXO
        let tx = wallet.create_tx(
            Amount::from_sat(2000),
            destination.clone(),
            vec![(UTXOKey(OutPoint::null()), spendable.clone())],
            Feerate { sats_per_kvb: 0 },
            &[],
        );
        assert_eq!(tx, Err(WalletError::NotEnoughSpendableUTXO));

        // peg out amount is under dust limit
        let tx = wallet.create_tx(
            Amount::from_sat(1),
            destination.clone(),
            vec![(UTXOKey(OutPoint::null()), spendable.clone())],
            Feerate { sats_per_kvb: 0 },
            &[],
        );
        assert_eq!(tx, Err(WalletError::PegOutUnderDustLimit));

        // successful tx creation
        let tx = wallet.create_tx(
            Amount::from_sat(1000),
            destination,
            vec![(UTXOKey(OutPoint::null()), spendable)],
            Feerate { sats_per_kvb: 0 },
            &[],
        );
        assert!(tx.is_ok());
    }
}
