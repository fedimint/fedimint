use std::hash::Hasher;
use std::sync::Arc;

use crate::bitcoind::BitcoindRpc;
use crate::config::WalletConfig;
use crate::db::{
    BlockHashKey, PegOutTxSignatureCI, PegOutTxSignatureCIPrefix, PendingPegOutKey,
    PendingPegOutPrefixKey, PendingTransaction, PendingTransactionKey, PendingTransactionPrefixKey,
    RoundConsensusKey, UTXOKey, UTXOPrefixKey, UnsignedTransactionKey,
};
use crate::keys::CompressedPublicKey;
use crate::tweakable::Tweakable;
use crate::txoproof::{PegInProof, PegInProofError};
use async_trait::async_trait;
use bitcoin::hashes::{sha256, Hash as BitcoinHash, HashEngine, Hmac, HmacEngine};
use bitcoin::secp256k1::{All, Secp256k1};
use bitcoin::util::bip143::SigHashCache;
use bitcoin::util::psbt::raw::ProprietaryKey;
use bitcoin::util::psbt::{Global, Input, PartiallySignedTransaction};
use bitcoin::{
    Address, AddressType, BlockHash, Network, Script, SigHashType, Transaction, TxIn, TxOut, Txid,
};
use bitcoincore_rpc::Auth;
use itertools::Itertools;
use minimint_api::db::batch::{BatchItem, BatchTx};
use minimint_api::db::{Database, RawDatabase};
use minimint_api::encoding::{Decodable, Encodable};
use minimint_api::{FederationModule, InputMeta, OutPoint, PeerId};
use minimint_derive::UnzipConsensus;
use miniscript::{Descriptor, DescriptorTrait, TranslatePk2};
use rand::{CryptoRng, Rng, RngCore};
use secp256k1::{Message, Signature};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::time::Duration;
use tracing::{debug, error, info, trace, warn};

pub mod bitcoind;
pub mod config;
pub mod db;
pub mod keys;
pub mod tweakable;
pub mod txoproof;

pub const CONFIRMATION_TARGET: u16 = 24;

/// The urgency of doing a peg-out is defined as the sum over all pending peg-outs of the amount of
/// BTC blocks that have been mined since the peg-out was created. E.g. 10 transactions, each
/// waiting for 10 blocks, would cross a minimum urgency threshold of 100.  
pub const MIN_PEG_OUT_URGENCY: u32 = 100;

pub type PartialSig = Vec<u8>;

pub type PegInDescriptor = Descriptor<CompressedPublicKey>;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, UnzipConsensus)]
pub enum WalletConsensusItem {
    RoundConsensus(RoundConsensusItem),
    PegOutSignature(PegOutSignatureItem),
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RoundConsensusItem {
    block_height: u32, // FIXME: use block hash instead, but needs more complicated verification logic
    fee_rate: Feerate,
    randomness: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PegOutSignatureItem {
    txid: Txid,
    signature: Vec<secp256k1::Signature>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct RoundConsensus {
    block_height: u32,
    fee_rate: Feerate,
    randomness_beacon: [u8; 32],
}

pub struct Wallet {
    cfg: WalletConfig,
    secp: Secp256k1<All>,
    btc_rpc: Box<dyn BitcoindRpc>,
    db: Arc<dyn RawDatabase>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Encodable, Decodable)]
pub struct SpendableUTXO {
    pub tweak: secp256k1::schnorrsig::PublicKey,
    #[serde(with = "bitcoin::util::amount::serde::as_sat")]
    pub amount: bitcoin::Amount,
    // FIXME: why do we save the script pub key? We can derive it from the tweak and the descriptor
    pub script_pubkey: Script,
}

// TODO: move pegout logic out of wallet into minimint consensus
#[derive(Clone, Debug, Serialize, Deserialize, Encodable, Decodable)]
pub struct PendingPegOut {
    destination: Script,
    #[serde(with = "bitcoin::util::amount::serde::as_sat")]
    amount: bitcoin::Amount,
    pending_since_block: u32,
}

struct StatelessWallet<'a> {
    descriptor: &'a Descriptor<CompressedPublicKey>,
    secret_key: &'a secp256k1::SecretKey,
    secp: &'a secp256k1::Secp256k1<secp256k1::All>,
}

#[derive(
    Copy,
    Clone,
    Debug,
    PartialEq,
    Ord,
    PartialOrd,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    Encodable,
    Decodable,
)]
pub struct Feerate {
    pub sats_per_kvb: u64,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct PegOut {
    pub recipient: bitcoin::Address,
    #[serde(with = "bitcoin::util::amount::serde::as_sat")]
    pub amount: bitcoin::Amount,
}

#[async_trait(?Send)]
impl FederationModule for Wallet {
    type Error = WalletError;
    type TxInput = Box<PegInProof>;
    type TxOutput = PegOut;
    // TODO: implement outcome
    type TxOutputOutcome = ();
    type ConsensusItem = WalletConsensusItem;

    async fn consensus_proposal<'a>(
        &'a self,
        mut rng: impl RngCore + CryptoRng + 'a,
    ) -> Vec<Self::ConsensusItem> {
        // TODO: implement retry logic in case bitcoind is temporarily unreachable
        let our_network_height = self.btc_rpc.get_block_height().await as u32;
        let our_target_height = our_network_height.saturating_sub(self.cfg.finalty_delay);

        // In case the wallet just got created the height is not committed to the DB yet but will
        // be set to 0 first, so we can assume that here.
        let last_consensus_height = self.consensus_height().unwrap_or(0);

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
            .unwrap_or(self.cfg.default_fee);

        let round_ci = WalletConsensusItem::RoundConsensus(RoundConsensusItem {
            block_height: proposed_height,
            fee_rate,
            randomness: rng.gen(),
        });

        self.db
            .find_by_prefix::<_, PegOutTxSignatureCI, Vec<Signature>>(&PegOutTxSignatureCIPrefix)
            .map(|res| {
                let (key, val) = res.expect("FB error");
                WalletConsensusItem::PegOutSignature(PegOutSignatureItem {
                    txid: key.0,
                    signature: val,
                })
            })
            .chain(std::iter::once(round_ci))
            .collect()
    }

    async fn begin_consensus_epoch<'a>(
        &'a self,
        mut batch: BatchTx<'a>,
        consensus_items: Vec<(PeerId, Self::ConsensusItem)>,
        _rng: impl RngCore + CryptoRng + 'a,
    ) {
        trace!("Received consensus proposals {:?}", &consensus_items);

        // Separate round consensus items from signatures for peg-out tx. While signatures can be
        // processed separately, all round consensus items need to be available at once.
        let UnzipWalletConsensusItem {
            peg_out_signature: peg_out_signatures,
            round_consensus,
        } = consensus_items.into_iter().unzip_wallet_consensus_item();

        // Apply signatures to peg-out tx
        for (peer, sig) in peg_out_signatures {
            if let Err(e) = self.process_peg_out_signature(batch.subtransaction(), peer, &sig) {
                warn!("Error processing peer {}'s peg-out signature: {}", peer, e)
            };
        }

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
            .process_block_height_proposals(batch.subtransaction(), height_proposals)
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

        batch.append_insert(RoundConsensusKey, round_consensus);
        batch.commit();
    }

    fn validate_input<'a>(&self, input: &'a Self::TxInput) -> Result<InputMeta<'a>, Self::Error> {
        if !self.block_is_known(input.proof_block()) {
            return Err(WalletError::UnknownPegInProofBlock(input.proof_block()));
        }

        input.verify(&self.secp, &self.cfg.peg_in_descriptor)?;

        if self
            .db
            .get_value::<_, SpendableUTXO>(&UTXOKey(input.outpoint()))
            .expect("DB error")
            .is_some()
        {
            return Err(WalletError::PegInAlreadyClaimed);
        }

        Ok(InputMeta {
            amount: minimint_api::Amount::from_sat(input.tx_output().value),
            puk_keys: Box::new(std::iter::once(*input.tweak_contract_key())),
        })
    }

    fn apply_input<'a, 'b>(
        &'a self,
        mut batch: BatchTx<'a>,
        input: &'b Self::TxInput,
    ) -> Result<InputMeta<'b>, Self::Error> {
        let meta = self.validate_input(input)?;
        debug!("Claiming peg-in {} worth {}", input.outpoint(), meta.amount);

        batch.append_insert_new(
            UTXOKey(input.outpoint()),
            SpendableUTXO {
                tweak: *input.tweak_contract_key(),
                amount: bitcoin::Amount::from_sat(input.tx_output().value),
                script_pubkey: input.tx_output().script_pubkey.clone(),
            },
        );

        batch.commit();
        Ok(meta)
    }

    fn validate_output(
        &self,
        output: &Self::TxOutput,
    ) -> Result<minimint_api::Amount, Self::Error> {
        if !is_address_valid_for_network(&output.recipient, self.cfg.network) {
            return Err(WalletError::WrongNetwork(
                self.cfg.network,
                output.recipient.network,
            ));
        }
        Ok(output.amount.into())
    }

    fn apply_output<'a>(
        &'a self,
        mut batch: BatchTx<'a>,
        output: &'a Self::TxOutput,
        out_point: minimint_api::OutPoint,
    ) -> Result<minimint_api::Amount, Self::Error> {
        let amount = self.validate_output(output)?;
        debug!(
            "Queuing peg-out of {} BTC to {}",
            output.amount, output.recipient
        );
        batch.append_insert_new(
            PendingPegOutKey(out_point),
            PendingPegOut {
                destination: output.recipient.script_pubkey(),
                amount: output.amount,
                pending_since_block: self.consensus_height().unwrap_or(0),
            },
        );
        batch.commit();
        Ok(amount)
    }

    async fn end_consensus_epoch<'a>(
        &'a self,
        mut batch: BatchTx<'a>,
        _rng: impl RngCore + CryptoRng + 'a,
    ) {
        let round_consensus = match self.current_round_consensus() {
            Some(consensus) => consensus,
            None => return,
        };

        // Check if we should create a peg-out transaction
        let (peg_out_ids, pending_peg_outs): (Vec<minimint_api::OutPoint>, Vec<PendingPegOut>) =
            self.pending_peg_outs().into_iter().unzip();
        let urgency = pending_peg_outs
            .iter()
            .map(|peg_out| round_consensus.block_height - peg_out.pending_since_block)
            .sum::<u32>();

        trace!(
            "Pending peg outs: {}, urgency: {}, urgency threshold: {}",
            pending_peg_outs.len(),
            urgency,
            MIN_PEG_OUT_URGENCY
        );

        // We only want to peg out if we have a real randomness beacon after the first consensus round
        let peg_out_ready = self.current_round_consensus().is_some(); // TODO: maybe destructure instead?
        if urgency > MIN_PEG_OUT_URGENCY && peg_out_ready {
            let mut psbt = self
                .create_peg_out_tx(pending_peg_outs, round_consensus)
                .await;
            let txid = psbt.global.unsigned_tx.txid();

            info!(
                "Signing peg out tx {} containing {} peg outs",
                txid,
                peg_out_ids.len()
            );
            let sigs = psbt
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
                    secp256k1::Signature::from_der(&sig[..sig.len() - 1])
                        .expect("we serialized it ourselves that way")
                })
                .collect::<Vec<_>>();

            batch.append_from_iter(
                peg_out_ids
                    .into_iter()
                    .map(|peg_out| BatchItem::delete(PendingPegOutKey(peg_out))),
            );
            batch.append_insert_new(UnsignedTransactionKey(psbt.global.unsigned_tx.txid()), psbt);
            batch.append_insert_new(PegOutTxSignatureCI(txid), sigs);
        }
        batch.commit();
    }

    fn output_status(&self, _out_point: OutPoint) -> Option<Self::TxOutputOutcome> {
        // TODO: return BTC tx id once included in peg-out tx
        Some(())
    }
}

impl Wallet {
    pub async fn new(cfg: WalletConfig, db: Arc<dyn RawDatabase>) -> Result<Wallet, WalletError> {
        let gen_cfg = cfg.clone();
        let bitcoind_rpc_gen = move || -> Box<dyn BitcoindRpc> {
            Box::new(
                bitcoincore_rpc::Client::new(
                    &gen_cfg.btc_rpc_address,
                    Auth::UserPass(gen_cfg.btc_rpc_user.clone(), gen_cfg.btc_rpc_pass.clone()),
                )
                .expect("Could not connect to bitcoind"),
            )
        };

        Self::new_with_bitcoind(cfg, db, bitcoind_rpc_gen).await
    }

    // TODO: work around bitcoind_gen being a closure, maybe make clonable?
    pub async fn new_with_bitcoind(
        cfg: WalletConfig,
        db: Arc<dyn RawDatabase>,
        bitcoind_gen: impl Fn() -> Box<dyn BitcoindRpc>,
    ) -> Result<Wallet, WalletError> {
        let broadcaster_bitcoind_rpc = bitcoind_gen();
        let broadcaster_db = db.clone();
        tokio::spawn(async move {
            broadcast_pending_tx(broadcaster_db, broadcaster_bitcoind_rpc).await;
        });

        let bitcoind_rpc = bitcoind_gen();

        let bitcoind_net = bitcoind_rpc.get_network().await;
        if bitcoind_net != cfg.network {
            return Err(WalletError::WrongNetwork(cfg.network, bitcoind_net));
        }

        let wallet = Wallet {
            cfg,
            secp: Default::default(),
            btc_rpc: bitcoind_rpc,
            db,
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

    /// Try to attach a contributed signature to a pending peg-out tx and try to finalize it.
    fn process_peg_out_signature(
        &self,
        mut batch: BatchTx,
        peer: PeerId,
        signature: &PegOutSignatureItem,
    ) -> Result<(), ProcessPegOutSigError> {
        let mut psbt = self
            .db
            .get_value::<_, PartiallySignedTransaction>(&UnsignedTransactionKey(signature.txid))
            .expect("DB error")
            .ok_or(ProcessPegOutSigError::UnknownTransaction(signature.txid))?;

        let peer_key = self
            .cfg
            .peer_peg_in_keys
            .get(&peer)
            .expect("always called with valid peer id");

        if psbt.inputs.len() != signature.signature.len() {
            return Err(ProcessPegOutSigError::WrongSignatureCount(
                psbt.inputs.len(),
                signature.signature.len(),
            ));
        }

        let mut tx_hasher = SigHashCache::new(&psbt.global.unsigned_tx);
        for (idx, (input, signature)) in psbt
            .inputs
            .iter_mut()
            .zip(signature.signature.iter())
            .enumerate()
        {
            let tx_hash = tx_hasher.signature_hash(
                idx,
                input
                    .witness_script
                    .as_ref()
                    .expect("Missing witness script"),
                input.witness_utxo.as_ref().expect("Missing UTXO").value,
                SigHashType::All,
            );

            let tweak = input
                .proprietary
                .get(&proprietary_tweak_key())
                .expect("we saved it with a tweak");

            let tweaked_peer_key = peer_key.tweak(tweak, &self.secp);
            self.secp
                .verify(
                    &Message::from_slice(&tx_hash[..]).unwrap(),
                    signature,
                    &tweaked_peer_key.key,
                )
                .map_err(|_| ProcessPegOutSigError::InvalidSignature)?;

            let psbt_sig = signature
                .serialize_der()
                .iter()
                .copied()
                .chain(std::iter::once(SigHashType::All.as_u32() as u8))
                .collect();

            if input
                .partial_sigs
                .insert(tweaked_peer_key.into(), psbt_sig)
                .is_some()
            {
                return Err(ProcessPegOutSigError::DuplicateSignature);
            }
            // TODO: delete signature item if it's our own
        }

        // FIXME: actually recognize change UTXOs on maturity
        // We need to save the change output's tweak key to be able to access the funds later on.
        // The tweak is extracted here because the psbt is moved next and not available anymore
        // when the tweak is actually needed in the end to be put into the batch on success.
        let change_tweak = psbt
            .outputs
            .iter()
            .flat_map(|output| output.proprietary.get(&proprietary_tweak_key()).cloned())
            .next();

        match miniscript::psbt::finalize(&mut psbt, &self.secp) {
            Ok(()) => {}
            Err(e) => {
                trace!("can't finalize peg-out tx {} yet: {}", signature.txid, e);

                // We want to save the new signature, so we need to overwrite the PSBT
                batch.append_insert(UnsignedTransactionKey(signature.txid), psbt);
                batch.commit();
                return Ok(());
            }
        }

        let tx = match miniscript::psbt::extract(&psbt, &self.secp) {
            Ok(tx) => tx,
            Err(e) => {
                // FIXME: this should never happen AFAIK, but I'd like to avoid DOS bugs for now
                error!(
                    "This shouldn't happen: could not extract tx from finalized PSBT ({})",
                    e
                );

                // Who knows what went wrong, we still want to save the received signature
                batch.append_insert(UnsignedTransactionKey(signature.txid), psbt);
                batch.commit();
                return Ok(());
            }
        };

        debug!("Finalized peg-out tx: {}", tx.txid());
        trace!("transaction = {:?}", tx);
        // FIXME: recognize change
        // We were able to finalize the transaction, so we will delete the PSBT and instead keep the
        // extracted tx for periodic transmission and to accept the change into our wallet
        // eventually once it confirms.
        batch.append_delete(UnsignedTransactionKey(signature.txid));
        batch.append_insert_new(
            PendingTransactionKey(signature.txid),
            PendingTransaction {
                tx,
                tweak: change_tweak,
            },
        );
        batch.commit();
        Ok(())
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
    async fn process_block_height_proposals(
        &self,
        batch: BatchTx<'_>,
        mut proposals: Vec<u32>,
    ) -> u32 {
        assert!(!proposals.is_empty());

        proposals.sort_unstable();
        let median_proposal = proposals[proposals.len() / 2];

        let consensus_height = self.consensus_height().unwrap_or(0);

        if median_proposal >= consensus_height {
            debug!("Setting consensus block height to {}", median_proposal);
            self.sync_up_to_consensus_heigh(batch, median_proposal)
                .await;
        } else {
            panic!(
                   "Median proposed consensus block height shrunk from {} to {}, the federation is broken",
                   consensus_height, median_proposal
               );
        }

        median_proposal
    }

    pub fn current_round_consensus(&self) -> Option<RoundConsensus> {
        self.db
            .get_value::<_, RoundConsensus>(&RoundConsensusKey)
            .expect("DB error")
    }

    pub fn consensus_height(&self) -> Option<u32> {
        self.current_round_consensus().map(|rc| rc.block_height)
    }

    async fn sync_up_to_consensus_heigh(&self, mut batch: BatchTx<'_>, new_height: u32) {
        let old_height = self.consensus_height().unwrap_or(0);
        if new_height < old_height {
            info!(
                "Nothing to sync, new height ({}) is lower than old height ({}), doing nothing.",
                new_height, old_height
            );
            return;
        }

        if new_height == old_height {
            debug!("Height didn't change, still at {}", old_height);
            return;
        }

        info!(
            "New consensus height {}, syncing up ({} blocks to go)",
            new_height,
            new_height - old_height
        );

        batch.reserve((new_height - old_height) as usize + 1);
        for height in (old_height + 1)..=(new_height) {
            if height % 100 == 0 {
                debug!("Caught up to block {}", height);
            }

            // TODO: use batching for mainnet syncing
            trace!("Fetching block hash for block {}", height);
            // TODO: implement retying failed RPC commands till they succeed while loudly complaining to alert the operator
            let block_hash = self.btc_rpc.get_block_hash(height as u64).await; // TODO: use u64 for height everywhere
            batch.append_insert_new(
                BlockHashKey(BlockHash::from_inner(block_hash.into_inner())),
                (),
            );
        }
        batch.commit();
    }

    fn block_is_known(&self, block_hash: BlockHash) -> bool {
        self.db
            .get_value::<_, ()>(&BlockHashKey(block_hash))
            .expect("DB error")
            .is_some()
    }

    pub fn pending_peg_outs(&self) -> Vec<(OutPoint, PendingPegOut)> {
        self.db
            .find_by_prefix::<_, PendingPegOutKey, PendingPegOut>(&PendingPegOutPrefixKey)
            .map_ok(|(key, peg_out)| (key.0, peg_out))
            .collect::<Result<_, _>>()
            .expect("DB error")
    }

    async fn create_peg_out_tx(
        &self,
        pending_peg_outs: Vec<PendingPegOut>,
        consensus: RoundConsensus,
    ) -> PartiallySignedTransaction {
        let wallet = self.offline_wallet();
        let mut psbt = wallet.create_tx(
            pending_peg_outs,
            self.available_utxos(),
            consensus.fee_rate,
            &consensus.randomness_beacon,
        );
        // TODO: extract sigs and do stuff?!
        wallet.sign_psbt(&mut psbt);
        psbt
    }

    fn available_utxos(&self) -> Vec<(UTXOKey, SpendableUTXO)> {
        self.db
            .find_by_prefix::<_, UTXOKey, SpendableUTXO>(&UTXOPrefixKey)
            .collect::<Result<_, _>>()
            .expect("DB error")
    }

    fn offline_wallet(&self) -> StatelessWallet {
        StatelessWallet {
            descriptor: &self.cfg.peg_in_descriptor,
            secret_key: &self.cfg.peg_in_key,
            secp: &self.secp,
        }
    }
}

impl<'a> StatelessWallet<'a> {
    fn create_tx(
        &self,
        outputs: Vec<PendingPegOut>,
        mut utxos: Vec<(UTXOKey, SpendableUTXO)>,
        feerate: Feerate,
        change_tweak: &[u8],
    ) -> PartiallySignedTransaction {
        // When building a transaction we need to take care of two things:
        //  * We need enough input amount to fund all outputs
        //  * We need to keep an eye on the tx weight so we can factor the fees into out calculation

        // We first calculate the total amount of outputs without change. We need at least that much
        // plus fees in input amounts.
        let peg_out_amount = outputs
            .iter()
            .map(|peg_out| peg_out.amount)
            .fold1(|a, b| a + b)
            .expect("We always peg out to at least one address");

        // We then go on to calculate the base size of the transaction `total_weight` and the
        // maximum weight per added input which we will add every time we select an input.
        let change_script = self.derive_script(change_tweak);
        let out_weight: usize = outputs
            .iter()
            .map(|out| out.destination.len() * 4 + 1 + 32)
            .sum::<usize>()
            // Add change script weight, it's very likely to be needed if not we just overpay in fees
            + 1 // script len varint, 1 byte for all addresses we accept
            + change_script.len() * 4 // script len
            + 32; // value
        let mut total_weight = 16 + // version
            12 + // up to 2**16-1 inputs
            12 + // up to 2**16-1 outputs
            out_weight + // weight of all outputs
            16; // lock time
        let max_input_weight = self
            .descriptor
            .max_satisfaction_weight()
            .expect("is satisfyable") + 
            128 + // TxOutHash
            16 + // TxOutIndex
            16; // sequence

        // Finally we initialize our accumulator for selected input amounts
        let mut total_selected_value = bitcoin::Amount::from_sat(0);

        // When selecting UTXOs we employ a very primitive algorithm:
        //  1. Sort UTXOs by amount, least to biggest
        //  2. Keep selecting UTXOs as long as we still lack input value to pay both all outputs
        //     plus the fee
        utxos.sort_by_key(|(_, utxo)| utxo.amount);
        let selected_utxos = utxos
            .into_iter()
            .take_while(|(_, utxo)| {
                let fee = feerate.calculate_fee(total_weight);
                if total_selected_value < (peg_out_amount + fee) {
                    total_selected_value += utxo.amount;
                    total_weight += max_input_weight;
                    true
                } else {
                    false
                }
            })
            .collect::<Vec<_>>();

        // We might have selected too much value on the input side, so we need to pay the remainder
        // back to ourselves.
        let fees = feerate.calculate_fee(total_weight);
        let change = total_selected_value - fees - peg_out_amount;
        let change_output = if change >= change_script.dust_value() {
            Some(PendingPegOut {
                destination: change_script,
                amount: change,
                pending_since_block: 0,
            })
        } else {
            None
        };

        info!(
            "Creating peg-out tx with {} inputs of value {} BTC, {} peg-outs of value {} paying {} BTC in fees (fee rate {}) and a change amount of {} BTC",
            selected_utxos.len(),
            total_selected_value.as_btc(),
            outputs.len(),
            peg_out_amount.as_btc(),
            fees.as_btc(),
            feerate.sats_per_kvb,
            change.as_btc()
        );

        let transaction = Transaction {
            version: 2,
            lock_time: 0,
            input: selected_utxos
                .iter()
                .map(|(utxo_key, _utxo)| TxIn {
                    previous_output: utxo_key.0,
                    script_sig: Default::default(),
                    sequence: 0xFFFFFFFF,
                    witness: vec![],
                })
                .collect(),
            output: outputs
                .iter()
                .chain(change_output.as_ref())
                .map(|peg_out| TxOut {
                    value: peg_out.amount.as_sat(),
                    script_pubkey: peg_out.destination.clone(),
                })
                .collect(),
        };
        info!("Creating peg-out tx {}", transaction.txid());

        // FIXME: use custom data structure that guarantees more invariants and only convert to PSBT for finalization
        let psbt = PartiallySignedTransaction {
            global: Global {
                unsigned_tx: transaction,
                version: 0,
                xpub: Default::default(),
                proprietary: Default::default(),
                unknown: Default::default(),
            },
            inputs: selected_utxos
                .into_iter()
                .map(|(_utxo_key, utxo)| Input {
                    non_witness_utxo: None,
                    witness_utxo: Some(TxOut {
                        value: utxo.amount.as_sat(),
                        script_pubkey: utxo.script_pubkey,
                    }),
                    partial_sigs: Default::default(),
                    sighash_type: None,
                    redeem_script: None,
                    witness_script: Some(
                        self.descriptor.tweak(&utxo.tweak, self.secp).script_code(),
                    ),
                    bip32_derivation: Default::default(),
                    final_script_sig: None,
                    final_script_witness: None,
                    ripemd160_preimages: Default::default(),
                    sha256_preimages: Default::default(),
                    hash160_preimages: Default::default(),
                    hash256_preimages: Default::default(),
                    proprietary: vec![(proprietary_tweak_key(), utxo.tweak.serialize().to_vec())]
                        .into_iter()
                        .collect(),
                    unknown: Default::default(),
                })
                .collect(),
            outputs: outputs
                .iter()
                .map(|_| Default::default())
                .chain(change_output.map(|_| {
                    let mut cout = bitcoin::util::psbt::Output::default();
                    cout.proprietary
                        .insert(proprietary_tweak_key(), change_tweak.to_vec());
                    cout
                }))
                .collect(),
        };

        psbt
    }

    fn sign_psbt(&self, psbt: &mut PartiallySignedTransaction) {
        let mut tx_hasher = SigHashCache::new(&psbt.global.unsigned_tx);

        for (idx, (psbt_input, _tx_input)) in psbt
            .inputs
            .iter_mut()
            .zip(psbt.global.unsigned_tx.input.iter())
            .enumerate()
        {
            let tweaked_secret = {
                let mut secret_key = *self.secret_key;

                let tweak_pk_bytes = psbt_input
                    .proprietary
                    .get(&proprietary_tweak_key())
                    .expect("Malformed PSBT: expected tweak");
                let pub_key = secp256k1::PublicKey::from_secret_key(self.secp, &secret_key);

                let tweak = {
                    let mut hasher = HmacEngine::<sha256::Hash>::new(&pub_key.serialize()[..]);
                    hasher.input(&tweak_pk_bytes[..]);
                    Hmac::from_engine(hasher).into_inner()
                };

                secret_key
                    .add_assign(&tweak[..])
                    .expect("Tweaking priv key failed"); // TODO: why could this happen?
                secret_key
            };

            let tx_hash = tx_hasher.signature_hash(
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
                SigHashType::All,
            );

            let mut signature = self
                .secp
                .sign(&Message::from_slice(&tx_hash[..]).unwrap(), &tweaked_secret)
                .serialize_der()
                .to_vec();
            signature.push(SigHashType::All.as_u32() as u8);

            psbt_input.partial_sigs.insert(
                bitcoin::PublicKey {
                    compressed: true,
                    key: secp256k1::PublicKey::from_secret_key(self.secp, &tweaked_secret),
                },
                signature,
            );
        }
    }

    fn derive_script(&self, tweak: &[u8]) -> Script {
        let descriptor = self.descriptor.translate_pk2_infallible(|pub_key| {
            let hashed_tweak = {
                let mut hasher = HmacEngine::<sha256::Hash>::new(&pub_key.key.serialize()[..]);
                hasher.input(tweak);
                Hmac::from_engine(hasher).into_inner()
            };

            let mut tweak_key = pub_key.key;
            tweak_key
                .add_exp_assign(self.secp, &hashed_tweak)
                .expect("tweaking failed");

            CompressedPublicKey { key: tweak_key }
        });

        descriptor.script_pubkey()
    }
}

fn proprietary_tweak_key() -> ProprietaryKey {
    ProprietaryKey {
        prefix: b"minimint".to_vec(),
        subtype: 0x00,
        key: vec![],
    }
}

pub fn is_address_valid_for_network(address: &Address, network: Network) -> bool {
    match (address.network, address.address_type()) {
        (Network::Testnet, Some(AddressType::P2pkh))
        | (Network::Testnet, Some(AddressType::P2sh)) => {
            [Network::Testnet, Network::Regtest, Network::Signet].contains(&network)
        }
        (Network::Testnet, _) => [Network::Testnet, Network::Signet].contains(&network),
        (addr_net, _) => addr_net == network,
    }
}

async fn broadcast_pending_tx(db: Arc<dyn RawDatabase>, rpc: Box<dyn BitcoindRpc>) {
    loop {
        let pending_tx = db
            .find_by_prefix::<_, PendingTransactionKey, PendingTransaction>(
                &PendingTransactionPrefixKey,
            )
            .collect::<Result<Vec<_>, _>>()
            .expect("DB error");

        for (_, PendingTransaction { tx, .. }) in pending_tx {
            debug!(
                "Broadcasting peg-out tx {} (weight {})",
                tx.txid(),
                tx.get_weight()
            );
            trace!("Transaction: {:?}", tx);
            rpc.submit_transaction(tx).await;
        }
        tokio::time::sleep(Duration::from_secs(10)).await;
    }
}

impl Feerate {
    pub fn calculate_fee(&self, weight: usize) -> bitcoin::Amount {
        let sats = self.sats_per_kvb * (weight as u64) / 1000;
        bitcoin::Amount::from_sat(sats)
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

#[derive(Debug, Error)]
pub enum WalletError {
    #[error("Connected bitcoind is on wrong network, expected {0}, got {1}")]
    WrongNetwork(Network, Network),
    #[error("Error querying bitcoind: {0}")]
    RpcErrot(bitcoincore_rpc::Error),
    #[error("Unknown bitcoin network: {0}")]
    UnknownNetwork(String),
    #[error("Unknown block hash in peg-in proof: {0}")]
    UnknownPegInProofBlock(BlockHash),
    #[error("Invalid peg-in proof: {0}")]
    PegInProofError(PegInProofError),
    #[error("The peg-in was already claimed")]
    PegInAlreadyClaimed,
}

#[derive(Debug, Error)]
pub enum ProcessPegOutSigError {
    #[error("No unsigned transaction with id {0} exists")]
    UnknownTransaction(Txid),
    #[error("Expected {0} signatures, got {1}")]
    WrongSignatureCount(usize, usize),
    #[error("Malformed signature: {0}")]
    MalformedSignature(secp256k1::Error),
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Duplicate signature")]
    DuplicateSignature,
}

impl From<bitcoincore_rpc::Error> for WalletError {
    fn from(e: bitcoincore_rpc::Error) -> Self {
        WalletError::RpcErrot(e)
    }
}

impl From<PegInProofError> for WalletError {
    fn from(e: PegInProofError) -> Self {
        WalletError::PegInProofError(e)
    }
}

// FIXME: make FakeFed not require Eq
/// **WARNING**: this is only intended to be used for testing
impl PartialEq for WalletError {
    fn eq(&self, other: &Self) -> bool {
        format!("{:?}", self) == format!("{:?}", other)
    }
}

/// **WARNING**: this is only intended to be used for testing
impl Eq for WalletError {}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bitcoin::hashes::Hash as BitcoinHash;
    use bitcoin::{Address, Amount, OutPoint, TxOut};
    use miniscript::descriptor::Wsh;
    use miniscript::policy::Concrete;
    use miniscript::{Descriptor, DescriptorTrait, Segwitv0};

    use crate::db::UTXOKey;
    use crate::keys::CompressedPublicKey;
    use crate::tweakable::Tweakable;
    use crate::{PendingPegOut, SpendableUTXO, StatelessWallet};

    use super::Feerate;

    #[test]
    fn sign_tx() {
        const CHANGE_TWEAK: [u8; 32] = [42u8; 32];

        let ctx = secp256k1::Secp256k1::new();
        let mut rng = rand::rngs::OsRng::new().unwrap();
        let (sec_key, pub_key) = ctx.generate_keypair(&mut rng);

        let descriptor = Descriptor::Wsh(
            Wsh::new(
                Concrete::Key(CompressedPublicKey::new(pub_key))
                    .compile::<Segwitv0>()
                    .unwrap(),
            )
            .unwrap(),
        );

        let wallet = StatelessWallet {
            descriptor: &descriptor,
            secret_key: &sec_key,
            secp: &ctx,
        };

        let peg_outs = vec![PendingPegOut {
            destination: Address::from_str("bc1qkuzm3093vc7t9q80ul4p5sydkg39sk8gm0park")
                .unwrap()
                .script_pubkey(),
            amount: Amount::from_sat(42),
            pending_since_block: 0,
        }];

        let tweak = secp256k1::schnorrsig::PublicKey::from_slice(&[0x02; 32][..]).unwrap();
        let tweaked = descriptor.tweak(&tweak, &ctx);
        let utxos = vec![(
            UTXOKey(OutPoint::new(
                BitcoinHash::from_slice(&[1u8; 32]).unwrap(),
                1,
            )),
            SpendableUTXO {
                tweak,
                amount: Amount::from_sat(42000),
                script_pubkey: tweaked.script_pubkey(),
            },
        )];

        let mut psbt = wallet.create_tx(
            peg_outs,
            utxos,
            Feerate { sats_per_kvb: 4000 },
            &CHANGE_TWEAK,
        );
        wallet.sign_psbt(&mut psbt);
        miniscript::psbt::finalize(&mut psbt, &ctx).unwrap();
        let tx = miniscript::psbt::extract(&psbt, &ctx).unwrap();

        tx.verify(|_| {
            Some(TxOut {
                value: 42000,
                script_pubkey: tweaked.script_pubkey(),
            })
        })
        .unwrap()
    }
}
