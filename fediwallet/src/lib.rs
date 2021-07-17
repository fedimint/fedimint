mod db;

use crate::db::{
    BlockHashKey, LastBlock, LastBlockKey, PendingPegOutKey, PendingPegOutPrefixKey,
    PendingTransaction, PendingTransactionKey, PendingTransactionPrefixKey, UTXOKey, UTXOPrefixKey,
    UnsignedTransactionKey,
};
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::consensus::Encodable;
use bitcoin::hashes::hex::ToHex;
use bitcoin::hashes::{sha256, Hash as BitcoinHash, HashEngine, Hmac, HmacEngine};
use bitcoin::secp256k1::{All, Secp256k1};
use bitcoin::util::bip143::SigHashCache;
use bitcoin::util::psbt::raw::ProprietaryKey;
use bitcoin::util::psbt::{Global, Input, PartiallySignedTransaction};
use bitcoin::{
    Address, AddressType, Amount, BlockHash, Network, OutPoint, Script, SigHashType, Transaction,
    TxIn, TxOut, Txid,
};
use bitcoincore_rpc_async::{Auth, RpcApi};
use config::{Feerate, WalletConfig};
use database::batch::{Batch, BatchItem, Element};
use database::{BatchDb, BincodeSerialized, Database, PrefixSearchable};
use itertools::Itertools;
use miniscript::{Descriptor, DescriptorTrait, TranslatePk2};
use mint_api::{CompressedPublicKey, PegInProof, TransactionId, Tweakable};
use rand::{CryptoRng, Rng, RngCore};
use secp256k1::Message;
use serde::{Deserialize, Serialize};
use std::hash::Hasher;
use thiserror::Error;
use tokio::time::Duration;
use tracing::{debug, error, info, trace, warn};

pub const CONFIRMATION_TARGET: u16 = 24;

/// The urgency of doing a peg-out is defined as the sum over all pending peg-outs of the amount of
/// BTC blocks that have been mined since the peg-out was created. E.g. 10 transactions, each
/// waiting for 10 blocks, would cross a minimum urgency threshold of 100.  
pub const MIN_PEG_OUT_URGENCY: u32 = 100;

pub type PartialSig = Vec<u8>;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PegOutSignatureItem {
    txid: Txid,
    signature: Vec<secp256k1::Signature>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct WalletConsensus {
    fee_rate: Feerate,
    randomness_beacon: Option<[u8; 32]>,
}

pub struct Wallet<D> {
    cfg: WalletConfig,
    secp: Secp256k1<All>,
    btc_rpc: bitcoincore_rpc_async::Client,
    db: D,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SpendableUTXO {
    pub tweak: secp256k1::PublicKey,
    #[serde(with = "bitcoin::util::amount::serde::as_sat")]
    pub amount: bitcoin::Amount,
    // FIXME: why do we save the script pub key? We can derive it from the tweak and the descriptor
    pub script_pubkey: Script,
}

// TODO: move pegout logic out of wallet into minimint consensus
#[derive(Clone, Debug, Serialize, Deserialize)]
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

impl<D> Wallet<D>
where
    D: Database + BatchDb + PrefixSearchable + Clone + Send + 'static,
{
    pub async fn new<R>(
        cfg: WalletConfig,
        db: D,
        rng: R,
    ) -> Result<
        (
            Self,
            WalletConsensusItem,
            Option<WalletConsensusItem>, // TODO: find a unified CI abstraction that allows both persistent and transient consensus items
            Batch,
        ),
        WalletError,
    >
    where
        R: RngCore + CryptoRng,
    {
        let broadcaster_cfg = cfg.clone();
        let broadcaster_db = db.clone();
        tokio::spawn(async move {
            // FIXME: become resilient against bitcoind outages
            let btc_rpc = bitcoincore_rpc_async::Client::new(
                broadcaster_cfg.btc_rpc_address.clone(),
                Auth::UserPass(
                    broadcaster_cfg.btc_rpc_user.clone(),
                    broadcaster_cfg.btc_rpc_pass.clone(),
                ),
            )
            .await
            .expect("Failed to connect to bitcoind");

            broadcast_pending_tx(broadcaster_db, btc_rpc).await;
        });

        let btc_rpc = bitcoincore_rpc_async::Client::new(
            cfg.btc_rpc_address.clone(),
            Auth::UserPass(cfg.btc_rpc_user.clone(), cfg.btc_rpc_pass.clone()),
        )
        .await?;

        let bitcoind_net = get_network(&btc_rpc).await?;
        if bitcoind_net != cfg.network {
            return Err(WalletError::WrongNetwork(cfg.network, bitcoind_net));
        }

        if db
            .get_value::<_, LastBlock>(&LastBlockKey)
            .expect("DB error")
            .is_none()
        {
            info!("Initializing new wallet DB.");
            let genesis = genesis_block(cfg.network);
            db.apply_batch(
                vec![
                    BatchItem::InsertNewElement(Element {
                        key: Box::new(LastBlockKey),
                        value: Box::new(LastBlock(0)),
                    }),
                    BatchItem::InsertNewElement(Element {
                        key: Box::new(BlockHashKey(genesis.block_hash())),
                        value: Box::new(()),
                    }),
                ]
                .iter(),
            )
            .expect("DB error");
        }

        let wallet = Wallet {
            cfg,
            secp: Default::default(),
            btc_rpc,
            db,
        };

        info!(
            "Starting initial wallet sync up to block {}",
            wallet.cfg.start_consensus_height
        );
        wallet
            .sync_up_to_consensus_heigh(wallet.cfg.start_consensus_height)
            .await?;

        // TODO: what to do for rejoining?
        let initial_consensus = WalletConsensus {
            fee_rate: wallet.cfg.default_fee,
            randomness_beacon: None,
        };

        // Generate consensus item for first round after fresh startup
        let (consensus_proposal, sig_ci, batch) =
            wallet.consensus_proposal(initial_consensus, rng).await?;

        Ok((wallet, consensus_proposal, sig_ci, batch))
    }

    async fn consensus_proposal<R>(
        &self,
        consensus: WalletConsensus,
        mut rng: R,
    ) -> Result<(WalletConsensusItem, Option<WalletConsensusItem>, Batch), WalletError>
    where
        R: RngCore + CryptoRng,
    {
        let network_height = self.btc_rpc.get_block_count().await? as u32;
        let target_height = network_height.saturating_sub(self.cfg.finalty_delay);
        let consensus_height = self.consensus_height();

        // TODO: verify that using the last consensus height instead of our last proposal opens new attack vectors
        let proposed_height = if target_height >= consensus_height {
            target_height
        } else {
            warn!(
                "The block height shrunk, new proposal would be {}, but we are sticking to the last consensus height {}.",
                target_height,
                consensus_height
            );
            consensus_height
        };

        let fee_rate = self
            .btc_rpc
            .estimate_smart_fee(CONFIRMATION_TARGET, None)
            .await?
            .fee_rate
            .map(|per_kb| Feerate {
                sats_per_kvb: per_kb.as_sat(),
            })
            .unwrap_or(self.cfg.default_fee);

        // Check if we should create a peg-out transaction
        let (peg_out_ids, pending_peg_outs): (Vec<TransactionId>, Vec<PendingPegOut>) =
            self.pending_peg_outs().into_iter().unzip();
        let urgency = pending_peg_outs
            .iter()
            .map(|peg_out| consensus_height - peg_out.pending_since_block)
            .sum::<u32>();

        trace!(
            "Pending peg outs: {}, urgency: {}, urgency threshold: {}",
            pending_peg_outs.len(),
            urgency,
            MIN_PEG_OUT_URGENCY
        );

        // We only want to peg out if we have a real randomness beacon after the first consensus round
        let peg_out_ready = consensus.randomness_beacon.is_some(); // TODO: maybe destructure instead?
        let (batch, sig_ci) = if urgency > MIN_PEG_OUT_URGENCY && peg_out_ready {
            let mut psbt = self.create_peg_out_tx(pending_peg_outs, consensus).await;
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

            let batch = peg_out_ids
                .into_iter()
                .map(|peg_out| BatchItem::DeleteElement(Box::new(PendingPegOutKey(peg_out))))
                .chain(std::iter::once(BatchItem::InsertNewElement(Element {
                    key: Box::new(UnsignedTransactionKey(psbt.global.unsigned_tx.txid())),
                    value: Box::new(BincodeSerialized::owned(psbt)),
                })))
                .collect();

            let sig_ci = WalletConsensusItem::PegOutSignature(PegOutSignatureItem {
                txid,
                signature: sigs,
            });

            (batch, Some(sig_ci))
        } else {
            (vec![], None)
        };

        let wallet_ci = WalletConsensusItem::RoundConsensus(RoundConsensusItem {
            block_height: proposed_height,
            fee_rate,
            randomness: rng.gen(),
        });

        Ok((wallet_ci, sig_ci, batch))
    }

    pub async fn process_consensus_proposals<R>(
        &self,
        proposals: Vec<(u16, WalletConsensusItem)>,
        rng: R,
    ) -> Result<(WalletConsensusItem, Option<WalletConsensusItem>, Batch), WalletError>
    where
        R: RngCore + CryptoRng,
    {
        trace!("Received consensus proposals {:?}", &proposals);

        // TODO: also warn on less than 1/3, that should never happen
        if proposals.is_empty() {
            panic!("No proposals were submitted this round");
        }

        // Apply signatures to peg-out tx
        let mut batch = proposals
            .iter()
            .filter_map(|(peer, ci)| match ci {
                WalletConsensusItem::PegOutSignature(sig) => {
                    match self.process_peg_out_signature(*peer, sig) {
                        Ok(batch) => Some(batch),
                        Err(e) => {
                            warn!("Error processing peer {}'s peg-out signature: {}", peer, e);
                            None
                        }
                    }
                }
                _ => None,
            })
            .flatten()
            .collect::<Vec<_>>();

        // Generate this round's wallet consensus
        let consensus = {
            let fee_proposals = proposals
                .iter()
                .filter_map(|(_, wc)| match wc {
                    WalletConsensusItem::RoundConsensus(rc) => Some(rc.fee_rate),
                    _ => None,
                })
                .collect();
            let consensus_fee_rate = self.process_fee_proposals(fee_proposals).await;

            let height_proposals = proposals
                .iter()
                .filter_map(|(_, wc)| match wc {
                    WalletConsensusItem::RoundConsensus(rc) => Some(rc.block_height),
                    _ => None,
                })
                .collect();
            // The height is saved to know how far we are synced up already. That's why no output
            // is generated and the consensus height is not part of the epoch's wallet consensus
            // struct constructed below.
            self.process_block_height_proposals(height_proposals)
                .await?;

            fn xor(mut lhs: [u8; 32], rhs: [u8; 32]) -> [u8; 32] {
                lhs.iter_mut().zip(rhs).for_each(|(lhs, rhs)| *lhs ^= rhs);
                lhs
            }

            let randomness_beacon = proposals
                .iter()
                .filter_map(|(_, wc)| match wc {
                    WalletConsensusItem::RoundConsensus(rc) => Some(rc.randomness),
                    _ => None,
                })
                .fold([0; 32], xor);

            WalletConsensus {
                fee_rate: consensus_fee_rate,
                randomness_beacon: Some(randomness_beacon),
            }
        };

        let (next_epoch_ci, sig_ci, next_epoch_ci_batch) =
            self.consensus_proposal(consensus, rng).await?;
        batch.extend(next_epoch_ci_batch);

        Ok((next_epoch_ci, sig_ci, batch))
    }

    /// Try to attach a contributed signature to a pending peg-out tx and try to finalize it.
    fn process_peg_out_signature(
        &self,
        peer: u16,
        signature: &PegOutSignatureItem,
    ) -> Result<Batch, ProcessPegOutSigError> {
        let mut psbt = self
            .db
            .get_value::<_, BincodeSerialized<PartiallySignedTransaction>>(&UnsignedTransactionKey(
                signature.txid,
            ))
            .expect("DB error")
            .ok_or(ProcessPegOutSigError::UnknownTransaction(signature.txid))?
            .into_owned();

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
                    &signature,
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
                return Ok(vec![BatchItem::InsertElement(Element {
                    key: Box::new(UnsignedTransactionKey(signature.txid)),
                    value: Box::new(BincodeSerialized::owned(psbt)),
                })]);
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
                return Ok(vec![BatchItem::InsertElement(Element {
                    key: Box::new(UnsignedTransactionKey(signature.txid)),
                    value: Box::new(BincodeSerialized::owned(psbt)),
                })]);
            }
        };

        // We were able to finalize the transaction, so we will delete the PSBT and instead keep the
        // extracted tx for periodic transmission and to accept the change into our wallet
        // eventually once it confirms.
        Ok(vec![
            BatchItem::DeleteElement(Box::new(UnsignedTransactionKey(signature.txid))),
            BatchItem::InsertNewElement(Element {
                key: Box::new(PendingTransactionKey(signature.txid)),
                value: Box::new(PendingTransaction {
                    tx,
                    tweak: change_tweak,
                }),
            }),
        ])
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
        mut proposals: Vec<u32>,
    ) -> Result<(), WalletError> {
        assert!(!proposals.is_empty());

        proposals.sort();
        let median_proposal = proposals[proposals.len() / 2];

        if median_proposal >= self.consensus_height() {
            debug!("Setting consensus block height to {}", median_proposal);
            self.sync_up_to_consensus_heigh(median_proposal).await?;
        } else {
            panic!(
                   "Median proposed consensus block height shrunk from {} to {}, the federation is broken",
                   self.consensus_height(), median_proposal
               );
        }

        Ok(())
    }

    pub fn consensus_height(&self) -> u32 {
        self.db
            .get_value::<_, LastBlock>(&LastBlockKey)
            .expect("DB error")
            .expect("ensured by constructor")
            .0
    }

    async fn sync_up_to_consensus_heigh(&self, new_height: u32) -> Result<(), WalletError> {
        let old_height = self.consensus_height();
        if new_height < old_height {
            info!(
                "Nothing to sync, new height ({}) is lower than old height ({}), doing nothing.",
                new_height, old_height
            );
            return Ok(());
        }

        if new_height == old_height {
            debug!("Height didn't change, still at {}", old_height);
            return Ok(());
        }

        info!(
            "New consensus height {}, syncing up ({} blocks to go)",
            new_height,
            new_height - old_height
        );

        let mut batch = Vec::<BatchItem>::with_capacity((new_height - old_height) as usize + 1);
        for height in (old_height + 1)..=(new_height) {
            if height % 100 == 0 {
                debug!("Caught up to block {}", height);
            }

            // TODO: use batching for mainnet syncing
            trace!("Fetching block hash for block {}", height);
            let block_hash = self.btc_rpc.get_block_hash(height as u64).await?;
            batch.push(BatchItem::InsertNewElement(Element {
                key: Box::new(BlockHashKey(BlockHash::from_inner(block_hash.into_inner()))),
                value: Box::new(()),
            }))
        }
        batch.push(BatchItem::InsertElement(Element {
            key: Box::new(LastBlockKey),
            value: Box::new(LastBlock(new_height)),
        }));

        self.db.apply_batch(batch.iter()).expect("DB error");

        Ok(())
    }

    fn block_is_known(&self, block_hash: BlockHash) -> bool {
        self.db
            .get_value::<_, ()>(&BlockHashKey(block_hash))
            .expect("DB error")
            .is_some()
    }

    pub fn verify_pigin(
        &self,
        peg_in_proof: &PegInProof,
    ) -> Option<Vec<(OutPoint, Amount, Script)>> {
        if !self.block_is_known(peg_in_proof.proof_block()) {
            return None;
        }

        let our_outputs =
            peg_in_proof.get_our_tweaked_txos(&self.secp, &self.cfg.peg_in_descriptor);

        if our_outputs.len() == 0 {
            return None;
        }

        if our_outputs.iter().any(|(out_point, _, _)| {
            self.db
                .get_value::<_, BincodeSerialized<SpendableUTXO>>(&UTXOKey(*out_point))
                .expect("DB error")
                .is_some()
        }) {
            return None;
        }

        Some(our_outputs)
    }

    pub fn claim_pegin(&self, peg_in_proof: &PegInProof) -> Option<(Batch, mint_api::Amount)> {
        let our_outputs = self.verify_pigin(peg_in_proof)?;
        debug!(
            "Claiming peg-in {:?}",
            our_outputs
                .iter()
                .map(|(out, _, _)| format!("{}:{}", out.txid, out.vout))
                .collect::<Vec<_>>()
        );

        let amount: u64 = our_outputs.iter().map(|(_, amt, _)| amt.as_sat()).sum();
        let fee = self.cfg.per_utxo_fee.as_sat() * our_outputs.len() as u64;
        let issuance_amount = mint_api::Amount::from_sat(amount.saturating_sub(fee));

        let batch = our_outputs
            .into_iter()
            .map(|(out_point, amount, script_pubkey)| {
                BatchItem::InsertNewElement(Element {
                    key: Box::new(UTXOKey(out_point)),
                    value: Box::new(BincodeSerialized::owned(SpendableUTXO {
                        tweak: *peg_in_proof.tweak_contract_key(),
                        amount,
                        script_pubkey,
                    })),
                })
            })
            .collect::<Vec<_>>();

        Some((batch, issuance_amount))
    }

    pub fn queue_pegout(
        &self,
        transaction_id: mint_api::TransactionId,
        address: Address,
        amount: bitcoin::Amount,
    ) -> Result<BatchItem, WalletError> {
        debug!("Queuing peg-out of {} BTC to {}", amount.as_btc(), address);
        if is_address_valid_for_network(&address, self.cfg.network) {
            Ok(BatchItem::InsertNewElement(Element {
                key: Box::new(PendingPegOutKey(transaction_id)),
                value: Box::new(BincodeSerialized::owned(PendingPegOut {
                    destination: address.script_pubkey(),
                    amount,
                    pending_since_block: self.consensus_height(),
                })),
            }))
        } else {
            warn!("Trying to peg-out to wrong network");
            Err(WalletError::WrongNetwork(self.cfg.network, address.network))
        }
    }

    pub fn pending_peg_outs(&self) -> Vec<(TransactionId, PendingPegOut)> {
        self.db
            .find_by_prefix::<_, PendingPegOutKey, BincodeSerialized<PendingPegOut>>(
                &PendingPegOutPrefixKey,
            )
            .map_ok(|(txid, peg_out)| (txid.0, peg_out.into_owned()))
            .collect::<Result<_, _>>()
            .expect("DB error")
    }

    async fn create_peg_out_tx(
        &self,
        pending_peg_outs: Vec<PendingPegOut>,
        consensus: WalletConsensus,
    ) -> PartiallySignedTransaction {
        let wallet = self.offline_wallet();
        let mut psbt = wallet.create_tx(
            pending_peg_outs,
            self.available_utxos(),
            consensus.fee_rate,
            &consensus
                .randomness_beacon
                .expect("presence checked before creating tx"),
        );
        // TODO: extract sigs and do stuff?!
        wallet.sign_psbt(&mut psbt);
        psbt
    }

    fn available_utxos(&self) -> Vec<(UTXOKey, SpendableUTXO)> {
        self.db
            .find_by_prefix::<_, UTXOKey, BincodeSerialized<SpendableUTXO>>(&UTXOPrefixKey)
            .map_ok(|(utxo_key, utxo)| (utxo_key, utxo.into_owned()))
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
        let mut total_selected_value = Amount::from_sat(0);

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
        let change_output = if change >= Amount::from_sat(change_script.dust_value()) {
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
                        self.descriptor.tweak(&utxo.tweak, &self.secp).script_code(),
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
                let pub_key = secp256k1::PublicKey::from_secret_key(&self.secp, &secret_key);

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
                    key: secp256k1::PublicKey::from_secret_key(&self.secp, &tweaked_secret),
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
                .add_exp_assign(&self.secp, &hashed_tweak)
                .expect("tweaking failed");

            CompressedPublicKey { key: tweak_key }
        });

        descriptor.script_pubkey()
    }
}

async fn get_network(rpc_client: &bitcoincore_rpc_async::Client) -> Result<Network, WalletError> {
    let bc = rpc_client.get_blockchain_info().await?;
    match bc.chain.as_str() {
        "main" => Ok(Network::Bitcoin),
        "test" => Ok(Network::Testnet),
        "regtest" => Ok(Network::Regtest),
        _ => Err(WalletError::UnknownNetwork(bc.chain)),
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

async fn broadcast_pending_tx<D>(db: D, rpc: bitcoincore_rpc_async::Client)
where
    D: Database + PrefixSearchable,
{
    loop {
        let pending_tx = db
            .find_by_prefix::<_, PendingTransactionKey, PendingTransaction>(
                &PendingTransactionPrefixKey,
            )
            .collect::<Result<Vec<_>, _>>()
            .expect("DB error");

        for (_, PendingTransaction { tx, .. }) in pending_tx {
            let mut raw_tx = Vec::new();
            tx.consensus_encode(&mut raw_tx)
                .expect("Nothing can go wrong with a vec");

            trace!(
                "Broadcasting peg-out tx {} (weight {})",
                tx.txid(),
                tx.get_weight()
            );
            trace!("Transaction: {}", raw_tx.to_hex());
            if let Err(e) = rpc.send_raw_transaction(&raw_tx).await {
                // FIXME: resubmit periodically, also in case it drops out of the mempool
                trace!("Could not submit peg out transaction: {}", e);
            }
        }
        tokio::time::sleep(Duration::from_secs(10)).await;
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

#[derive(Debug, Error)]
pub enum WalletError {
    #[error("Connected bitcoind is on wrong network, expected {0}, got {1}")]
    WrongNetwork(Network, Network),
    #[error("Error querying bitcoind: {0}")]
    RpcErrot(bitcoincore_rpc_async::Error),
    #[error("Unknown bitcoin network: {0}")]
    UnknownNetwork(String),
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

impl From<bitcoincore_rpc_async::Error> for WalletError {
    fn from(e: bitcoincore_rpc_async::Error) -> Self {
        WalletError::RpcErrot(e)
    }
}

#[cfg(test)]
mod tests {
    use crate::db::UTXOKey;
    use crate::{PendingPegOut, SpendableUTXO, StatelessWallet};
    use bitcoin::hashes::Hash as BitcoinHash;
    use bitcoin::{Address, Amount, OutPoint, TxOut};
    use config::Feerate;
    use miniscript::descriptor::Wsh;
    use miniscript::policy::Concrete;
    use miniscript::{Descriptor, DescriptorTrait, Segwitv0};
    use mint_api::{CompressedPublicKey, Tweakable};
    use std::str::FromStr;

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

        let tweak = secp256k1::PublicKey::from_slice(&[02u8; 33]).unwrap();
        let tweaked = descriptor.tweak(&tweak, &ctx);
        let utxos = vec![(
            UTXOKey(OutPoint::new(
                BitcoinHash::from_slice(&[1u8; 32]).unwrap(),
                1,
            )),
            SpendableUTXO {
                tweak: secp256k1::PublicKey::from_slice(&[02u8; 33]).unwrap(),
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
