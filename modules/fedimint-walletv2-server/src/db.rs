use bitcoin::{TxOut, Txid};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{PeerId, impl_db_lookup, impl_db_record};
use fedimint_walletv2_common::TxInfo;
use fedimint_walletv2_common::taproot::frost::{
    FrostFinalizationStat, FrostSignatureShares, FrostSigningCommitments,
};
use secp256k1::ecdsa::Signature;
use secp256k1::schnorr;
use serde::Serialize;
use strum_macros::EnumIter;

use crate::taproot::frost::{FrostSigningNonces, FrostSigningPackage};
use crate::{FederationTx, FederationWallet};

#[repr(u8)]
#[derive(Clone, EnumIter, Debug)]
pub enum DbKeyPrefix {
    Output = 0x30,
    SpentOutput = 0x31,
    BlockCountVote = 0x32,
    FeeRateVote = 0x33,
    TxLog = 0x34,
    TxInfoIndex = 0x35,
    UnsignedTx = 0x36,
    Signatures = 0x37,
    UnconfirmedTx = 0x38,
    FederationWallet = 0x39,
    SchnorrSignatures = 0x3a,
    FrostSigningCommitments = 0x3b,
    FrostSigningNonce = 0x3c,
    FrostSignatureShare = 0x3d,
    FrostSigningPackages = 0x3e,
    FrostSigningAttempt = 0x3f,
    FrostAdvanceVote = 0x40,
    LocalFrostSignatureShare = 0x41,
    FrostFinalizationStat = 0x42,
}

impl std::fmt::Display for DbKeyPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub struct OutputKey(pub u64);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct OutputPrefix;

#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub struct Output(pub bitcoin::OutPoint, pub TxOut);

impl_db_record!(
    key = OutputKey,
    value = Output,
    db_prefix = DbKeyPrefix::Output,
);

impl_db_lookup!(key = OutputKey, query_prefix = OutputPrefix);

#[derive(Clone, Debug, Eq, PartialEq, Encodable, Decodable, Serialize)]
pub struct SpentOutputKey(pub u64);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct SpentOutputPrefix;

impl_db_record!(
    key = SpentOutputKey,
    value = (),
    db_prefix = DbKeyPrefix::SpentOutput
);

impl_db_lookup!(key = SpentOutputKey, query_prefix = SpentOutputPrefix);

#[derive(Clone, Debug, Eq, PartialEq, Encodable, Decodable, Serialize)]
pub struct FederationWalletPrefix;

#[derive(Clone, Debug, Eq, PartialEq, Encodable, Decodable, Serialize)]
pub struct FederationWalletKey;

impl_db_record!(
    key = FederationWalletKey,
    value = FederationWallet,
    db_prefix = DbKeyPrefix::FederationWallet,
);

impl_db_lookup!(
    key = FederationWalletKey,
    query_prefix = FederationWalletPrefix
);

#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub struct TxInfoKey(pub u64);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct TxInfoPrefix;

impl_db_record!(
    key = TxInfoKey,
    value = TxInfo,
    db_prefix = DbKeyPrefix::TxLog,
);

impl_db_lookup!(key = TxInfoKey, query_prefix = TxInfoPrefix);

#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub struct TxInfoIndexKey(pub fedimint_core::OutPoint);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct TxInfoIndexPrefix;

impl_db_record!(
    key = TxInfoIndexKey,
    value = u64,
    db_prefix = DbKeyPrefix::TxInfoIndex,
);

impl_db_lookup!(key = TxInfoIndexKey, query_prefix = TxInfoIndexPrefix);

#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub struct UnsignedTxKey(pub Txid);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct UnsignedTxPrefix;

impl_db_record!(
    key = UnsignedTxKey,
    value = FederationTx,
    db_prefix = DbKeyPrefix::UnsignedTx,
);

impl_db_lookup!(key = UnsignedTxKey, query_prefix = UnsignedTxPrefix);

#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub struct SignaturesKey(pub Txid, pub PeerId);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct SignaturesTxidPrefix(pub Txid);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct SignaturesPrefix;

impl_db_record!(
    key = SignaturesKey,
    value = Vec<Signature>,
    db_prefix = DbKeyPrefix::Signatures,
);

impl_db_lookup!(key = SignaturesKey, query_prefix = SignaturesTxidPrefix);

impl_db_lookup!(key = SignaturesKey, query_prefix = SignaturesPrefix);

#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub struct SchnorrSignaturesKey(pub Txid, pub PeerId);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct SchnorrSignaturesTxidPrefix(pub Txid);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct SchnorrSignaturesPrefix;

impl_db_record!(
    key = SchnorrSignaturesKey,
    value = Vec<schnorr::Signature>,
    db_prefix = DbKeyPrefix::SchnorrSignatures,
);

impl_db_lookup!(
    key = SchnorrSignaturesKey,
    query_prefix = SchnorrSignaturesTxidPrefix
);

impl_db_lookup!(
    key = SchnorrSignaturesKey,
    query_prefix = SchnorrSignaturesPrefix
);

#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub struct UnconfirmedTxKey(pub Txid);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct UnconfirmedTxPrefix;

impl_db_record!(
    key = UnconfirmedTxKey,
    value = FederationTx,
    db_prefix = DbKeyPrefix::UnconfirmedTx,
);

impl_db_lookup!(key = UnconfirmedTxKey, query_prefix = UnconfirmedTxPrefix);

#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub struct BlockCountVoteKey(pub PeerId);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct BlockCountVotePrefix;

impl_db_record!(
    key = BlockCountVoteKey,
    value = u64,
    db_prefix = DbKeyPrefix::BlockCountVote
);

impl_db_lookup!(key = BlockCountVoteKey, query_prefix = BlockCountVotePrefix);

#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub struct FeeRateVoteKey(pub PeerId);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct FeeRateVotePrefix;

impl_db_record!(
    key = FeeRateVoteKey,
    value = Option<u64>,
    db_prefix = DbKeyPrefix::FeeRateVote
);

impl_db_lookup!(key = FeeRateVoteKey, query_prefix = FeeRateVotePrefix);

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct FrostSigningCommitmentsKey {
    pub peer_id: PeerId,
    pub frost_commitments: FrostSigningCommitments,
}

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct FrostSigningCommitmentsPrefix;

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct FrostSigningCommitmentsPeerPrefix(pub PeerId);

impl_db_record!(
    key = FrostSigningCommitmentsKey,
    value = (),
    db_prefix = DbKeyPrefix::FrostSigningCommitments
);

impl_db_lookup!(
    key = FrostSigningCommitmentsKey,
    query_prefix = FrostSigningCommitmentsPrefix,
    query_prefix = FrostSigningCommitmentsPeerPrefix
);

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct FrostSigningNoncesKey(pub FrostSigningCommitments); // indexed by the nonce commitment

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct FrostSigningNoncesPrefix;

impl_db_record!(
    key = FrostSigningNoncesKey,
    value = FrostSigningNonces,
    db_prefix = DbKeyPrefix::FrostSigningNonce
);

impl_db_lookup!(
    key = FrostSigningNoncesKey,
    query_prefix = FrostSigningNoncesPrefix
);

/// Field order matters: `(txid, attempt, peer_id)` lets us derive both a
/// per-attempt prefix (for threshold tally) and a per-tx prefix (for
/// finalization cleanup) by encoding-prefix matching.
#[derive(Debug, Clone, Encodable, Decodable)]
pub struct FrostSignatureShareKey {
    pub txid: Txid,
    pub attempt: u32,
    pub peer_id: PeerId,
}

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct FrostSignatureShareAttemptPrefix {
    pub txid: Txid,
    pub attempt: u32,
}

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct FrostSignatureShareTxidPrefix(pub Txid);

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct FrostSignatureSharePrefix;

impl_db_record!(
    key = FrostSignatureShareKey,
    value = FrostSignatureShares,
    db_prefix = DbKeyPrefix::FrostSignatureShare
);

impl_db_lookup!(
    key = FrostSignatureShareKey,
    query_prefix = FrostSignatureSharePrefix,
    query_prefix = FrostSignatureShareTxidPrefix,
    query_prefix = FrostSignatureShareAttemptPrefix
);

/// Local-only stash of our own pre-computed signature share for `(txid,
/// attempt)`. Written by `compute_and_store_frost_signature_shares` when
/// we're a signer; read by `consensus_proposal` to broadcast; cleared on
/// tx finalization.
///
/// Kept separate from the consensus-replicated `FrostSignatureShareKey` so
/// that consensus inputs (suspects in `pick_signing_session`) only ever
/// see shares that have actually been delivered through `AlephBFT` — every
/// guardian's view is identical at every consensus item boundary.
#[derive(Debug, Clone, Encodable, Decodable)]
pub struct LocalFrostSignatureShareKey {
    pub txid: Txid,
    pub attempt: u32,
}

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct LocalFrostSignatureShareTxidPrefix(pub Txid);

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct LocalFrostSignatureSharePrefix;

impl_db_record!(
    key = LocalFrostSignatureShareKey,
    value = FrostSignatureShares,
    db_prefix = DbKeyPrefix::LocalFrostSignatureShare
);

impl_db_lookup!(
    key = LocalFrostSignatureShareKey,
    query_prefix = LocalFrostSignatureSharePrefix,
    query_prefix = LocalFrostSignatureShareTxidPrefix
);

#[derive(Debug, Clone, Encodable, Decodable, Serialize)]
pub struct FrostSigningPackagesKey {
    pub txid: Txid,
    pub attempt: u32,
}

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct FrostSigningPackagesTxidPrefix(pub Txid);

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct FrostSigningPackagesPrefix;

impl_db_record!(
    key = FrostSigningPackagesKey,
    value = Vec<FrostSigningPackage>,
    db_prefix = DbKeyPrefix::FrostSigningPackages
);

impl_db_lookup!(
    key = FrostSigningPackagesKey,
    query_prefix = FrostSigningPackagesPrefix,
    query_prefix = FrostSigningPackagesTxidPrefix
);

/// One record per attempt. Once an attempt is created, its record is
/// never overwritten — advancing creates a new record at `(txid,
/// attempt + 1)`. Old records linger until tx finalization, which lets
/// late shares for old attempts still verify against the original
/// `signing_session` and (in principle) complete that attempt.
#[derive(Debug, Clone, Encodable, Decodable, Serialize)]
pub struct FrostSigningAttempt {
    pub signing_session: Vec<PeerId>,
}

#[derive(Debug, Clone, Encodable, Decodable, Serialize)]
pub struct FrostSigningAttemptKey {
    pub txid: Txid,
    pub attempt: u32,
}

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct FrostSigningAttemptTxidPrefix(pub Txid);

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct FrostSigningAttemptPrefix;

impl_db_record!(
    key = FrostSigningAttemptKey,
    value = FrostSigningAttempt,
    db_prefix = DbKeyPrefix::FrostSigningAttempt
);

impl_db_lookup!(
    key = FrostSigningAttemptKey,
    query_prefix = FrostSigningAttemptPrefix,
    query_prefix = FrostSigningAttemptTxidPrefix
);

/// A vote from `voter` to start a fresh attempt for tx `txid` after
/// `attempt` stalled. Existence of the entry = the vote is cast; once
/// `f+1` distinct voters' entries exist for the same `(txid, attempt)`,
/// all peers deterministically open `attempt+1` with a freshly shuffled
/// signing session. The original attempt's record stays in place — late
/// shares can still complete it — so this is purely additive, not an
/// abandonment.
#[derive(Debug, Clone, Encodable, Decodable, Serialize)]
pub struct FrostAdvanceVoteKey {
    pub txid: Txid,
    pub attempt: u32,
    pub voter: PeerId,
}

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct FrostAdvanceVoteAttemptPrefix {
    pub txid: Txid,
    pub attempt: u32,
}

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct FrostAdvanceVoteTxidPrefix(pub Txid);

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct FrostAdvanceVotePrefix;

impl_db_record!(
    key = FrostAdvanceVoteKey,
    value = (),
    db_prefix = DbKeyPrefix::FrostAdvanceVote
);

impl_db_lookup!(
    key = FrostAdvanceVoteKey,
    query_prefix = FrostAdvanceVotePrefix,
    query_prefix = FrostAdvanceVoteTxidPrefix,
    query_prefix = FrostAdvanceVoteAttemptPrefix
);

/// Per-guardian, locally-measured FROST finalization-latency record for a
/// finalized federation transaction, keyed by its `txid`. Written in the
/// finalize branch of `process_frost_signature_share`; read by the
/// authenticated `FROST_FINALIZATION_STATS_ENDPOINT`.
///
/// Node-local diagnostics: `duration_millis` comes from a local wall clock, so
/// the value differs across guardians — but it is never read back during
/// consensus, so (like the FROST nonces in `FrostSigningNoncesKey`) the
/// divergence has no consensus implications.
#[derive(Debug, Clone, Encodable, Decodable)]
pub struct FrostFinalizationStatKey(pub Txid);

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct FrostFinalizationStatPrefix;

impl_db_record!(
    key = FrostFinalizationStatKey,
    value = FrostFinalizationStat,
    db_prefix = DbKeyPrefix::FrostFinalizationStat
);

impl_db_lookup!(
    key = FrostFinalizationStatKey,
    query_prefix = FrostFinalizationStatPrefix
);
