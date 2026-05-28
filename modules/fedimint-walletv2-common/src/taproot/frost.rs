use std::collections::BTreeMap;

use fedimint_core::PeerId;
use fedimint_core::encoding::{Decodable, DecodeError, Encodable};
use fedimint_core::module::registry::ModuleDecoderRegistry;
use frost_secp256k1_tr::keys::PublicKeyPackage;
use frost_secp256k1_tr::round2::SignatureShare;
use serde::{Deserialize, Serialize};

/// Per-guardian, locally-measured record of how long a single transaction took
/// to reach a finalized (threshold-aggregated) FROST signature on *this*
/// guardian. Served, keyed by `txid`, by the authenticated
/// `FROST_FINALIZATION_STATS_ENDPOINT`.
///
/// `duration_millis` is the wall-clock gap between when this guardian first
/// observed attempt 0 of the signing session (in `consensus_proposal`) and when
/// it aggregated the threshold signature. Because finalization is a
/// deterministic function of the consensus log, this value differs across
/// guardians only by clock skew and how far behind each peer is in processing
/// the log — it is a node-local latency metric, not a blame-attribution one.
///
/// `attempts` is how many adaptive-ROAST attempts were created before
/// finalization: `1` means it finalized on the first signing session, while
/// higher counts indicate stalled sessions that had to reshuffle around
/// unavailable signers. Together with `advance_votes` (total advance votes
/// recorded for the tx across all attempts) this is what explains how signing
/// latency grows as more guardians go offline.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Encodable, Decodable)]
pub struct FrostFinalizationStat {
    pub txid: bitcoin::Txid,
    pub duration_millis: u64,
    pub attempts: u32,
    pub advance_votes: u64,
}

/// Client-computed aggregate of the per-guardian [`FrostFinalizationStat`]s for
/// a single `txid`, collected by querying each guardian's authenticated
/// `FROST_FINALIZATION_STATS_ENDPOINT`. Offline guardians simply don't appear
/// in `per_guardian`, so the median/mean are taken over the guardians that
/// responded.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FrostFinalizationStatsSummary {
    pub txid: bitcoin::Txid,
    /// Number of guardians that returned a finalization stat for `txid`.
    pub responses: usize,
    /// Number of adaptive-ROAST attempts before finalization. Unlike the
    /// per-guardian durations this is derived from the consensus log, so it's
    /// identical across guardians; taken from any responder (`None` if none
    /// responded).
    pub attempts: Option<u32>,
    /// Median of the responding guardians' `duration_millis` (even counts take
    /// the mean of the two middle values), or `None` if none responded.
    pub median_duration_millis: Option<u64>,
    /// Mean of the responding guardians' `duration_millis` (integer millis), or
    /// `None` if none responded.
    pub mean_duration_millis: Option<u64>,
    /// The raw per-guardian stats the summary was computed from.
    pub per_guardian: BTreeMap<PeerId, FrostFinalizationStat>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct FrostSigningCommitments(pub frost_secp256k1_tr::round1::SigningCommitments);

impl Encodable for FrostSigningCommitments {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<(), std::io::Error> {
        let bytes = self.0.serialize().map_err(std::io::Error::other)?;
        bytes.consensus_encode(writer)
    }
}

impl Decodable for FrostSigningCommitments {
    fn consensus_decode_partial<R: std::io::Read>(
        r: &mut R,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let bytes = Vec::<u8>::consensus_decode_partial(r, modules)?;
        frost_secp256k1_tr::round1::SigningCommitments::deserialize(&bytes)
            .map(FrostSigningCommitments)
            .map_err(DecodeError::from_err)
    }
}

impl std::hash::Hash for FrostSigningCommitments {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0
            .serialize()
            .expect("FROST signing commitments serialize")
            .hash(state);
    }
}

impl Ord for FrostSigningCommitments {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let a = self
            .0
            .serialize()
            .expect("FROST signing commitments serialize");
        let b = other
            .0
            .serialize()
            .expect("FROST signing commitments serialize");
        a.cmp(&b)
    }
}

impl PartialOrd for FrostSigningCommitments {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct FrostPublicKeyPackage(pub PublicKeyPackage);

impl Encodable for FrostPublicKeyPackage {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<(), std::io::Error> {
        let bytes = self.0.serialize().map_err(std::io::Error::other)?;
        bytes.consensus_encode(writer)
    }
}

impl Decodable for FrostPublicKeyPackage {
    fn consensus_decode_partial<R: std::io::Read>(
        r: &mut R,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let bytes = Vec::<u8>::consensus_decode_partial(r, modules)?;
        PublicKeyPackage::deserialize(&bytes)
            .map(FrostPublicKeyPackage)
            .map_err(DecodeError::from_err)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct FrostSignatureShares {
    pub signature_shares: Vec<SignatureShare>,
}

impl Encodable for FrostSignatureShares {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<(), std::io::Error> {
        let bytes_vec: Vec<Vec<u8>> = self
            .signature_shares
            .iter()
            .map(SignatureShare::serialize)
            .collect();
        bytes_vec.consensus_encode(writer)
    }
}

impl Decodable for FrostSignatureShares {
    fn consensus_decode_partial<R: std::io::Read>(
        r: &mut R,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let bytes_vec = Vec::<Vec<u8>>::consensus_decode_partial(r, modules)?;
        let signature_shares = bytes_vec
            .into_iter()
            .map(|bytes| SignatureShare::deserialize(&bytes).map_err(DecodeError::from_err))
            .collect::<Result<Vec<_>, DecodeError>>()?;

        Ok(FrostSignatureShares { signature_shares })
    }
}

impl std::hash::Hash for FrostSignatureShares {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        for share in &self.signature_shares {
            share.serialize().hash(state);
        }
    }
}
