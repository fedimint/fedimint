use fedimint_core::encoding::{Decodable, DecodeError, Encodable};
use fedimint_core::module::registry::ModuleDecoderRegistry;
use frost_secp256k1_tr::keys::PublicKeyPackage;
use frost_secp256k1_tr::round2::SignatureShare;
use serde::{Deserialize, Serialize};

/// Implements `Encodable`/`Decodable` for a newtype wrapping a FROST type by
/// bridging through the FROST type's own byte serialization: encoding writes
/// `self.0.serialize()` as a length-prefixed byte vector, decoding reads the
/// byte vector back through `<Inner>::deserialize`.
#[macro_export]
macro_rules! impl_frost_encodable {
    ($wrapper:ident, $inner:ty) => {
        impl ::fedimint_core::encoding::Encodable for $wrapper {
            fn consensus_encode<W: ::std::io::Write>(
                &self,
                writer: &mut W,
            ) -> ::std::result::Result<(), ::std::io::Error> {
                let bytes = self.0.serialize().map_err(::std::io::Error::other)?;
                ::fedimint_core::encoding::Encodable::consensus_encode(&bytes, writer)
            }
        }

        impl ::fedimint_core::encoding::Decodable for $wrapper {
            fn consensus_decode_partial<R: ::std::io::Read>(
                r: &mut R,
                modules: &::fedimint_core::module::registry::ModuleDecoderRegistry,
            ) -> ::std::result::Result<Self, ::fedimint_core::encoding::DecodeError> {
                let bytes = <::std::vec::Vec<u8> as ::fedimint_core::encoding::Decodable>::consensus_decode_partial(r, modules)?;
                <$inner>::deserialize(&bytes)
                    .map($wrapper)
                    .map_err(::fedimint_core::encoding::DecodeError::from_err)
            }
        }
    };
}

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

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct FrostSigningCommitments(pub frost_secp256k1_tr::round1::SigningCommitments);

impl_frost_encodable!(
    FrostSigningCommitments,
    frost_secp256k1_tr::round1::SigningCommitments
);

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

impl_frost_encodable!(FrostPublicKeyPackage, PublicKeyPackage);

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
