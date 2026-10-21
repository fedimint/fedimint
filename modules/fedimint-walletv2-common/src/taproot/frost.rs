use bip445::{PublicNonce, SignatureShare};
use bitcoin::XOnlyPublicKey;
use fedimint_core::encoding::{Decodable, Encodable};
use secp256k1::PublicKey;
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

/// One peer's public nonce for one signing session, the commitment the other
/// signers bind into the session before any message is signed.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, Hash, Encodable, Decodable)]
pub struct FrostSigningCommitments(pub PublicNonce);

impl Ord for FrostSigningCommitments {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (self.0.0, self.0.1).cmp(&(other.0.0, other.0.1))
    }
}

impl PartialOrd for FrostSigningCommitments {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// The public commitment to the DKG's polynomial: one point per coefficient,
/// `threshold` in total. Carried by `WalletDescriptor::Frost` so every
/// guardian's public key share can be derived from it, and its constant term
/// is the aggregate public key.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, Hash, Encodable, Decodable)]
pub struct FrostPolynomial(pub Vec<PublicKey>);

impl FrostPolynomial {
    /// The federation's aggregate public key, the polynomial's constant term.
    pub fn aggregate_key(&self) -> PublicKey {
        *self
            .0
            .first()
            .expect("FROST polynomial has at least one coefficient")
    }

    /// The aggregate key as a BIP-340 x-only key — the BIP-341 internal key of
    /// every address of a FROST federation.
    pub fn internal_key(&self) -> XOnlyPublicKey {
        self.aggregate_key().x_only_public_key().0
    }
}

/// One peer's signature share for every input of a transaction, in input
/// order.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, Hash, Encodable, Decodable)]
pub struct FrostSignatureShares {
    pub signature_shares: Vec<SignatureShare>,
}
