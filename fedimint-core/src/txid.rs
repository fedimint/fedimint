use bitcoin::hashes::hash_newtype;
use bitcoin::hashes::sha256::Hash as Sha256;

hash_newtype!(
    /// A transaction id for peg-ins, peg-outs and reissuances
    pub struct TransactionId(Sha256);
);
