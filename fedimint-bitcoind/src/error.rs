use bitcoin::Txid;
use fedimint_core::encoding::DecodeError;
use thiserror::Error;

/// A failure talking to the Bitcoin data source.
///
/// `Display` prints only the outermost layer; the backend's own error is
/// reachable through [`std::error::Error::source`] and printed flat by
/// [`FmtCompact::fmt_compact`](fedimint_core::util::FmtCompact).
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum BitcoinRpcError {
    /// The backend url could not be parsed, or a client for it could not be
    /// built.
    #[error("Invalid Bitcoin rpc url {url}")]
    InvalidUrl {
        /// The url that was rejected, with any credentials redacted, or the
        /// name of the environment variable it came from when it could
        /// not be parsed at all.
        url: String,
        /// Why it was rejected.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// The backend refused the call or could not be reached.
    #[error("The Bitcoin rpc backend failed")]
    Backend(#[source] Box<dyn std::error::Error + Send + Sync>),

    /// The script is not one the backend can watch as an address.
    #[error("Script is not a standard address")]
    NonStandardScript(#[source] Box<dyn std::error::Error + Send + Sync>),

    /// The backend answered, but the answer cannot be used.
    #[error("Invalid Bitcoin rpc response: {message}")]
    InvalidResponse {
        /// What is wrong with the response.
        message: String,
    },

    /// No merkle proof is available for the transaction.
    #[error("No merkle proof found for transaction {txid}")]
    ProofNotFound {
        /// The transaction the proof was requested for.
        txid: Txid,
    },

    /// The script has more history than can be processed in one go.
    #[error("Script history exceeds the maximum of {max} transactions")]
    ScriptHistoryTooLong {
        /// The maximum number of transactions that can be processed.
        max: usize,
    },

    /// A response could not be decoded.
    #[error("Failed to decode a Bitcoin rpc response")]
    Decode(#[source] DecodeError),
}
