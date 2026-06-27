use std::collections::BTreeMap;
use std::fmt::{self, Debug, Display};
use std::time::Duration;

use fedimint_connectors::error::ServerError;
use fedimint_core::PeerId;
use fedimint_core::fmt_utils::AbbreviateJson;
use fedimint_core::util::FmtCompactAnyhow as _;
use fedimint_logging::LOG_CLIENT_NET_API;
use serde::Serialize;
use thiserror::Error;
use tracing::{trace, warn};

/// An API request error when calling an entire federation
///
/// Generally all Federation errors are retryable.
#[derive(Debug, Error)]
pub struct FederationError {
    pub method: String,
    pub params: serde_json::Value,
    /// Higher-level general error
    ///
    /// The `general` error should be Some, when the error is not simply peers
    /// responding with enough errors, but something more global.
    pub general: Option<anyhow::Error>,
    pub peer_errors: BTreeMap<PeerId, ServerError>,
}

impl Display for FederationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Federation rpc error { ")?;
        f.write_fmt(format_args!("method => {}, ", self.method))?;
        if let Some(general) = self.general.as_ref() {
            f.write_fmt(format_args!(
                "params => {:?}, ",
                AbbreviateJson(&self.params)
            ))?;
            f.write_fmt(format_args!("general => {general}, "))?;
            if !self.peer_errors.is_empty() {
                f.write_str(", ")?;
            }
        }
        for (i, (peer, e)) in self.peer_errors.iter().enumerate() {
            f.write_fmt(format_args!("{peer} => {e:#}"))?;
            if i != self.peer_errors.len() - 1 {
                f.write_str(", ")?;
            }
        }
        f.write_str(" }")?;
        Ok(())
    }
}

impl FederationError {
    pub fn general(
        method: impl Into<String>,
        params: impl Serialize,
        e: impl Into<anyhow::Error>,
    ) -> FederationError {
        FederationError {
            method: method.into(),
            params: serde_json::to_value(params).unwrap_or_default(),
            general: Some(e.into()),
            peer_errors: BTreeMap::default(),
        }
    }

    pub(crate) fn peer_errors(
        method: impl Into<String>,
        params: impl Serialize,
        peer_errors: BTreeMap<PeerId, ServerError>,
    ) -> Self {
        Self {
            method: method.into(),
            params: serde_json::to_value(params).unwrap_or_default(),
            general: None,
            peer_errors,
        }
    }

    pub fn new_one_peer(
        peer_id: PeerId,
        method: impl Into<String>,
        params: impl Serialize,
        error: ServerError,
    ) -> Self {
        Self {
            method: method.into(),
            params: serde_json::to_value(params).expect("Serialization of valid params won't fail"),
            general: None,
            peer_errors: [(peer_id, error)].into_iter().collect(),
        }
    }

    /// Report any errors
    pub fn report_if_unusual(&self, context: &str) {
        if let Some(error) = self.general.as_ref() {
            // Any general federation errors are unusual
            warn!(target: LOG_CLIENT_NET_API, err = %error.fmt_compact_anyhow(), %context, "General FederationError");
        }
        for (peer_id, e) in &self.peer_errors {
            e.report_if_unusual(*peer_id, context);
        }
    }

    /// Get the general error if any.
    pub fn get_general_error(&self) -> Option<&anyhow::Error> {
        self.general.as_ref()
    }

    /// Get errors from different peers.
    pub fn get_peer_errors(&self) -> impl Iterator<Item = (PeerId, &ServerError)> {
        self.peer_errors.iter().map(|(peer, error)| (*peer, error))
    }

    pub fn any_peer_error_method_not_found(&self) -> bool {
        self.peer_errors
            .values()
            .any(|peer_err| matches!(peer_err, ServerError::InvalidRpcId(_)))
    }
}

#[derive(Debug, Error)]
pub enum OutputOutcomeError {
    #[error("Response deserialization error: {0}")]
    ResponseDeserialization(anyhow::Error),
    #[error("Federation error: {0}")]
    Federation(#[from] FederationError),
    #[error("Core error: {0}")]
    Core(#[from] anyhow::Error),
    #[error("Transaction rejected: {0}")]
    Rejected(String),
    #[error("Invalid output index {out_idx}, larger than {outputs_num} in the transaction")]
    InvalidVout { out_idx: u64, outputs_num: usize },
    #[error("Timeout reached after waiting {}s", .0.as_secs())]
    Timeout(Duration),
}

impl OutputOutcomeError {
    pub fn report_if_important(&self) {
        let important = match self {
            OutputOutcomeError::Federation(e) => {
                e.report_if_unusual("OutputOutcome");
                return;
            }
            OutputOutcomeError::Core(_)
            | OutputOutcomeError::InvalidVout { .. }
            | OutputOutcomeError::ResponseDeserialization(_) => true,
            OutputOutcomeError::Rejected(_) | OutputOutcomeError::Timeout(_) => false,
        };

        trace!(target: LOG_CLIENT_NET_API, error = %self, "OutputOutcomeError");

        if important {
            warn!(target: LOG_CLIENT_NET_API, error = %self, "Uncommon OutputOutcomeError");
        }
    }

    /// Was the transaction rejected (which is final)
    pub fn is_rejected(&self) -> bool {
        matches!(
            self,
            OutputOutcomeError::Rejected(_) | OutputOutcomeError::InvalidVout { .. }
        )
    }
}
