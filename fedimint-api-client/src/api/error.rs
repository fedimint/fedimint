use std::collections::BTreeMap;
use std::fmt::{self, Debug, Display};
use std::time::Duration;

use fedimint_core::fmt_utils::AbbreviateJson;
use fedimint_core::util::FmtCompactAnyhow as _;
use fedimint_core::PeerId;
use fedimint_logging::LOG_CLIENT_NET_API;
use jsonrpsee_core::client::Error as JsonRpcClientError;
use jsonrpsee_types::error::METHOD_NOT_FOUND_CODE;
#[cfg(target_family = "wasm")]
use jsonrpsee_wasm_client::{Client as WsClient, WasmClientBuilder as WsClientBuilder};
use serde::Serialize;
use thiserror::Error;
use tracing::{error, trace, warn};

/// An API request error when calling a single federation peer
#[derive(Debug, Error)]
pub enum PeerError {
    #[error("Response deserialization error: {0}")]
    ResponseDeserialization(anyhow::Error),
    #[error("Invalid peer id: {peer_id}")]
    InvalidPeerId { peer_id: PeerId },
    #[error("Rpc error: {0}")]
    Rpc(#[from] JsonRpcClientError),
    #[error("Invalid response: {0}")]
    InvalidResponse(String),
}

impl PeerError {
    /// Report errors that are worth reporting
    ///
    /// The goal here is to avoid spamming logs with errors that happen commonly
    /// for all sorts of expected reasons, while printing ones that suggest
    /// there's a problem.
    pub fn report_if_important(&self, peer_id: PeerId) {
        let important = match self {
            PeerError::ResponseDeserialization(_)
            | PeerError::InvalidPeerId { .. }
            | PeerError::InvalidResponse(_) => true,
            PeerError::Rpc(rpc_e) => match rpc_e {
                // TODO: Does this cover all retryable cases?
                JsonRpcClientError::Transport(_) | JsonRpcClientError::RequestTimeout => false,
                JsonRpcClientError::RestartNeeded(_)
                | JsonRpcClientError::Call(_)
                | JsonRpcClientError::ParseError(_)
                | JsonRpcClientError::InvalidSubscriptionId
                | JsonRpcClientError::InvalidRequestId(_)
                | JsonRpcClientError::Custom(_)
                | JsonRpcClientError::HttpNotImplemented
                | JsonRpcClientError::EmptyBatchRequest(_)
                | JsonRpcClientError::RegisterMethod(_) => true,
            },
        };

        trace!(target: LOG_CLIENT_NET_API, error = %self, "PeerError");

        if important {
            warn!(target: LOG_CLIENT_NET_API, error = %self, %peer_id, "Unusual PeerError");
        }
    }
}

/// An API request error when calling an entire federation
///
/// Generally all Federation errors are retryable.
#[derive(Debug, Error)]
pub struct FederationError {
    pub method: String,
    pub params: serde_json::Value,
    pub general: Option<anyhow::Error>,
    pub peer_errors: BTreeMap<PeerId, PeerError>,
}

impl Display for FederationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Federation rpc error {")?;
        if let Some(general) = self.general.as_ref() {
            f.write_fmt(format_args!("method => {}, ", self.method))?;
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
            f.write_fmt(format_args!("{peer} => {e})"))?;
            if i == self.peer_errors.len() - 1 {
                f.write_str(", ")?;
            }
        }
        f.write_str("}")?;
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
        peer_errors: BTreeMap<PeerId, PeerError>,
    ) -> Self {
        use std::fmt::Write;
        let general_fmt = peer_errors
            .iter()
            .fold(String::new(), |mut s, (peer_id, e)| {
                if !s.is_empty() {
                    write!(s, ", ").expect("can't fail");
                }
                write!(s, "peer-{peer_id}: {e}").expect("can't fail");

                s
            });

        Self {
            method: method.into(),
            params: serde_json::to_value(params).unwrap_or_default(),
            general: Some(anyhow::anyhow!("Received errors from peers: {general_fmt}",)),
            peer_errors,
        }
    }

    pub fn new_one_peer(
        peer_id: PeerId,
        method: impl Into<String>,
        params: impl Serialize,
        error: PeerError,
    ) -> Self {
        Self {
            method: method.into(),
            params: serde_json::to_value(params).expect("Serialization of valid params won't fail"),
            general: None,
            peer_errors: [(peer_id, error)].into_iter().collect(),
        }
    }

    /// Report any errors
    pub fn report_if_important(&self) {
        if let Some(error) = self.general.as_ref() {
            warn!(target: LOG_CLIENT_NET_API, err = %error.fmt_compact_anyhow(), "General FederationError");
        }
        for (peer_id, e) in &self.peer_errors {
            e.report_if_important(*peer_id);
        }
    }

    /// Get the general error if any.
    pub fn get_general_error(&self) -> Option<&anyhow::Error> {
        self.general.as_ref()
    }

    /// Get errors from different peers.
    pub fn get_peer_errors(&self) -> impl Iterator<Item = (PeerId, &PeerError)> {
        self.peer_errors.iter().map(|(peer, error)| (*peer, error))
    }

    pub fn any_peer_error_method_not_found(&self) -> bool {
        self.peer_errors.values().any(|peer_err| {
            matches!(
                peer_err,
                PeerError::Rpc(JsonRpcClientError::Call(err)) if err.code() == METHOD_NOT_FOUND_CODE
            )
        })
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
                e.report_if_important();
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
