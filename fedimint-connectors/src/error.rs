use fedimint_core::PeerId;
use fedimint_core::util::SafeUrl;
use fedimint_logging::LOG_CLIENT_NET_API;
use thiserror::Error;
use tracing::{trace, warn};

/// An API request error when calling a single federation peer
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ServerError {
    /// The response payload was returned successfully but failed to be
    /// deserialized
    #[error("Response deserialization error: {0}")]
    ResponseDeserialization(anyhow::Error),

    /// The request was addressed to an invalid `peer_id`
    #[error("Invalid peer id: {peer_id}")]
    InvalidPeerId { peer_id: PeerId },

    /// The request was addressed to an invalid `url`
    #[error("Invalid peer url: {url}")]
    InvalidPeerUrl { url: SafeUrl, source: anyhow::Error },

    /// The endpoint specification for the peer is invalid (e.g. wrong url)
    #[error("Invalid endpoint")]
    InvalidEndpoint(anyhow::Error),

    /// Could not connect
    #[error("Connection failed: {0}")]
    Connection(anyhow::Error),

    /// Underlying transport failed, in some typical way
    #[error("Transport error: {0}")]
    Transport(anyhow::Error),

    /// The rpc id (e.g. jsonrpc method name) was not recognized by the peer
    ///
    /// This one is important and sometimes used to detect backward
    /// compatibility capabilities, so transports should properly support
    /// it.
    #[error("Invalid rpc id")]
    InvalidRpcId(anyhow::Error),

    /// Something about the request we've sent was wrong, should not typically
    /// happen
    #[error("Invalid request")]
    InvalidRequest(anyhow::Error),

    /// Something about the response was wrong, should not typically happen
    #[error("Invalid response: {0}")]
    InvalidResponse(anyhow::Error),

    /// Server returned an internal error, suggesting something is wrong with it
    #[error("Unspecified server error: {0}")]
    ServerError(anyhow::Error),

    /// Some condition on the response this not match
    ///
    /// Typically expected, and often used in `FilterMap` query strategy to
    /// reject responses that don't match some criteria.
    #[error("Unspecified condition error: {0}")]
    ConditionFailed(anyhow::Error),

    /// An internal client error
    ///
    /// Things that shouldn't happen (better than panicking), logical errors,
    /// malfunctions caused by internal issues.
    #[error("Unspecified internal client error: {0}")]
    InternalClientError(anyhow::Error),
}

impl ServerError {
    pub fn is_unusual(&self) -> bool {
        match self {
            ServerError::ResponseDeserialization(_)
            | ServerError::InvalidPeerId { .. }
            | ServerError::InvalidPeerUrl { .. }
            | ServerError::InvalidResponse(_)
            | ServerError::InvalidRpcId(_)
            | ServerError::InvalidRequest(_)
            | ServerError::InternalClientError(_)
            | ServerError::InvalidEndpoint(_)
            | ServerError::ServerError(_) => true,
            ServerError::Connection(_)
            | ServerError::Transport(_)
            | ServerError::ConditionFailed(_) => false,
        }
    }
    /// Report errors that are worth reporting
    ///
    /// The goal here is to avoid spamming logs with errors that happen commonly
    /// for all sorts of expected reasons, while printing ones that suggest
    /// there's a problem.
    pub fn report_if_unusual(&self, peer_id: PeerId, context: &str) {
        let unusual = self.is_unusual();

        trace!(target: LOG_CLIENT_NET_API, error = %self, %context, "ServerError");

        if unusual {
            warn!(target: LOG_CLIENT_NET_API, error = %self,%context, %peer_id, "Unusual ServerError");
        }
    }
}
