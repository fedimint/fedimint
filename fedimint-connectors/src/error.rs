use fedimint_core::PeerId;
use fedimint_core::util::SafeUrl;
use fedimint_logging::LOG_CLIENT_NET_API;
use thiserror::Error;
use tracing::{trace, warn};

/// A failure to build a connector, or to reach a gateway through one.
///
/// Peer (guardian) requests report [`ServerError`] instead; this type covers
/// the connector layer underneath it.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ConnectorError {
    /// No connector is registered for the url's scheme.
    #[error("Unsupported scheme {scheme}; missing endpoint handler")]
    UnsupportedScheme { scheme: String },

    /// The connector for this scheme was switched off when the registry was
    /// built.
    #[error("The {scheme} connector is not enabled")]
    NotEnabled { scheme: &'static str },

    /// Tor routing was requested from a build that has no Tor support.
    #[error("Tor was requested, but support for it is not compiled in")]
    TorNotCompiledIn,

    /// This transport can reach guardians but not gateways.
    #[error("This transport cannot connect to a gateway")]
    GatewayUnsupported,

    /// The url carries no host to address.
    #[error("Missing host in url {url}")]
    MissingHost { url: SafeUrl },

    /// The url's host is not a valid Iroh node id.
    #[error("Invalid Iroh node id {host}")]
    InvalidNodeId {
        host: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// The url could not be parsed.
    #[error("Invalid url {url}")]
    InvalidUrl {
        url: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// The Iroh api url path selects a wire version this build does not know.
    #[error("Unsupported Iroh api url path {path}")]
    UnsupportedUrlPath { path: String },

    /// The transport refused the connection or failed to start.
    #[error("Transport failure")]
    Transport(#[source] Box<dyn std::error::Error + Send + Sync>),

    /// The Tor client could not be bootstrapped.
    #[error("Failed to bootstrap the Tor client")]
    Tor(#[source] Box<dyn std::error::Error + Send + Sync>),
}

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
