use std::collections::BTreeMap;

use fedimint_core::config::FederationId;
use fedimint_core::module::ModuleConsensusVersion;
use serde::{Deserialize, Deserializer, Serialize};

use crate::RegisteredProtocol;

/// Public gateway endpoint for federation-scoped capability and health queries.
///
/// Clients send an unauthenticated HTTP or Iroh `POST` containing
/// `{"federation_id":"<hex federation id>"}`. The reply contains the echoed
/// `federation_id` and a `federation_status` tagged as `served` or `unserved`.
/// A served response also contains sanitized connectivity and independently
/// tagged `lnv1` and `lnv2` module states.
///
/// Identifies the federation whose gateway status should be reported.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub struct FederationStatusRequest {
    /// Federation to inspect.
    pub federation_id: FederationId,
}

/// Sanitized health of one gateway connection to one requested federation.
///
/// This protocol is public over the gateway's HTTP and Iroh transports. It
/// reports only the exact federation ID supplied by the caller; the
/// authenticated `/info` endpoint remains the only global federation inventory.
/// A configured gateway returns [`FederationStatus::Unserved`] instead of `404`
/// for an unknown federation.
///
/// The tagged enums make valid combinations explicit: unserved responses have
/// no connectivity or module claims, and registration exists only for supported
/// modules. Supported LNv1 uses [`Lnv1RegistrationStatus::GatewayManaged`];
/// supported LNv2 uses [`Lnv2RegistrationStatus::FederationManaged`]. Other
/// pairings are invalid.
#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct FederationStatusResponse {
    /// Echo of the federation identifier supplied by the caller.
    federation_id: FederationId,
    /// Whether the requested federation is served, and its status when served.
    #[serde(flatten)]
    status: FederationStatus,
}

impl FederationStatusResponse {
    /// Constructs a response for a federation this gateway does not serve.
    pub fn unserved(federation_id: FederationId) -> Self {
        Self {
            federation_id,
            status: FederationStatus::Unserved,
        }
    }

    /// Constructs a response for a served federation.
    pub fn served(
        federation_id: FederationId,
        connectivity: FederationConnectivity,
        lnv1: LightningModuleStatus<Lnv1RegistrationStatus>,
        lnv2: LightningModuleStatus<Lnv2RegistrationStatus>,
    ) -> Self {
        Self {
            federation_id,
            status: FederationStatus::Served {
                connectivity,
                lnv1,
                lnv2,
            },
        }
    }

    /// Returns the federation named by this response.
    pub fn federation_id(&self) -> FederationId {
        self.federation_id
    }

    /// Returns the validated scoped status.
    pub fn status(&self) -> &FederationStatus {
        &self.status
    }
}

#[derive(Deserialize)]
#[serde(
    tag = "federation_status",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum FederationStatusResponseWire {
    Unserved {
        federation_id: FederationId,
    },
    Served {
        federation_id: FederationId,
        connectivity: FederationConnectivity,
        lnv1: LightningModuleStatus<Lnv1RegistrationStatus>,
        lnv2: LightningModuleStatus<Lnv2RegistrationStatus>,
    },
}

impl<'de> Deserialize<'de> for FederationStatusResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(
            match FederationStatusResponseWire::deserialize(deserializer)? {
                FederationStatusResponseWire::Unserved { federation_id } => {
                    Self::unserved(federation_id)
                }
                FederationStatusResponseWire::Served {
                    federation_id,
                    connectivity,
                    lnv1,
                    lnv2,
                } => Self::served(federation_id, connectivity, lnv1, lnv2),
            },
        )
    }
}

/// Whether this gateway serves the exact requested federation.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "federation_status",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum FederationStatus {
    /// This gateway has no loaded client for the requested federation.
    Unserved,
    /// This gateway has a loaded client and can report its scoped status.
    Served {
        /// Aggregated current connection-pool state, not an active reachability
        /// probe.
        connectivity: FederationConnectivity,
        /// Gateway support and registration health for the federation's LNv1
        /// module.
        lnv1: LightningModuleStatus<Lnv1RegistrationStatus>,
        /// Gateway support and registration health for the federation's LNv2
        /// module.
        lnv2: LightningModuleStatus<Lnv2RegistrationStatus>,
    },
}

/// Aggregated gateway-to-federation connectivity without guardian details.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FederationConnectivity {
    /// No guardian connection is currently live.
    Disconnected,
    /// Some guardian connections are live, but fewer than the federation
    /// threshold.
    Degraded,
    /// Enough guardian connections are live to satisfy the federation
    /// threshold.
    Connected,
}

/// Coherent module presence and registration state.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "module_status", rename_all = "snake_case", deny_unknown_fields)]
pub enum LightningModuleStatus<R> {
    /// The federation configuration does not contain this module generation.
    Absent {},
    /// The gateway initialized the module.
    Supported {
        /// Module consensus version declared by the federation.
        consensus_version: ModuleConsensusVersion,
        /// How gateway discovery is configured for this module.
        registration: R,
    },
}

/// Gateway-managed discovery state for a supported LNv1 module.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum Lnv1RegistrationStatus {
    /// The gateway periodically advertises its configured LNv1 transports.
    GatewayManaged {
        /// Whether the gateway and federation configuration allow registration.
        configured: bool,
        /// Per-transport results retained from registration attempts.
        endpoints: BTreeMap<RegisteredProtocol, RegistrationEndpointStatus>,
    },
}

/// Federation-managed discovery state for a supported LNv2 module.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum Lnv2RegistrationStatus {
    /// Federation administrators configure LNv2 gateway URLs; there is no
    /// gateway TTL.
    FederationManaged,
}

/// Sanitized retained registration state for one public gateway transport.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct RegistrationEndpointStatus {
    /// Completed attempt with the newest begin-order observed by this process.
    ///
    /// This is absent before the first attempt after startup.
    pub last_attempt: Option<RegistrationAttempt>,
    /// Approximate remaining lifetime of the successful LNv1 announcement with
    /// the newest begin-order.
    ///
    /// This is absent before the first success and zero after that announcement
    /// expires. A later failed refresh does not erase an earlier valid TTL.
    pub advertised_ttl_remaining_secs: Option<u64>,
}

/// One completed, sanitized gateway registration attempt.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct RegistrationAttempt {
    /// Unix timestamp when the attempt completed.
    pub completed_at_unix_secs: u64,
    /// Finite, detail-free result of the attempt.
    pub result: RegistrationAttemptResult,
}

/// Sanitized result of a gateway registration attempt.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationAttemptResult {
    /// The federation accepted the registration request.
    Succeeded,
    /// The registration request failed without exposing internal details.
    Failed,
}

#[cfg(test)]
mod tests;
