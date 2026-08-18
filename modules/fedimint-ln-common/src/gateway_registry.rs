use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize};

use crate::LightningGatewayAnnouncement;

/// Current `LNv1` registry snapshot format.
pub const LNV1_REGISTRY_SNAPSHOT_VERSION: u32 = 1;

/// Result of querying every guardian for the `LNv1` registry snapshot.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Lnv1RegistrySnapshotResult {
    /// At least one peer predates the endpoint, including a mixed rollout.
    EndpointUnavailable,
    /// The federation returned an unsupported snapshot version.
    UnsupportedVersion {
        /// Unsupported protocol version.
        protocol_version: u32,
    },
    /// The federation returned a valid current-version snapshot.
    Snapshot(Lnv1RegistrySnapshotV1),
}

/// Versioned `LNv1` registry snapshot returned by federation peers.
#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct Lnv1RegistrySnapshotV1 {
    /// Snapshot format version.
    protocol_version: u32,
    /// Current, non-expired registrations, preserving existing list semantics.
    registrations: Vec<LightningGatewayAnnouncement>,
    /// Registry state at snapshot time.
    state: Lnv1RegistryState,
}

#[derive(Deserialize)]
struct Lnv1RegistrySnapshotFields {
    protocol_version: u32,
    registrations: Vec<LightningGatewayAnnouncement>,
    state: Lnv1RegistryState,
}

impl<'de> Deserialize<'de> for Lnv1RegistrySnapshotV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = Lnv1RegistrySnapshotFields::deserialize(deserializer)?;
        let snapshot = Self {
            protocol_version: wire.protocol_version,
            registrations: wire.registrations,
            state: wire.state,
        };
        if !snapshot.has_valid_fields() {
            return Err(D::Error::custom(
                "unsupported or contradictory LNv1 registry snapshot",
            ));
        }
        Ok(snapshot)
    }
}

impl Lnv1RegistrySnapshotV1 {
    /// Constructs a snapshot for a registry with no records.
    pub fn no_registrations() -> Self {
        Self {
            protocol_version: LNV1_REGISTRY_SNAPSHOT_VERSION,
            registrations: vec![],
            state: Lnv1RegistryState::NoRegistrations,
        }
    }

    /// Constructs a snapshot for a registry where every record has expired.
    pub fn registrations_expired() -> Self {
        Self {
            protocol_version: LNV1_REGISTRY_SNAPSHOT_VERSION,
            registrations: vec![],
            state: Lnv1RegistryState::RegistrationsExpired,
        }
    }

    /// Constructs a snapshot containing current registrations.
    pub fn registrations_current(registrations: Vec<LightningGatewayAnnouncement>) -> Option<Self> {
        (!registrations.is_empty()).then_some(Self {
            protocol_version: LNV1_REGISTRY_SNAPSHOT_VERSION,
            registrations,
            state: Lnv1RegistryState::RegistrationsCurrent,
        })
    }

    fn has_valid_fields(&self) -> bool {
        self.protocol_version == LNV1_REGISTRY_SNAPSHOT_VERSION
            && match self.state {
                Lnv1RegistryState::NoRegistrations | Lnv1RegistryState::RegistrationsExpired => {
                    self.registrations.is_empty()
                }
                Lnv1RegistryState::RegistrationsCurrent => !self.registrations.is_empty(),
            }
    }

    /// Returns the current wire protocol version.
    pub fn protocol_version(&self) -> u32 {
        self.protocol_version
    }

    /// Returns the registry state.
    pub fn state(&self) -> Lnv1RegistryState {
        self.state
    }

    /// Returns the current non-expired registrations.
    pub fn registrations(&self) -> &[LightningGatewayAnnouncement] {
        &self.registrations
    }

    /// Consumes the snapshot and returns its current registrations.
    pub fn into_registrations(self) -> Vec<LightningGatewayAnnouncement> {
        self.registrations
    }
}

/// `LNv1` registry state, including whether stored records have expired.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Lnv1RegistryState {
    /// No registration records exist.
    NoRegistrations,
    /// Records exist, but every registration has expired.
    RegistrationsExpired,
    /// At least one non-expired registration exists.
    RegistrationsCurrent,
}

#[cfg(test)]
mod tests;
