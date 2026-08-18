use fedimint_core::util::SafeUrl;
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize};

/// Current `LNv2` registry snapshot format.
pub const LNV2_REGISTRY_SNAPSHOT_VERSION: u32 = 1;

/// Result of querying every guardian for the `LNv2` registry snapshot.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Lnv2RegistrySnapshotResult {
    /// At least one peer predates the endpoint, including a mixed rollout.
    EndpointUnavailable,
    /// The federation returned an unsupported snapshot version.
    UnsupportedVersion {
        /// Unsupported protocol version.
        protocol_version: u32,
    },
    /// The federation returned a valid current-version snapshot.
    Snapshot(Lnv2RegistrySnapshotV1),
}

/// Versioned `LNv2` registry snapshot returned by federation peers.
///
/// `LNv2` registrations have no TTL, so this type deliberately carries no
/// expiration timestamp or expired state.
#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct Lnv2RegistrySnapshotV1 {
    /// Snapshot format version.
    protocol_version: u32,
    /// Registered gateway API URLs, preserving existing list semantics.
    registrations: Vec<SafeUrl>,
    /// Registry state at snapshot time.
    state: Lnv2RegistryState,
}

#[derive(Deserialize)]
struct Lnv2RegistrySnapshotFields {
    protocol_version: u32,
    registrations: Vec<SafeUrl>,
    state: Lnv2RegistryState,
}

impl<'de> Deserialize<'de> for Lnv2RegistrySnapshotV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = Lnv2RegistrySnapshotFields::deserialize(deserializer)?;
        let snapshot = Self {
            protocol_version: wire.protocol_version,
            registrations: wire.registrations,
            state: wire.state,
        };
        if !snapshot.has_valid_fields() {
            return Err(D::Error::custom(
                "unsupported or contradictory LNv2 registry snapshot",
            ));
        }
        Ok(snapshot)
    }
}

impl Lnv2RegistrySnapshotV1 {
    /// Constructs a valid current-version registry snapshot.
    pub fn new(registrations: Vec<SafeUrl>) -> Self {
        let state = if registrations.is_empty() {
            Lnv2RegistryState::NoRegistrations
        } else {
            Lnv2RegistryState::RegistrationsCurrent
        };
        Self {
            protocol_version: LNV2_REGISTRY_SNAPSHOT_VERSION,
            registrations,
            state,
        }
    }

    fn has_valid_fields(&self) -> bool {
        self.protocol_version == LNV2_REGISTRY_SNAPSHOT_VERSION
            && match self.state {
                Lnv2RegistryState::NoRegistrations => self.registrations.is_empty(),
                Lnv2RegistryState::RegistrationsCurrent => !self.registrations.is_empty(),
            }
    }

    /// Returns the current wire protocol version.
    pub fn protocol_version(&self) -> u32 {
        self.protocol_version
    }

    /// Returns the registry state.
    pub fn state(&self) -> Lnv2RegistryState {
        self.state
    }

    /// Returns the registered gateway API URLs.
    pub fn registrations(&self) -> &[SafeUrl] {
        &self.registrations
    }

    /// Consumes the snapshot and returns the registered gateway API URLs.
    pub fn into_registrations(self) -> Vec<SafeUrl> {
        self.registrations
    }
}

/// `LNv2` registry state. `LNv2` registrations do not expire.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Lnv2RegistryState {
    /// No gateway URL is registered.
    NoRegistrations,
    /// At least one gateway URL is registered.
    RegistrationsCurrent,
}

#[cfg(test)]
mod tests;
