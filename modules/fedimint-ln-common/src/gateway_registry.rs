use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize};

use crate::LightningGatewayAnnouncement;

/// Current LNv1 registry-evidence wire protocol.
pub const LNV1_REGISTRY_EVIDENCE_PROTOCOL_VERSION: u32 = 1;

/// Compatibility outcome for the additive `LNv1` registry-evidence endpoint.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Lnv1RegistryEvidenceCompatibility {
    /// At least one peer predates the endpoint, including a mixed rollout.
    UnknownLegacy,
    /// The federation returned an unsupported evidence protocol.
    Incompatible {
        /// Unsupported protocol version.
        protocol_version: u32,
    },
    /// The federation returned coherent current-version evidence.
    Compatible(Lnv1RegistryEvidenceV1),
}

/// Versioned LNv1 registry snapshot returned by federation peers.
#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct Lnv1RegistryEvidenceV1 {
    /// Wire protocol version.
    protocol_version: u32,
    /// Current, non-expired registrations, preserving existing list semantics.
    registrations: Vec<LightningGatewayAnnouncement>,
    /// Sanitized registry health at snapshot time.
    state: Lnv1RegistryState,
}

#[derive(Deserialize)]
struct Lnv1RegistryEvidenceWire {
    protocol_version: u32,
    registrations: Vec<LightningGatewayAnnouncement>,
    state: Lnv1RegistryState,
}

impl<'de> Deserialize<'de> for Lnv1RegistryEvidenceV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = Lnv1RegistryEvidenceWire::deserialize(deserializer)?;
        let evidence = Self {
            protocol_version: wire.protocol_version,
            registrations: wire.registrations,
            state: wire.state,
        };
        if !evidence.is_coherent() {
            return Err(D::Error::custom(
                "unsupported or contradictory LNv1 registry evidence",
            ));
        }
        Ok(evidence)
    }
}

impl Lnv1RegistryEvidenceV1 {
    /// Constructs a snapshot proving that no registration records exist.
    pub fn no_registrations() -> Self {
        Self {
            protocol_version: LNV1_REGISTRY_EVIDENCE_PROTOCOL_VERSION,
            registrations: vec![],
            state: Lnv1RegistryState::NoRegistrations,
        }
    }

    /// Constructs a snapshot proving that registration records all expired.
    pub fn registrations_expired() -> Self {
        Self {
            protocol_version: LNV1_REGISTRY_EVIDENCE_PROTOCOL_VERSION,
            registrations: vec![],
            state: Lnv1RegistryState::RegistrationsExpired,
        }
    }

    /// Constructs a snapshot containing current registrations.
    pub fn registrations_current(registrations: Vec<LightningGatewayAnnouncement>) -> Option<Self> {
        (!registrations.is_empty()).then_some(Self {
            protocol_version: LNV1_REGISTRY_EVIDENCE_PROTOCOL_VERSION,
            registrations,
            state: Lnv1RegistryState::RegistrationsCurrent,
        })
    }

    fn is_coherent(&self) -> bool {
        self.protocol_version == LNV1_REGISTRY_EVIDENCE_PROTOCOL_VERSION
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

    /// Returns the sanitized registry state.
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

/// Sanitized LNv1 registry state with its TTL semantics preserved.
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
