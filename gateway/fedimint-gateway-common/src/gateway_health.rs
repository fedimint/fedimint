use crate::{
    FederationConnectivity, FederationStatus, FederationStatusResponse, LightningModuleStatus,
};

/// Sanitized outcome of probing one currently registered gateway.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum GatewayProbeHealth {
    /// The gateway could not be reached.
    Unreachable,
    /// The gateway uses an unsupported status protocol or module version.
    Incompatible,
    /// The gateway predates the scoped status endpoint.
    UnknownLegacy,
    /// Current explicit evidence establishes healthy service.
    Healthy,
    /// Available evidence does not justify a stronger diagnosis.
    Indeterminate,
}

/// Aggregate health of one Lightning module generation's gateway registry.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum GatewayHealth {
    /// The federation configuration has no module of this generation.
    ModuleAbsent,
    /// The registry explicitly contains no registrations.
    NoRegistrations,
    /// LNv1 registrations exist, but all are expired.
    RegistrationsExpired,
    /// Every currently registered gateway is explicitly unreachable.
    GatewayUnreachable,
    /// Every currently registered gateway is explicitly incompatible.
    GatewayIncompatible,
    /// Every currently registered gateway lacks the scoped status endpoint.
    HealthUnknownLegacy,
    /// At least one currently registered gateway is explicitly healthy.
    Healthy,
    /// The available or mixed evidence does not justify another state.
    Indeterminate,
}

/// Reduces a decoded scoped gateway response for the requested module
/// generation to sanitized probe evidence.
fn gateway_probe_health<'a, R: 'a>(
    response: &'a FederationStatusResponse,
    module: impl FnOnce(&'a FederationStatus) -> Option<&'a LightningModuleStatus<R>>,
) -> GatewayProbeHealth {
    let Some(module) = module(response.status()) else {
        return GatewayProbeHealth::Indeterminate;
    };
    match module {
        LightningModuleStatus::Absent {} => GatewayProbeHealth::Indeterminate,
        LightningModuleStatus::Supported { .. } => match response.status() {
            FederationStatus::Served {
                connectivity: FederationConnectivity::Connected,
                ..
            } => GatewayProbeHealth::Healthy,
            FederationStatus::Served {
                connectivity:
                    FederationConnectivity::Degraded | FederationConnectivity::Disconnected,
                ..
            }
            | FederationStatus::Unserved => GatewayProbeHealth::Indeterminate,
        },
    }
}

/// Reduces a decoded scoped response to LNv1 probe evidence.
pub fn lnv1_gateway_probe_health(response: &FederationStatusResponse) -> GatewayProbeHealth {
    gateway_probe_health(response, |status| match status {
        FederationStatus::Unserved => None,
        FederationStatus::Served { lnv1, .. } => Some(lnv1),
    })
}

/// Reduces a decoded scoped response to LNv2 probe evidence.
pub fn lnv2_gateway_probe_health(response: &FederationStatusResponse) -> GatewayProbeHealth {
    gateway_probe_health(response, |status| match status {
        FederationStatus::Unserved => None,
        FederationStatus::Served { lnv2, .. } => Some(lnv2),
    })
}

#[cfg(test)]
mod tests;
