use crate::{
    FederationConnectivity, FederationStatus, FederationStatusResponse, LightningModuleStatus,
};

/// Result of checking one currently registered gateway.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum GatewayCheckResult {
    /// The gateway could not be reached.
    Unreachable,
    /// The gateway predates the status endpoint for one federation.
    EndpointUnavailable,
    /// The gateway serves this federation and is connected to it.
    Healthy,
    /// The check did not establish another result.
    Unknown,
}

/// Health of the gateways registered for one Lightning module generation.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum GatewayHealth {
    /// The federation configuration has no module of this generation.
    ModuleAbsent,
    /// The registry contains no registrations.
    NoRegistrations,
    /// `LNv1` registrations exist, but all are expired.
    RegistrationsExpired,
    /// Every currently registered gateway is unreachable.
    GatewayUnreachable,
    /// Every currently registered gateway lacks the status endpoint for one
    /// federation.
    GatewayStatusUnavailable,
    /// At least one currently registered gateway is healthy.
    Healthy,
    /// The registry query or gateway checks did not establish another state.
    Unknown,
}

/// Converts a gateway response into the result for one Lightning generation.
fn gateway_check_result<'a, R: 'a>(
    response: &'a FederationStatusResponse,
    module: impl FnOnce(&'a FederationStatus) -> Option<&'a LightningModuleStatus<R>>,
) -> GatewayCheckResult {
    let Some(module) = module(response.status()) else {
        return GatewayCheckResult::Unknown;
    };
    match module {
        LightningModuleStatus::Absent {} => GatewayCheckResult::Unknown,
        LightningModuleStatus::Supported { .. } => match response.status() {
            FederationStatus::Served {
                connectivity: FederationConnectivity::Connected,
                ..
            } => GatewayCheckResult::Healthy,
            FederationStatus::Served {
                connectivity:
                    FederationConnectivity::Degraded | FederationConnectivity::Disconnected,
                ..
            }
            | FederationStatus::Unserved => GatewayCheckResult::Unknown,
        },
    }
}

/// Returns the `LNv1` result from a gateway response.
pub fn lnv1_gateway_check_result(response: &FederationStatusResponse) -> GatewayCheckResult {
    gateway_check_result(response, |status| match status {
        FederationStatus::Unserved => None,
        FederationStatus::Served { lnv1, .. } => Some(lnv1),
    })
}

/// Returns the `LNv2` result from a gateway response.
pub fn lnv2_gateway_check_result(response: &FederationStatusResponse) -> GatewayCheckResult {
    gateway_check_result(response, |status| match status {
        FederationStatus::Unserved => None,
        FederationStatus::Served { lnv2, .. } => Some(lnv2),
    })
}

#[cfg(test)]
mod tests;
