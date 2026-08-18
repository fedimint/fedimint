use super::{GatewayCheckResult, lnv1_gateway_check_result};
use crate::{
    FederationConnectivity, FederationStatusResponse, LightningModuleStatus, Lnv1RegistrationStatus,
};

#[test]
fn disconnected_federation_is_not_gateway_transport_failure() {
    let status = FederationStatusResponse::served(
        fedimint_core::config::FederationId::dummy(),
        FederationConnectivity::Disconnected,
        LightningModuleStatus::Supported {
            consensus_version: fedimint_core::module::ModuleConsensusVersion::new(2, 1),
            registration: Lnv1RegistrationStatus::GatewayManaged {
                configured: true,
                endpoints: std::collections::BTreeMap::new(),
            },
        },
        LightningModuleStatus::Absent {},
    );
    assert_eq!(
        lnv1_gateway_check_result(&status),
        GatewayCheckResult::Unknown
    );
}
