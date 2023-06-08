use std::time::Duration;

use fedimint_client::sm::{OperationId, State, StateTransition};
use fedimint_client::DynGlobalClientContext;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::task::sleep;
use fedimint_ln_common::api::LnFederationApi;
use fedimint_ln_common::LightningGateway;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::error;
use url::Url;

use super::GatewayClientContext;

#[cfg_attr(doc, aquamarine::aquamarine)]
/// State machine that registers the lightning gateway with
/// the federation.
///
/// ```mermaid
/// graph LR
/// classDef virtual fill:#fff,stroke-dasharray: 5 5
///
///    Register -- register lightning gateway succeeded --> WaitForTTL
///    Register -- register lightning gateway failed --> Register
///    WaitForTTL -- wait for time to live to expire --> Register
/// ```
#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub enum GatewayRegisterStates {
    Register(RegisterGateway),
    WaitForTTL(WaitForTimeToLive),
}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub struct GatewayRegisterCommon {
    pub operation_id: OperationId,
    pub time_to_live: Duration,
    pub registration_info: LightningGateway,
}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub struct GatewayRegisterStateMachine {
    pub common: GatewayRegisterCommon,
    pub state: GatewayRegisterStates,
}

impl State for GatewayRegisterStateMachine {
    type ModuleContext = GatewayClientContext;
    type GlobalContext = DynGlobalClientContext;

    fn transitions(
        &self,
        _context: &Self::ModuleContext,
        global_context: &Self::GlobalContext,
    ) -> Vec<fedimint_client::sm::StateTransition<Self>> {
        match &self.state {
            GatewayRegisterStates::Register(register_gateway) => {
                register_gateway.transitions(global_context.clone(), self.common.clone())
            }
            GatewayRegisterStates::WaitForTTL(wait_for_ttl) => {
                wait_for_ttl.transitions(self.common.clone())
            }
        }
    }

    fn operation_id(&self) -> fedimint_client::sm::OperationId {
        self.common.operation_id
    }
}

#[derive(Error, Debug, Serialize, Deserialize, Encodable, Decodable, Clone, Eq, PartialEq)]
pub enum GatewayRegistrationError {
    #[error("Error registering the Lightning Gateway. Gateway API: {api:?}")]
    RegistrationError { api: Url },
}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub struct RegisterGateway;

impl RegisterGateway {
    fn transitions(
        &self,
        global_context: DynGlobalClientContext,
        common: GatewayRegisterCommon,
    ) -> Vec<StateTransition<GatewayRegisterStateMachine>> {
        vec![StateTransition::new(
            Self::await_register_with_federation(global_context, common.clone()),
            move |_dbtx, res, _| {
                Box::pin(Self::transition_register_federation(res, common.clone()))
            },
        )]
    }

    async fn await_register_with_federation(
        global_context: DynGlobalClientContext,
        common: GatewayRegisterCommon,
    ) -> Result<(), GatewayRegistrationError> {
        global_context
            .module_api()
            .register_gateway(&common.registration_info)
            .await
            .map_err(|_| GatewayRegistrationError::RegistrationError {
                api: common.registration_info.api,
            })
    }

    async fn transition_register_federation(
        result: Result<(), GatewayRegistrationError>,
        common: GatewayRegisterCommon,
    ) -> GatewayRegisterStateMachine {
        if result.is_err() {
            error!("{result:?}");

            // Briefly wait and then try again
            sleep(Duration::from_secs(15)).await;
            return GatewayRegisterStateMachine {
                common,
                state: GatewayRegisterStates::Register(RegisterGateway {}),
            };
        }

        GatewayRegisterStateMachine {
            common,
            state: GatewayRegisterStates::WaitForTTL(WaitForTimeToLive {}),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub struct WaitForTimeToLive;

impl WaitForTimeToLive {
    fn transitions(
        &self,
        common: GatewayRegisterCommon,
    ) -> Vec<StateTransition<GatewayRegisterStateMachine>> {
        let ttl = common.time_to_live;
        vec![StateTransition::new(sleep(ttl), move |_, _, _| {
            Box::pin(Self::transition_wait_for_ttl(common.clone()))
        })]
    }

    async fn transition_wait_for_ttl(common: GatewayRegisterCommon) -> GatewayRegisterStateMachine {
        GatewayRegisterStateMachine {
            common,
            state: GatewayRegisterStates::Register(RegisterGateway {}),
        }
    }
}
