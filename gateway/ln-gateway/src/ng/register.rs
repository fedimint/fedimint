use std::cmp::Ordering;
use std::time::Duration;

use fedimint_client::sm::{ClientSMDatabaseTransaction, OperationId, State, StateTransition};
use fedimint_client::DynGlobalClientContext;
use fedimint_core::config::FederationId;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::task::sleep;
use fedimint_ln_common::api::LnFederationApi;
use fedimint_ln_common::LightningGateway;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::error;
use url::Url;

use super::{GatewayClientContext, INITIAL_REGISTER_BACKOFF_DURATION};
use crate::db::FederationRegistrationKey;

#[cfg_attr(doc, aquamarine::aquamarine)]
/// State machine that registers the lightning gateway with
/// the federation.
///
/// ```mermaid
/// graph LR
/// classDef virtual fill:#fff,stroke-dasharray: 5 5
///
///    Register -- register gateway with federation succeeded --> WaitForTTL
///    Register -- register gateway with federation failed --> FailureBackoff
///    FailureBackoff -- wait for backoff duration --> Register
///    WaitForTTL -- wait for time to live to expire and `LightningGateway` has not changed --> Register
///    WaitForTTL -- wait for time to live to expire and `LightningGateway` has changed --> Done
/// ```
#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub enum RegisterWithFederationStates {
    Register(RegisterWithFederation),
    WaitForTTL(WaitForTimeToLive),
    FailureBackoff(FailureBackoff),
    Done,
}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub struct RegisterWithFederationCommon {
    pub operation_id: OperationId,
    pub time_to_live: Duration,
    pub registration_info: LightningGateway,
    pub federation_id: FederationId,
}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub struct RegisterWithFederationStateMachine {
    pub common: RegisterWithFederationCommon,
    pub state: RegisterWithFederationStates,
}

impl State for RegisterWithFederationStateMachine {
    type ModuleContext = GatewayClientContext;
    type GlobalContext = DynGlobalClientContext;

    fn transitions(
        &self,
        _context: &Self::ModuleContext,
        global_context: &Self::GlobalContext,
    ) -> Vec<fedimint_client::sm::StateTransition<Self>> {
        match &self.state {
            RegisterWithFederationStates::Register(register_gateway) => {
                register_gateway.transitions(global_context.clone(), self.common.clone())
            }
            RegisterWithFederationStates::WaitForTTL(wait_for_ttl) => {
                wait_for_ttl.transitions(self.common.clone())
            }
            RegisterWithFederationStates::FailureBackoff(failure_backoff) => {
                failure_backoff.transitions(self.common.clone())
            }
            RegisterWithFederationStates::Done => {
                vec![]
            }
        }
    }

    fn operation_id(&self) -> fedimint_client::sm::OperationId {
        self.common.operation_id
    }
}

#[derive(Error, Debug, Serialize, Deserialize, Encodable, Decodable, Clone, Eq, PartialEq)]
pub enum RegisterWithFederationError {
    #[error("Error registering the Lightning Gateway. Gateway API: {api:?}")]
    RegistrationError { api: Url },
}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub struct RegisterWithFederation {
    pub backoff_duration: Duration,
}

impl RegisterWithFederation {
    fn transitions(
        &self,
        global_context: DynGlobalClientContext,
        common: RegisterWithFederationCommon,
    ) -> Vec<StateTransition<RegisterWithFederationStateMachine>> {
        let backoff_duration = self.backoff_duration;
        vec![StateTransition::new(
            Self::await_register_with_federation(global_context, common.clone()),
            move |dbtx, res, _| {
                Box::pin(Self::transition_register_federation(
                    res,
                    common.clone(),
                    dbtx,
                    backoff_duration,
                ))
            },
        )]
    }

    async fn await_register_with_federation(
        global_context: DynGlobalClientContext,
        common: RegisterWithFederationCommon,
    ) -> Result<(), RegisterWithFederationError> {
        global_context
            .module_api()
            .register_gateway(&common.registration_info)
            .await
            .map_err(|_| RegisterWithFederationError::RegistrationError {
                api: common.registration_info.api,
            })
    }

    async fn transition_register_federation(
        result: Result<(), RegisterWithFederationError>,
        common: RegisterWithFederationCommon,
        dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
        backoff_duration: Duration,
    ) -> RegisterWithFederationStateMachine {
        if result.is_err() {
            error!("{result:?}");

            return RegisterWithFederationStateMachine {
                common,
                state: RegisterWithFederationStates::FailureBackoff(FailureBackoff {
                    backoff_duration,
                }),
            };
        }

        let mut dbtx = dbtx.module_tx();
        dbtx.insert_entry(
            &FederationRegistrationKey {
                id: common.federation_id,
            },
            &common.registration_info,
        )
        .await;

        RegisterWithFederationStateMachine {
            common,
            state: RegisterWithFederationStates::WaitForTTL(WaitForTimeToLive {}),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub struct FailureBackoff {
    backoff_duration: Duration,
}

impl FailureBackoff {
    fn transitions(
        &self,
        common: RegisterWithFederationCommon,
    ) -> Vec<StateTransition<RegisterWithFederationStateMachine>> {
        let backoff_duration = self.backoff_duration;
        vec![StateTransition::new(
            sleep(self.backoff_duration),
            move |_, _, _| {
                Box::pin(Self::transition_failure_backoff(
                    backoff_duration,
                    common.clone(),
                ))
            },
        )]
    }

    async fn transition_failure_backoff(
        backoff_duration: Duration,
        common: RegisterWithFederationCommon,
    ) -> RegisterWithFederationStateMachine {
        // Double the backoff duration so that the federation isn't spammed with
        // registration requests
        let new_backoff_duration = backoff_duration.mul_f32(2.0);
        let one_day = Duration::from_secs(86400);

        // Wait for a maximum of one day
        let min_duration = match new_backoff_duration.cmp(&one_day) {
            Ordering::Less => new_backoff_duration,
            _ => one_day,
        };

        RegisterWithFederationStateMachine {
            common,
            state: RegisterWithFederationStates::Register(RegisterWithFederation {
                backoff_duration: min_duration,
            }),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub struct WaitForTimeToLive;

impl WaitForTimeToLive {
    fn transitions(
        &self,
        common: RegisterWithFederationCommon,
    ) -> Vec<StateTransition<RegisterWithFederationStateMachine>> {
        let ttl = common.time_to_live;
        vec![StateTransition::new(sleep(ttl), move |dbtx, _, _| {
            Box::pin(Self::transition_wait_for_ttl(common.clone(), dbtx))
        })]
    }

    async fn transition_wait_for_ttl(
        common: RegisterWithFederationCommon,
        dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
    ) -> RegisterWithFederationStateMachine {
        let mut dbtx = dbtx.module_tx();
        let registration_info = dbtx
            .get_value(&FederationRegistrationKey {
                id: common.federation_id,
            })
            .await;

        if let Some(registration_info) = registration_info {
            // If the stored db registration info is not the same as the state machine's
            // registration info, that means another state machine has
            // overwritten it and we can safely transition to `Done`.
            if registration_info != common.registration_info {
                return RegisterWithFederationStateMachine {
                    common,
                    state: RegisterWithFederationStates::Done,
                };
            }

            // Re-register since the TTL has expired
            return RegisterWithFederationStateMachine {
                common,
                state: RegisterWithFederationStates::Register(RegisterWithFederation {
                    backoff_duration: INITIAL_REGISTER_BACKOFF_DURATION,
                }),
            };
        }

        // Transition to `Done` since this gateway has been unregistered from the
        // federation
        RegisterWithFederationStateMachine {
            common,
            state: RegisterWithFederationStates::Done,
        }
    }
}
