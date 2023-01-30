use std::collections::BTreeMap;

use fedimint_api::{
    db::DatabaseTransaction,
    module::{api_endpoint, ApiEndpoint, ApiError},
};

use crate::{
    account::AccountBalance,
    action::{ActionProposed, ActionProposedDb, ActionStaged},
    db,
    epoch::{self, EpochOutcome, EpochState},
    StabilityPool,
};

pub fn endpoints() -> Vec<ApiEndpoint<StabilityPool>> {
    vec![
        // Get outcome of given `epoch_id`.
        api_endpoint! {
            "/epoch",
            async |_module: &StabilityPool, dbtx, epoch_id: u64| -> EpochOutcome {
                epoch_outcome(dbtx, epoch_id).await
            }
        },
        // Get the `epoch_id` that the federation will accept user actions for.
        api_endpoint! {
            "/epoch_next",
            async |_module: &StabilityPool, dbtx, _request: ()| -> u64 {
                Ok(epoch::EpochState::from_db(dbtx).await.staging_epoch_id())
            }
        },
        api_endpoint! {
            "/epoch_last_settled",
            async |_module: &StabilityPool, dbtx, _request: ()| -> Option<u64> {
                Ok(epoch::EpochState::from_db(dbtx).await.latest_settled)
            }
        },
        api_endpoint! {
            "/account",
            async |_module: &StabilityPool, dbtx, request: secp256k1_zkp::XOnlyPublicKey| -> BalanceResponse {
                Ok(account(dbtx, request).await)
            }
        },
        api_endpoint! {
            "/action",
            async |_module: &StabilityPool, dbtx, request: secp256k1_zkp::XOnlyPublicKey| -> ActionStaged {
                db::get(dbtx, &db::ActionStagedKey(request)).await
                    .ok_or(ApiError::not_found(format!("no action staged for account {}", request)))
            }
        },
        api_endpoint! {
            "/action_propose",
            async |module: &StabilityPool, dbtx, request: ActionProposed| -> () {
                propose_action(dbtx, &module.proposed_db, request).await
            }
        },
        api_endpoint! {
            "/state",
            async |_module: &StabilityPool, dbtx, _request: ()| -> State {
                Ok(state(dbtx).await)
            }
        },
    ]
}

pub async fn epoch_outcome(
    dbtx: &mut DatabaseTransaction<'_>,
    epoch_id: u64,
) -> Result<EpochOutcome, ApiError> {
    db::get(dbtx, &db::EpochOutcomeKey(epoch_id))
        .await
        .ok_or(ApiError::not_found(format!(
            "no outcome for epoch {}",
            epoch_id
        )))
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
pub struct BalanceResponse {
    pub unlocked: u64,
    pub locked: Option<LockedBalanceResponse>,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
pub struct LockedBalanceResponse {
    pub value: u64,
    pub side: SideResponse,
    pub epoch_id: u64,
    pub epoch_start_price: u64,
    pub epoch: EpochOutcome,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
pub enum SideResponse {
    Provider,
    Seeker,
}

pub async fn account(
    dbtx: &mut DatabaseTransaction<'_>,
    account_id: secp256k1_zkp::XOnlyPublicKey,
) -> BalanceResponse {
    let epoch_state = EpochState::from_db(dbtx).await;
    let epoch_id = epoch_state.current_epoch_id();

    let account = match db::get(dbtx, &db::AccountBalanceKey(account_id)).await {
        Some(account) => account,
        None => {
            return BalanceResponse {
                unlocked: 0,
                locked: None,
            }
        }
    };

    let epoch_outcome = db::get(dbtx, &db::EpochOutcomeKey(epoch_id))
        .await
        .expect("must exist");
    let epoch_start_price = db::get(dbtx, &db::EpochOutcomeKey(epoch_id.saturating_sub(1)))
        .await
        .expect("must exist")
        .settled_price
        .expect("should be settled");

    match account.locked {
        crate::LockedBalance::Seeker(locked) => BalanceResponse {
            unlocked: account.unlocked.msats,
            locked: Some(LockedBalanceResponse {
                value: locked.msats,
                side: SideResponse::Seeker,
                epoch_id,
                epoch_start_price,
                epoch: epoch_outcome,
            }),
        },
        crate::LockedBalance::Provider(locked) => BalanceResponse {
            unlocked: account.unlocked.msats,
            locked: Some(LockedBalanceResponse {
                value: locked.msats,
                side: SideResponse::Provider,
                epoch_id,
                epoch_start_price,
                epoch: epoch_outcome,
            }),
        },
        crate::LockedBalance::None => BalanceResponse {
            unlocked: account.unlocked.msats,
            locked: None,
        },
    }
    // match epoch_state.current_epoch_id() {
    //     Some(epoch_id) => {
    //     }
    //     None => BalanceResponse {
    //         unlocked: account.unlocked.msats,
    //         locked: None,
    //     },
    // }
}

pub async fn propose_action(
    dbtx: &mut DatabaseTransaction<'_>,
    proposed_db: &ActionProposedDb,
    request: ActionProposed,
) -> Result<(), ApiError> {
    request
        .verify_signature()
        .map_err(|_| ApiError::bad_request(format!("bad signature")))?;

    let account_id = request.account_id();
    let next_epoch = EpochState::from_db(dbtx).await.staging_epoch_id();

    if request.epoch_id() != next_epoch {
        return Err(ApiError::bad_request(format!(
            "next epoch is {}",
            next_epoch
        )));
    }

    let mut most_recent: Option<ActionStaged> = proposed_db.get(account_id).map(Into::into);
    if most_recent.is_none() {
        most_recent = db::get(dbtx, &db::ActionStagedKey(account_id)).await;
    }

    if let Some(recent) = most_recent {
        if request.epoch_id() == recent.epoch_id() && request.sequence() <= recent.sequence() {
            return Err(ApiError::bad_request(format!(
                "seeker action sequence should be greater than previous {}",
                recent.sequence()
            )));
        }
    }

    Ok(proposed_db.insert(request))
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct State {
    pub previous_epoch: StateEpoch,
    pub current_epoch: StateEpoch,

    pub accounts: BTreeMap<secp256k1_zkp::XOnlyPublicKey, AccountBalance>,
    pub staged: BTreeMap<secp256k1_zkp::XOnlyPublicKey, ActionStaged>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct StateEpoch {
    pub epoch_id: u64,
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<EpochOutcome>,
}

pub async fn state(dbtx: &mut DatabaseTransaction<'_>) -> State {
    let epoch_state = EpochState::from_db(dbtx).await;

    let previous_epoch_id = epoch_state.latest_ended.unwrap_or(0);
    let current_epoch_id = epoch_state.current_epoch_id();

    let previous_epoch = db::get(dbtx, &db::EpochOutcomeKey(previous_epoch_id)).await;
    let current_epoch = db::get(dbtx, &db::EpochOutcomeKey(current_epoch_id)).await;

    let accounts = db::prefix_entries(dbtx, &db::AccountBalanceKeyPrefix)
        .await
        .map(|(k, balance)| (k.0, balance))
        .collect::<BTreeMap<_, _>>();

    let staged = db::prefix_values(dbtx, &db::ActionStagedKeyPrefix)
        .await
        .map(|action| (action.account_id(), action))
        .collect::<BTreeMap<_, _>>();

    State {
        previous_epoch: StateEpoch {
            epoch_id: previous_epoch_id,
            outcome: previous_epoch,
        },
        current_epoch: StateEpoch {
            epoch_id: current_epoch_id,
            outcome: current_epoch,
        },
        accounts,
        staged,
    }
}
