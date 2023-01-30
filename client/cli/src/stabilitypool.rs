use clap::Subcommand;
use fedimint_api::{Amount, OutPoint, TransactionId};
use mint_client::{Client, UserClientConfig};
use stabilitypool::{
    self,
    api::SideResponse,
    config::PoolConfigClient,
    stability_core::{self, CollateralRatio},
    ActionStaged, EpochOutcome, ProviderBid, SeekerAction,
};

use crate::{CliError, CliErrorKind};

#[derive(Subcommand)]
pub enum PoolCommand {
    /// Get stability pool account details.
    Balance,

    /// Get outcome of given stability pool epoch.
    Epoch { epoch_id: u64 },

    /// Get the next stability pool epoch.
    EpochNext,

    /// Deposit into unlocked balance of stability pool.
    Deposit { amount: Amount },

    /// Withdraw from unlocked balance of stability pool.
    Withdraw { amount: Amount },

    /// User action commands.
    #[clap(subcommand)]
    Action(Propose),

    /// Get the state of the stability pool.
    State,
}

#[derive(Subcommand)]
pub enum Propose {
    /// Check the current action staged for account.
    Staged,
    /// Lock funds as a seeker.
    SeekerLock { amount: Amount },
    /// Unlock funds as a seeker.
    SeekerUnlock { amount: Amount },
    /// Bid as a provider.
    ProviderBid { min_feerate: u64, amount: Amount },
}

#[derive(serde::Serialize)]
#[serde(rename_all(serialize = "snake_case"))]
pub enum PoolCliOutput {
    Balance { balance: AccountBalance },

    EpochOutcome { outcome: EpochOutcome },

    EpochNext { epoch_id: u64 },

    Deposit { deposit_tx: OutPoint },

    Withdraw { withdraw_tx: TransactionId },

    Propose {},

    Staged { action: ActionStaged },

    State { state: stabilitypool::api::State },
}

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct AccountBalance {
    pub unlocked: u64,
    pub locked: Option<LockedBalance>,
}

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all(serialize = "snake_case"))]
pub struct LockedBalance {
    side: SideResponse,
    locked_value_msat: u64,
    locked_value_usd: f64,
    current_value_msat: u64,
    current_value_usd: f64,
    epoch_fee_msat: i64,
    epoch_fee_usd: f64,
    feerate: u64,
    msat_pnl: i64,
    usd_pnl: f64,
    current_price: f64,
    epoch_start_price: f64,
}

impl LockedBalance {
    pub fn from_core_locked_balance(
        balance: stabilitypool::api::LockedBalanceResponse,
        current_price: u64,
        collateral_ratio: CollateralRatio,
    ) -> Self {
        let feerate = balance.epoch.feerate;
        let epoch_start_price: u64 = balance.epoch_start_price;
        let side = balance.side;
        let locked_value_msat = balance.value;
        let current_value_msat = match side {
            SideResponse::Provider => stability_core::provider_payout(
                locked_value_msat,
                feerate,
                epoch_start_price,
                current_price,
                collateral_ratio,
            ),
            SideResponse::Seeker => stability_core::seeker_payout(
                locked_value_msat,
                feerate,
                epoch_start_price,
                current_price,
                collateral_ratio,
            ),
        };
        let epoch_fee_msat = match side {
            SideResponse::Provider => {
                -(stability_core::provider_fee(feerate, locked_value_msat, collateral_ratio) as i64)
            }
            SideResponse::Seeker => stability_core::seeker_fee(feerate, locked_value_msat) as i64,
        };

        let msat_pnl = locked_value_msat as i64 - current_value_msat as i64;
        LockedBalance {
            side,
            locked_value_msat,
            locked_value_usd: msat_to_usd(locked_value_msat as i64, epoch_start_price),
            current_value_msat,
            current_value_usd: msat_to_usd(current_value_msat as i64, current_price),
            epoch_fee_msat,
            epoch_fee_usd: msat_to_usd(epoch_fee_msat, current_price),
            feerate: feerate.approx_ppm_feerate(),
            msat_pnl,
            usd_pnl: msat_to_usd(msat_pnl, current_price),
            current_price: (current_price as f64) / 100.0,
            epoch_start_price: (epoch_start_price as f64) / 100.0,
        }
    }
}

fn msat_to_usd(msat: i64, price: u64) -> f64 {
    msat as f64 * (price as f64 / 100.0) / 1e11
}

pub(crate) async fn handle_command(
    command: PoolCommand,
    client: Client<UserClientConfig>,
    rng: rand::rngs::OsRng,
) -> Result<PoolCliOutput, CliError> {
    let config = client
        .config()
        .0
        .modules
        .get(&3)
        .expect("missing pool config")
        .cast::<PoolConfigClient>()
        .unwrap();

    match command {
        PoolCommand::Balance => match client.pool_client().balance().await {
            Ok(balance) => {
                let oracle = config.oracle.oracle_client();
                let current_price = oracle.price_now().await.unwrap();
                let output = AccountBalance {
                    unlocked: balance.unlocked,
                    locked: balance
                        .locked
                        .map(|balance| {
                            Ok(LockedBalance::from_core_locked_balance(
                                balance,
                                current_price,
                                config.collateral_ratio,
                            ))
                        })
                        .transpose()?,
                };
                Ok(PoolCliOutput::Balance { balance: output })
            }
            Err(e) => Err(CliError::from(
                CliErrorKind::GeneralFederationError,
                "failed",
                Some(e.into()),
            )),
        },
        PoolCommand::Epoch { epoch_id } => {
            match client.pool_client().epoch_outcome(epoch_id).await {
                Ok(outcome) => Ok(PoolCliOutput::EpochOutcome { outcome }),
                Err(e) => Err(CliError::from(
                    CliErrorKind::GeneralFederationError,
                    "failed",
                    Some(e.into()),
                )),
            }
        }
        // The minimum oldest epoch id that the client can act on
        PoolCommand::EpochNext => match client.pool_client().staging_epoch().await {
            Ok(epoch_id) => Ok(PoolCliOutput::EpochNext { epoch_id }),
            Err(e) => Err(CliError::from(
                CliErrorKind::GeneralFederationError,
                "failed",
                Some(e.into()),
            )),
        },
        PoolCommand::Deposit { amount } => match client.pool_deposit(amount, rng).await {
            Ok(outpoint) => Ok(PoolCliOutput::Deposit {
                deposit_tx: outpoint,
            }),
            Err(e) => Err(CliError::from(
                CliErrorKind::GeneralFederationError,
                "failed",
                Some(e.into()),
            )),
        },
        PoolCommand::Withdraw { amount } => match client.pool_withdraw(amount, rng).await {
            Ok(txid) => Ok(PoolCliOutput::Withdraw { withdraw_tx: txid }),
            Err(e) => Err(CliError::from(
                CliErrorKind::GeneralFederationError,
                "failed",
                Some(e.into()),
            )),
        },
        PoolCommand::Action(action) => {
            let res = match action {
                Propose::Staged => {
                    return match client.pool_client().staged_action().await {
                        Ok(action) => Ok(PoolCliOutput::Staged { action }),
                        Err(e) => Err(CliError::from(
                            CliErrorKind::GeneralFederationError,
                            "failed",
                            Some(e.into()),
                        )),
                    }
                }
                Propose::SeekerLock { amount } => {
                    client
                        .pool_client()
                        .propose_seeker_action(SeekerAction::Lock { amount })
                        .await
                }
                Propose::SeekerUnlock { amount } => {
                    client
                        .pool_client()
                        .propose_seeker_action(SeekerAction::Unlock { amount })
                        .await
                }
                Propose::ProviderBid {
                    amount,
                    min_feerate,
                } => {
                    client
                        .pool_client()
                        .propose_provider_action(ProviderBid {
                            max_amount: amount,
                            min_feerate,
                        })
                        .await
                }
            };

            match res {
                Ok(_) => Ok(PoolCliOutput::Propose {}),
                Err(e) => Err(CliError::from(
                    CliErrorKind::GeneralFederationError,
                    "failed",
                    Some(e.into()),
                )),
            }
        }
        PoolCommand::State => match client.pool_client().state().await {
            Ok(state) => Ok(PoolCliOutput::State { state }),
            Err(e) => Err(CliError::from(
                CliErrorKind::GeneralFederationError,
                "failed",
                Some(e.into()),
            )),
        },
    }
}
