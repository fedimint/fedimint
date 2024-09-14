use std::{ffi, iter};

use anyhow::{ensure, Context};
use bitcoin::address::NetworkUnchecked;
use bitcoin::Address;
use clap::Parser;
use dialoguer::{Confirm, Select};
use fedimint_core::util::SafeUrl;
use serde::Serialize;
use serde_json::Value;

use crate::{UnspentDeposit, WalletClientModule};

#[derive(Parser, Serialize)]
enum Opts {
    Send {
        address: Address<NetworkUnchecked>,
        amount: bitcoin::Amount,
    },
    Generate,
    List,
    Check {
        esplora: SafeUrl,
        index: u64,
    },
    Receive {
        esplora: SafeUrl,
        index: u64,
    },
}

pub(crate) async fn handle_cli_command(
    wallet: &WalletClientModule,
    args: &[ffi::OsString],
) -> anyhow::Result<Value> {
    let opts = Opts::parse_from(iter::once(&ffi::OsString::from("walletv2")).chain(args.iter()));

    let value = match opts {
        Opts::Send { address, amount } => {
            let send_fee = wallet.send_fee().await?;

            if !Confirm::new()
                .with_prompt("Dou you want to continue with a fee of {send_fee.amount}")
                .default(false)
                .interact()
                .context("Failed to confirm fee")?
            {
                return Ok(json(()));
            }

            let operation_id = wallet.send(&address, amount, send_fee).await?;

            json(wallet.await_final_operation_state(operation_id).await)
        }
        Opts::Generate => json(wallet.generate_new_address().await),
        Opts::List => {
            for (index, address) in wallet.list_addresses().await.iter().enumerate() {
                println!("{index} - {address}");
            }

            json(())
        }
        Opts::Check { esplora, index } => {
            for deposit in wallet.check_address_for_deposits(esplora, index).await? {
                println!(
                    "{}",
                    match deposit.confirmations_required {
                        Some(0) => {
                            format!("{} - Confirmed", deposit.value)
                        }
                        Some(confirmations) => format!(
                            "{} - Requires {} additional confirmations",
                            deposit.value, confirmations
                        ),
                        None => format!("{} - Pending", deposit.value),
                    }
                );
            }

            json(())
        }
        Opts::Receive { esplora, index } => {
            let unspent_deposits = wallet
                .check_address_for_deposits(esplora, index)
                .await?
                .into_iter()
                .filter(|deposit| deposit.confirmations_required == Some(0))
                .collect::<Vec<UnspentDeposit>>();

            ensure!(
                !unspent_deposits.is_empty(),
                "No unspent deposits are ready to be claimed"
            );

            let index = Select::new()
                .items(
                    &unspent_deposits
                        .iter()
                        .map(|deposit| format!("{}", deposit.value))
                        .collect::<Vec<String>>(),
                )
                .interact()
                .context("Failed to select unspent deposit for consolidation")?;

            let receive_fee = wallet.receive_fee().await?;

            if !Confirm::new()
                .with_prompt("Dou you want to continue with a fee of {receive_fee.amount}")
                .default(false)
                .interact()
                .context("Failed to confirm fee")?
            {
                return Ok(json(()));
            }

            let operation_id = wallet
                .receive(&unspent_deposits[index], receive_fee)
                .await?;

            json(wallet.await_final_operation_state(operation_id).await)
        }
    };

    Ok(value)
}

fn json<T: Serialize>(value: T) -> Value {
    serde_json::to_value(value).expect("JSON serialization failed")
}
