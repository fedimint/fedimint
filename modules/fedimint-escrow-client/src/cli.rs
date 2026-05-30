use std::time::Duration;
use std::{ffi, iter};

use anyhow::Ok;
use clap::Parser;
use fedimint_core::{Amount, secp256k1};
use fedimint_escrow_common::EscrowId;
use futures::StreamExt;
use serde::Serialize;

use crate::EscrowClientModule;
use crate::output::EscrowOutputSMState;

#[derive(Parser, Serialize)]
enum Opts {
    /// Create a new escrow contract
    Create {
        #[clap(long)]
        seller_key: secp256k1::PublicKey,
        #[clap(long)]
        arbiter_key: secp256k1::PublicKey,
        #[clap(long)]
        arbiter_fee_msats: Amount,
        #[clap(long)]
        amount_sats: u64,
        #[clap(long)]
        timeout: u64,
    },

    /// Get the created contract for the escrow_id
    GetContract {
        #[clap(long)]
        escrow_id: String,
    },

    /// List the client's escrow operations
    ListEscrow,
}

pub(crate) async fn handle_cli_command(
    client: &EscrowClientModule,
    args: &[std::ffi::OsString],
) -> anyhow::Result<serde_json::Value> {
    let opts = Opts::parse_from(iter::once(&ffi::OsString::from("escrow")).chain(args.iter()));

    match opts {
        Opts::Create {
            seller_key,
            arbiter_key,
            arbiter_fee_msats,
            amount_sats,
            timeout,
        } => {
            let (operation_id, escrow_id) = client
                .create_escrow(
                    seller_key,
                    arbiter_key,
                    arbiter_fee_msats,
                    Amount::from_sats(amount_sats),
                    Duration::from_secs(timeout),
                )
                .await?;

            let mut stream = client
                .subscribe_escrow_creation(operation_id)
                .await?
                .into_stream();

            while let Some(state) = stream.next().await {
                match &state {
                    EscrowOutputSMState::Active => {
                        break;
                    }
                    EscrowOutputSMState::Failed { reason } => {
                        return Err(anyhow::anyhow!("Escrow creation failed: {reason}"));
                    }
                    EscrowOutputSMState::Creating => {}
                }
            }

            Ok(serde_json::json!({
                "operation_id": operation_id,
                "escrow_id": hex::encode(escrow_id.0),
            }))
        }
        Opts::GetContract { escrow_id } => {
            let escrow_id_bytes = hex::decode(&escrow_id)?;
            let escrow_id = EscrowId(
                escrow_id_bytes
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("Invalid escrow_id length"))?,
            );

            let contract = client.get_contract(escrow_id).await?;
            Ok(serde_json::to_value(contract)?)
        }
        Opts::ListEscrow => {
            let contracts = client.list_escrow_operation().await;
            Ok(serde_json::to_value(contracts)?)
        }
    }
}
