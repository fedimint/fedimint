use std::time::Duration;
use std::{ffi, iter};

use anyhow::Ok;
use clap::Parser;
use fedimint_core::secp256k1::schnorr;
use fedimint_core::{Amount, secp256k1};
use fedimint_escrow_common::{EscrowId, Outcome};
use futures::StreamExt;
use serde::Serialize;

use crate::EscrowClientModule;
use crate::input::EscrowInputSMState;
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

    /// Resolve the specific escrow with the buyer signature
    ResolveEscrow {
        escrow_id: String,
        buyer_signature: String,
    },

    /// Resolve the escrow with the arbiter outcome (tx submitted by winner
    /// party)
    SubmitArbiterDecision {
        escrow_id: String,
        outcome: Outcome,
        arbiter_signature: String,
    },

    /// Arbiter claims its fees for the escrow
    ClaimArbiterFee {
        escrow_id: String,
        arbiter_signature: String,
    },
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
        Opts::ResolveEscrow {
            escrow_id,
            buyer_signature,
        } => {
            let escrow_id_bytes = hex::decode(&escrow_id)?;
            let escrow_id = EscrowId(
                escrow_id_bytes
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("Invalid escrow_id length"))?,
            );
            let sig_bytes = hex::decode(&buyer_signature)?;

            let buyer_signature = schnorr::Signature::from_slice(&sig_bytes)
                .map_err(|e| anyhow::anyhow!("Invalid schnorr signature: {e}"))?;

            let operation_id = client.resolve_escrow(escrow_id, buyer_signature).await?;

            let mut stream = client
                .subscribe_escrow_resolution(operation_id)
                .await?
                .into_stream();

            while let Some(state) = stream.next().await {
                match &state {
                    EscrowInputSMState::Pending => {}
                    EscrowInputSMState::Refunded => {
                        break;
                    }
                    EscrowInputSMState::Released => {
                        break;
                    }
                    EscrowInputSMState::Failed { reason } => {
                        return Err(anyhow::anyhow!("Escrow creation failed: {reason}"));
                    }
                    EscrowInputSMState::FeeClaimed => {}
                    EscrowInputSMState::FeeClaiming => {}
                }
            }

            Ok(serde_json::json!({
                "operation_id": operation_id
            }))
        }
        Opts::SubmitArbiterDecision {
            escrow_id,
            outcome,
            arbiter_signature,
        } => {
            let escrow_id_bytes = hex::decode(&escrow_id)?;
            let escrow_id = EscrowId(
                escrow_id_bytes
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("Invalid escrow_id length"))?,
            );
            let sig_bytes = hex::decode(&arbiter_signature)?;

            let arbiter_signature = schnorr::Signature::from_slice(&sig_bytes)
                .map_err(|e| anyhow::anyhow!("Invalid schnorr signature: {e}"))?;

            let operation_id = client
                .submit_arbiter_decision(escrow_id, outcome, arbiter_signature)
                .await?;

            let mut stream = client
                .subscribe_escrow_resolution(operation_id)
                .await?
                .into_stream();

            while let Some(state) = stream.next().await {
                match &state {
                    EscrowInputSMState::Pending => {}
                    EscrowInputSMState::Refunded => {
                        break;
                    }
                    EscrowInputSMState::Released => {
                        break;
                    }
                    EscrowInputSMState::Failed { reason } => {
                        return Err(anyhow::anyhow!("Escrow creation failed: {reason}"));
                    }
                    EscrowInputSMState::FeeClaimed => {}
                    EscrowInputSMState::FeeClaiming => {}
                }
            }

            Ok(serde_json::json!({
                "operation_id": operation_id
            }))
        }
        Opts::ClaimArbiterFee {
            escrow_id,
            arbiter_signature,
        } => {
            let escrow_id_bytes = hex::decode(&escrow_id)?;
            let escrow_id = EscrowId(
                escrow_id_bytes
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("Invalid escrow_id length"))?,
            );
            let sig_bytes = hex::decode(&arbiter_signature)?;

            let arbiter_signature = schnorr::Signature::from_slice(&sig_bytes)
                .map_err(|e| anyhow::anyhow!("Invalid schnorr signature: {e}"))?;

            let operation_id = client
                .claim_arbiter_fee(escrow_id, arbiter_signature)
                .await?;

            let mut stream = client
                .subscribe_fee_claim(operation_id)
                .await?
                .into_stream();

            while let Some(state) = stream.next().await {
                match &state {
                    EscrowInputSMState::Pending => {}
                    EscrowInputSMState::FeeClaiming => {}
                    EscrowInputSMState::FeeClaimed => {
                        break;
                    }
                    EscrowInputSMState::Refunded => {}
                    EscrowInputSMState::Released => {}
                    EscrowInputSMState::Failed { reason } => {
                        return Err(anyhow::anyhow!("Escrow creation failed: {reason}"));
                    }
                }
            }

            Ok(serde_json::json!({
                "operation_id": operation_id
            }))
        }
    }
}
