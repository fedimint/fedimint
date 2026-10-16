use std::time::Duration;
use std::{ffi, iter};

use clap::Parser;
use fedimint_core::secp256k1::PublicKey;
use fedimint_core::secp256k1::schnorr::Signature;
use fedimint_core::{Amount, secp256k1};
use fedimint_escrow_common::{EscrowId, EscrowMessage, FallbackPolicy, Outcome};
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
        recipient_key: secp256k1::PublicKey,
        #[clap(long)]
        arbiter_key: secp256k1::PublicKey,
        #[clap(long)]
        arbiter_fee_msats: Amount,
        #[clap(long)]
        arbiter_fee_key: Vec<PublicKey>,
        #[clap(long)]
        amount_sats: u64,
        #[clap(long)]
        timeout: u64,
        #[clap(long)]
        resolution_deadline: u64,
        #[clap(long)]
        default_fallback: FallbackPolicy,
    },

    /// Get the created contract for the escrow_id
    GetContract {
        #[clap(long)]
        escrow_id: EscrowId,
    },

    /// List the client's escrow operations
    ListEscrow,

    /// Resolve the specific escrow with the funder signature
    ResolveEscrow {
        escrow_id: EscrowId,
        funder_signature: Signature,
    },

    /// Resolve the escrow with the arbiter outcom
    SubmitArbiterDecision {
        escrow_id: EscrowId,
        outcome: Outcome,
        arbiter_signature: Signature,
    },

    /// Contract get in disputed state, resolution timeout is calculated from
    /// when the contract goes in disputed state
    EngageArbiter { escrow_id: EscrowId },

    /// parties(funder/recipient) can trigger a fallback after resolution
    /// timeout for a disputed contract
    TriggerFallback { escrow_id: EscrowId },

    /// Arbiter claims its fees for the escrow
    ClaimPayout { escrow_id: EscrowId },

    SignMessage {
        #[command(subcommand)]
        message: SignMessageOpts,
    },
}

#[derive(clap::Subcommand, Serialize)]
enum SignMessageOpts {
    Resolution {
        #[clap(long)]
        escrow_id: EscrowId,

        #[clap(long)]
        outcome: Outcome,
    },

    ArbiterEngaged {
        #[clap(long)]
        escrow_id: EscrowId,
    },
}

pub(crate) async fn handle_cli_command(
    client: &EscrowClientModule,
    args: &[std::ffi::OsString],
) -> anyhow::Result<serde_json::Value> {
    let opts = Opts::parse_from(iter::once(&ffi::OsString::from("escrow")).chain(args.iter()));

    match opts {
        Opts::Create {
            recipient_key,
            arbiter_key,
            arbiter_fee_msats,
            arbiter_fee_key,
            amount_sats,
            timeout,
            resolution_deadline,
            default_fallback,
        } => {
            let result = client
                .create_escrow(
                    recipient_key,
                    arbiter_key,
                    arbiter_fee_msats,
                    Amount::from_sats(amount_sats),
                    Duration::from_secs(timeout),
                    arbiter_fee_key,
                    Duration::from_secs(resolution_deadline),
                    default_fallback,
                )
                .await?;

            let mut stream = client
                .subscribe_escrow_creation(result.operation_id)
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
                "operation_id": result.operation_id,
                "escrow_id": result.escrow_id,
                "contract_hash": result.contract_hash,
                "timeout": result.timeout,
            }))
        }
        Opts::GetContract { escrow_id } => {
            let contract = client.get_contract(escrow_id).await?;
            Ok(serde_json::to_value(contract)?)
        }
        Opts::ListEscrow => {
            let contracts = client.list_contracts().await?;
            Ok(serde_json::to_value(contracts)?)
        }
        Opts::EngageArbiter { escrow_id } => {
            let operation_id = client.engage_arbiter(escrow_id).await?;

            let mut stream = client
                .subscribe_escrow_resolution(operation_id)
                .await?
                .into_stream();

            while let Some(state) = stream.next().await {
                match &state {
                    EscrowInputSMState::Failed { reason } => {
                        return Err(anyhow::anyhow!("Escrow resolution failed: {reason}"));
                    }
                    EscrowInputSMState::Disputed => {
                        break;
                    }
                    _ => {}
                }
            }

            Ok(serde_json::json!({
                "operation_id": operation_id
            }))
        }
        Opts::ResolveEscrow {
            escrow_id,
            funder_signature,
        } => {
            let operation_id = client.resolve_escrow(escrow_id, funder_signature).await?;

            let mut stream = client
                .subscribe_escrow_resolution(operation_id)
                .await?
                .into_stream();

            while let Some(state) = stream.next().await {
                match &state {
                    EscrowInputSMState::Released => {
                        break;
                    }
                    EscrowInputSMState::Failed { reason } => {
                        return Err(anyhow::anyhow!("Escrow resolution failed: {reason}"));
                    }
                    _ => {}
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
            let operation_id = client
                .submit_arbiter_decision(escrow_id, outcome, arbiter_signature)
                .await?;

            let mut stream = client
                .subscribe_escrow_resolution(operation_id)
                .await?
                .into_stream();

            while let Some(state) = stream.next().await {
                match &state {
                    EscrowInputSMState::Refunded => {
                        break;
                    }
                    EscrowInputSMState::Released => {
                        break;
                    }
                    EscrowInputSMState::Split => {
                        break;
                    }
                    EscrowInputSMState::Failed { reason } => {
                        return Err(anyhow::anyhow!(
                            "Escrow arbiter resolution failed: {reason}"
                        ));
                    }
                    _ => {}
                }
            }

            Ok(serde_json::json!({
                "operation_id": operation_id
            }))
        }
        Opts::ClaimPayout { escrow_id } => {
            let operation_id = client.claim_payout(escrow_id).await?;

            let mut stream = client
                .subscribe_claim_payout(operation_id)
                .await?
                .into_stream();

            while let Some(state) = stream.next().await {
                match &state {
                    EscrowInputSMState::Failed { reason } => {
                        return Err(anyhow::anyhow!(
                            "Escrow arbiter resolution failed: {reason}"
                        ));
                    }
                    EscrowInputSMState::Claimed => {
                        break;
                    }
                    _ => {}
                }
            }

            Ok(serde_json::json!({
                "operation_id": operation_id
            }))
        }
        Opts::TriggerFallback { escrow_id } => {
            let operation_id = client.trigger_fallback(escrow_id).await?;

            let mut stream = client
                .subscribe_escrow_resolution(operation_id)
                .await?
                .into_stream();

            while let Some(state) = stream.next().await {
                match &state {
                    EscrowInputSMState::Refunded => {
                        break;
                    }
                    EscrowInputSMState::Released => {
                        break;
                    }
                    EscrowInputSMState::Split => {
                        break;
                    }
                    EscrowInputSMState::Failed { reason } => {
                        return Err(anyhow::anyhow!(
                            "Escrow arbiter resolution failed: {reason}"
                        ));
                    }
                    _ => {}
                }
            }

            Ok(serde_json::json!({
                "operation_id": operation_id
            }))
        }
        Opts::SignMessage { message } => {
            let escrow_message =
                match message {
                    SignMessageOpts::Resolution { escrow_id, outcome } => {
                        let federation_id = client.federation_id;
                        let contract = client.get_contract(escrow_id).await?.ok_or_else(|| {
                            anyhow::anyhow!("Contract not found for this escrow_id")
                        })?;
                        EscrowMessage::Resolution {
                            escrow_id,
                            federation_id,
                            outcome,
                            contract_hash: contract.contract_hash,
                        }
                    }

                    SignMessageOpts::ArbiterEngaged { escrow_id } => {
                        let federation_id = client.federation_id;
                        let contract = client.get_contract(escrow_id).await?.ok_or_else(|| {
                            anyhow::anyhow!("Contract not found for this escrow_id")
                        })?;
                        EscrowMessage::ArbiterEngaged {
                            escrow_id,
                            federation_id,
                            contract_hash: contract.contract_hash,
                        }
                    }
                };

            let sig = client.sign_message(escrow_message)?;

            Ok(serde_json::json!({
                "signature": sig.to_string(),
            }))
        }
    }
}
