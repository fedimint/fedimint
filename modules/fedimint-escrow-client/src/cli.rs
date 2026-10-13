use std::time::Duration;
use std::{ffi, iter};

use anyhow::{Ok, anyhow};
use clap::Parser;
use fedimint_core::secp256k1::{PublicKey, schnorr};
use fedimint_core::{Amount, secp256k1};
use fedimint_escrow_common::{ContractHash, EscrowId, EscrowMessage, FallbackPolicy, Outcome};
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
        escrow_id: String,
    },

    /// List the client's escrow operations
    ListEscrow,

    /// Resolve the specific escrow with the funder signature
    ResolveEscrow {
        escrow_id: String,
        funder_signature: String,
    },

    /// Resolve the escrow with the arbiter outcome (tx submitted by winner
    /// party)
    SubmitArbiterDecision {
        escrow_id: String,
        outcome: Outcome,
        arbiter_signature: String,
    },

    /// Arbiter claims its fees for the escrow
    ClaimPayout { escrow_id: String },

    SignMessage {
        #[command(subcommand)]
        message: SignMessageOpts,
    },
}

#[derive(clap::Subcommand, Serialize)]
enum SignMessageOpts {
    Resolution {
        #[clap(long)]
        escrow_id: String,

        #[clap(long)]
        outcome: Outcome,

        #[clap(long)]
        contract_hash: String,
    },

    ArbiterEngaged {
        #[clap(long)]
        escrow_id: String,

        #[clap(long)]
        contract_hash: String,
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
                "escrow_id": hex::encode(result.escrow_id),
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
            let contracts = client.list_escrow_operations().await;
            Ok(serde_json::to_value(contracts)?)
        }
        Opts::ResolveEscrow {
            escrow_id,
            funder_signature,
        } => {
            let escrow_id_bytes = hex::decode(&escrow_id)?;
            let escrow_id = EscrowId(
                escrow_id_bytes
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("Invalid escrow_id length"))?,
            );
            let sig_bytes = hex::decode(&funder_signature)?;

            let funder_signature = schnorr::Signature::from_slice(&sig_bytes)
                .map_err(|e| anyhow::anyhow!("Invalid schnorr signature: {e}"))?;

            let operation_id = client.resolve_escrow(escrow_id, funder_signature).await?;

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
                    EscrowInputSMState::Split => {}
                    EscrowInputSMState::Failed { reason } => {
                        return Err(anyhow::anyhow!("Escrow resolution failed: {reason}"));
                    }
                    EscrowInputSMState::Claimed => {}
                    EscrowInputSMState::Disputed => {}
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
                    EscrowInputSMState::Split => {
                        break;
                    }
                    EscrowInputSMState::Failed { reason } => {
                        return Err(anyhow::anyhow!(
                            "Escrow arbiter resolution failed: {reason}"
                        ));
                    }
                    EscrowInputSMState::Claimed => {}
                    EscrowInputSMState::Disputed => {}
                }
            }

            Ok(serde_json::json!({
                "operation_id": operation_id
            }))
        }
        Opts::ClaimPayout { escrow_id } => {
            let escrow_id_bytes = hex::decode(&escrow_id)?;
            let escrow_id = EscrowId(
                escrow_id_bytes
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("Invalid escrow_id length"))?,
            );

            let operation_id = client.claim_payout(escrow_id).await?;

            Ok(serde_json::json!({
                "operation_id": operation_id
            }))
        }
        Opts::SignMessage { message } => {
            let escrow_message = match message {
                SignMessageOpts::Resolution {
                    escrow_id,
                    outcome,
                    contract_hash,
                } => {
                    let escrow_id_bytes = hex::decode(escrow_id)?;
                    let escrow_id = EscrowId(
                        escrow_id_bytes
                            .try_into()
                            .map_err(|_| anyhow::anyhow!("Invalid escrow_id"))?,
                    );

                    let contract_hash_bytes = hex::decode(contract_hash)?;
                    let contract_hash: [u8; 32] = contract_hash_bytes
                        .try_into()
                        .map_err(|_| anyhow::anyhow!("Invalid contract hash"))?;

                    let federation_id = client.federation_id;

                    EscrowMessage::Resolution {
                        escrow_id,
                        federation_id,
                        outcome,
                        contract_hash: ContractHash(contract_hash),
                    }
                }

                SignMessageOpts::ArbiterEngaged {
                    escrow_id,
                    contract_hash,
                } => {
                    let escrow_id_bytes = hex::decode(escrow_id)?;
                    let escrow_id = EscrowId(
                        escrow_id_bytes
                            .try_into()
                            .map_err(|_| anyhow!("Invalid escrow_id"))?,
                    );

                    let contract_hash_bytes = hex::decode(contract_hash)?;
                    let contract_hash = ContractHash(
                        contract_hash_bytes
                            .try_into()
                            .map_err(|_| anyhow::anyhow!("Invalid contract hash"))?,
                    );
                    let federation_id = client.federation_id;

                    EscrowMessage::ArbiterEngaged {
                        escrow_id,
                        federation_id,
                        contract_hash,
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
