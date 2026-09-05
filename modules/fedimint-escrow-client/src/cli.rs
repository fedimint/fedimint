use std::time::Duration;
use std::{ffi, iter};

use anyhow::Ok;
use clap::Parser;
use fedimint_core::secp256k1::schnorr;
use fedimint_core::{Amount, secp256k1};
use fedimint_escrow_common::{ContractHash, EscrowId, EscrowMessage, Outcome};
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
    ClaimArbiterFee {
        escrow_id: String,
        arbiter_signature: String,
    },

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
        federation_id: String,

        #[clap(long)]
        outcome: Outcome,

        #[clap(long)]
        contract_hash: String,
    },

    ArbiterFeeClaim {
        #[clap(long)]
        escrow_id: String,

        #[clap(long)]
        fee_msats: Amount,
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
            amount_sats,
            timeout,
        } => {
            let result = client
                .create_escrow(
                    recipient_key,
                    arbiter_key,
                    arbiter_fee_msats,
                    Amount::from_sats(amount_sats),
                    Duration::from_secs(timeout),
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
                    EscrowInputSMState::Failed { reason } => {
                        return Err(anyhow::anyhow!("Escrow creation failed: {reason}"));
                    }
                    EscrowInputSMState::FeeClaimed => {}
                    EscrowInputSMState::FeeClaiming => {}
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
                    EscrowInputSMState::Failed { reason } => {
                        return Err(anyhow::anyhow!("Escrow creation failed: {reason}"));
                    }
                    EscrowInputSMState::FeeClaimed => {}
                    EscrowInputSMState::FeeClaiming => {}
                    EscrowInputSMState::Disputed => {}
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
                    EscrowInputSMState::Disputed => {}
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
        Opts::SignMessage { message } => {
            let escrow_message = match message {
                SignMessageOpts::Resolution {
                    escrow_id,
                    federation_id,
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

                    let federation_id = federation_id.parse()?;

                    EscrowMessage::Resolution {
                        escrow_id,
                        federation_id,
                        outcome,
                        contract_hash: ContractHash(contract_hash),
                    }
                }

                SignMessageOpts::ArbiterFeeClaim {
                    escrow_id,
                    fee_msats,
                } => {
                    let escrow_id_bytes = hex::decode(escrow_id)?;
                    let escrow_id = EscrowId(
                        escrow_id_bytes
                            .try_into()
                            .map_err(|_| anyhow::anyhow!("Invalid escrow_id"))?,
                    );

                    EscrowMessage::ArbiterFeeClaim {
                        escrow_id,
                        fee_amount: fee_msats,
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
