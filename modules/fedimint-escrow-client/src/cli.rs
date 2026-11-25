use std::time::Duration;
use std::{ffi, iter};

use clap::Parser;
use fedimint_client_module::OperationId;
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
    /// Create a new escrow contract with the parties, fees, arbiter fee keys,
    /// amount, timeout, resolution deadline and a default fallback
    Create {
        #[clap(long, short = 'r')]
        recipient_key: secp256k1::PublicKey,
        #[clap(long, short = 'a')]
        arbiter_key: secp256k1::PublicKey,
        #[clap(long, short = 'f')]
        arbiter_fee: u64,
        #[clap(long, short = 'k')]
        arbiter_fee_key: Vec<PublicKey>,
        #[clap(long, short = 'm')]
        amount_sats: u64,
        #[clap(long, short = 't')]
        timeout: u64,
        #[clap(long, short = 'd')]
        resolution_deadline: u64,
        #[clap(long, short = 'p')]
        default_fallback: FallbackPolicy,
    },

    /// Get the escrow contract for the escrow_id
    GetContract {
        #[clap(long, visible_alias = "id")]
        escrow_id: EscrowId,
    },

    /// List escrow contracts associated with the client
    ListEscrow {
        pubkey: Option<PublicKey>,
        limit: Option<u32>,
        last_seen: Option<EscrowId>,
    },

    /// Release an escrow using the funder's signature
    ResolveEscrow {
        #[clap(long, visible_alias = "id")]
        escrow_id: EscrowId,
        #[clap(long, short = 's')]
        signature: Signature,
    },

    /// Resolve the escrow with the arbiter outcome
    SubmitArbiterDecision {
        #[clap(long, visible_alias = "id")]
        escrow_id: EscrowId,
        #[clap(long, short = 'o')]
        outcome: Outcome,
        #[clap(long, short = 's')]
        arbiter_signature: Signature,
    },

    /// Engaging the arbiter will get the contract in disputed state, resolution
    /// timeout is calculated from when the contract goes in disputed state
    EngageArbiter {
        #[clap(long, visible_alias = "id")]
        escrow_id: EscrowId,
    },

    /// Either party (funder or recipient) can trigger fallback after the
    /// resolution deadline for a disputed contract.
    TriggerFallback {
        #[clap(long, visible_alias = "id")]
        escrow_id: EscrowId,
    },

    /// Parties including the arbiter can claim their payouts for the escrow
    ClaimPayout {
        #[clap(long, visible_alias = "id")]
        escrow_id: EscrowId,
    },

    /// Sign a resolution message or arbiter engagement signature
    SignMessage {
        #[command(subcommand)]
        message: SignMessageOpts,
    },
}

#[derive(clap::Subcommand, Serialize)]
enum SignMessageOpts {
    /// Sign resolution message for the given escrow with the outcome
    Resolution {
        #[clap(long, visible_alias = "id")]
        escrow_id: EscrowId,

        #[clap(long, short = 'o')]
        outcome: Outcome,
    },

    /// Sign message to engage the arbiter for the given escrow
    ArbiterEngaged {
        #[clap(long, visible_alias = "id")]
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
            arbiter_fee,
            arbiter_fee_key,
            amount_sats,
            timeout,
            resolution_deadline,
            default_fallback,
        } => {
            create(
                client,
                recipient_key,
                arbiter_key,
                arbiter_fee,
                arbiter_fee_key,
                amount_sats,
                timeout,
                resolution_deadline,
                default_fallback,
            )
            .await
        }
        Opts::GetContract { escrow_id } => {
            let contract = client.get_contract(escrow_id).await?;
            Ok(serde_json::to_value(contract)?)
        }
        Opts::ListEscrow {
            pubkey,
            limit,
            last_seen,
        } => {
            let contracts = client.list_contracts(pubkey, limit, last_seen).await?;
            Ok(serde_json::to_value(contracts)?)
        }
        Opts::EngageArbiter { escrow_id } => engage_arbiter(client, escrow_id).await,
        Opts::ResolveEscrow {
            escrow_id,
            signature,
        } => resolve_escrow(client, escrow_id, signature).await,
        Opts::SubmitArbiterDecision {
            escrow_id,
            outcome,
            arbiter_signature,
        } => submit_arbiter_decision(client, escrow_id, outcome, arbiter_signature).await,
        Opts::ClaimPayout { escrow_id } => claim_payout(client, escrow_id).await,
        Opts::TriggerFallback { escrow_id } => trigger_fallback(client, escrow_id).await,
        Opts::SignMessage { message } => sign_message(client, message).await,
    }
}

fn operation_json(operation_id: OperationId) -> serde_json::Value {
    serde_json::json!({
        "operation_id": operation_id
    })
}

async fn wait_for_input_state(
    mut stream: impl futures::Stream<Item = EscrowInputSMState> + Unpin,
    what: &str,
    is_done: impl Fn(&EscrowInputSMState) -> bool,
) -> anyhow::Result<()> {
    while let Some(state) = stream.next().await {
        if let EscrowInputSMState::Failed { reason } = &state {
            return Err(anyhow::anyhow!("{what}: {reason}"));
        }
        if is_done(&state) {
            break;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn create(
    client: &EscrowClientModule,
    recipient_key: PublicKey,
    arbiter_key: PublicKey,
    arbiter_fee: u64,
    arbiter_fee_key: Vec<PublicKey>,
    amount_sats: u64,
    timeout: u64,
    resolution_deadline: u64,
    default_fallback: FallbackPolicy,
) -> anyhow::Result<serde_json::Value> {
    let result = client
        .create_escrow(
            None,
            recipient_key,
            arbiter_key,
            Amount::from_sats(arbiter_fee),
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

async fn engage_arbiter(
    client: &EscrowClientModule,
    escrow_id: EscrowId,
) -> anyhow::Result<serde_json::Value> {
    let operation_id = client.engage_arbiter(escrow_id, None).await?;

    let stream = client
        .subscribe_escrow_resolution(operation_id)
        .await?
        .into_stream();
    wait_for_input_state(stream, "arbiter engagement failed", |state| {
        matches!(state, EscrowInputSMState::Disputed)
    })
    .await?;

    Ok(operation_json(operation_id))
}

async fn resolve_escrow(
    client: &EscrowClientModule,
    escrow_id: EscrowId,
    signature: Signature,
) -> anyhow::Result<serde_json::Value> {
    let operation_id = client.resolve_escrow(escrow_id, signature, None).await?;

    let stream = client
        .subscribe_escrow_resolution(operation_id)
        .await?
        .into_stream();
    wait_for_input_state(stream, "Escrow resolution failed", |state| {
        matches!(
            state,
            EscrowInputSMState::Released | EscrowInputSMState::Refunded
        )
    })
    .await?;

    Ok(operation_json(operation_id))
}

async fn submit_arbiter_decision(
    client: &EscrowClientModule,
    escrow_id: EscrowId,
    outcome: Outcome,
    arbiter_signature: Signature,
) -> anyhow::Result<serde_json::Value> {
    let operation_id = client
        .submit_arbiter_decision(escrow_id, outcome, arbiter_signature, None)
        .await?;

    let stream = client
        .subscribe_escrow_resolution(operation_id)
        .await?
        .into_stream();
    wait_for_input_state(stream, "Escrow arbiter resolution failed", |state| {
        matches!(
            state,
            EscrowInputSMState::Refunded | EscrowInputSMState::Released | EscrowInputSMState::Split
        )
    })
    .await?;

    Ok(operation_json(operation_id))
}

async fn claim_payout(
    client: &EscrowClientModule,
    escrow_id: EscrowId,
) -> anyhow::Result<serde_json::Value> {
    let operation_id = client.claim_payout(escrow_id, None).await?;

    let stream = client
        .subscribe_claim_payout(operation_id)
        .await?
        .into_stream();
    wait_for_input_state(stream, "escrow claim payout failed", |state| {
        matches!(state, EscrowInputSMState::Claimed)
    })
    .await?;

    Ok(operation_json(operation_id))
}

async fn trigger_fallback(
    client: &EscrowClientModule,
    escrow_id: EscrowId,
) -> anyhow::Result<serde_json::Value> {
    let operation_id = client.trigger_fallback(escrow_id, None).await?;

    let stream = client
        .subscribe_escrow_resolution(operation_id)
        .await?
        .into_stream();
    wait_for_input_state(stream, "Escrow fallback resolution failed", |state| {
        matches!(
            state,
            EscrowInputSMState::Refunded
                | EscrowInputSMState::Released
                | EscrowInputSMState::Disputed
                | EscrowInputSMState::Split
        )
    })
    .await?;

    Ok(operation_json(operation_id))
}

async fn contract_hash(
    client: &EscrowClientModule,
    escrow_id: EscrowId,
) -> anyhow::Result<fedimint_escrow_common::ContractHash> {
    let contract = client
        .get_contract(escrow_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Contract not found for this escrow_id"))?;
    Ok(contract.contract_hash)
}

async fn sign_message(
    client: &EscrowClientModule,
    message: SignMessageOpts,
) -> anyhow::Result<serde_json::Value> {
    let federation_id = client.federation_id;
    let escrow_message = match message {
        SignMessageOpts::Resolution { escrow_id, outcome } => EscrowMessage::Resolution {
            escrow_id,
            federation_id,
            outcome,
            contract_hash: contract_hash(client, escrow_id).await?,
        },
        SignMessageOpts::ArbiterEngaged { escrow_id } => EscrowMessage::ArbiterEngaged {
            escrow_id,
            federation_id,
            contract_hash: contract_hash(client, escrow_id).await?,
        },
    };

    let sig = client.sign_message(escrow_message)?;

    Ok(serde_json::json!({
        "signature": sig.to_string(),
    }))
}
