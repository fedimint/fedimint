use std::{ffi, iter};

use anyhow::Context as _;
use bitcoin::hashes::sha256;
use bitcoin::secp256k1;
use clap::{Parser, Subcommand};
use fedimint_core::core::OperationId;
use fedimint_core::util::SafeUrl;
use fedimint_core::{Amount, OutPoint, PeerId, TransactionId, hex};
use fedimint_lnv2_common::contracts::{OutgoingContract, PaymentImage};
use lightning_invoice::Bolt11Invoice;
use secp256k1::schnorr::Signature;
use secp256k1::{Keypair, PublicKey, SecretKey};
use serde::Serialize;
use serde_json::Value;

use crate::api::LightningFederationApi;
use crate::{Bolt11InvoiceDescription, LightningClientModule};

#[derive(Parser, Serialize)]
enum Opts {
    /// Pay an invoice. For  testing  you can optionally specify a gateway to
    /// route with, otherwise a gateway will be selected automatically.
    Send {
        invoice: Bolt11Invoice,
        #[arg(long)]
        gateway: Option<SafeUrl>,
    },
    /// Await the final state of the send operation.
    AwaitSend { operation_id: OperationId },
    /// Request an invoice. For testing you can optionally specify a gateway to
    /// generate the invoice, otherwise a gateway will be selected
    /// automatically.
    Receive {
        amount: Amount,
        #[arg(long)]
        gateway: Option<SafeUrl>,
    },
    /// Await the final state of the receive operation.
    AwaitReceive { operation_id: OperationId },
    /// Lnurl subcommands
    #[command(subcommand)]
    Lnurl(LnurlOpts),
    /// Gateway subcommands
    #[command(subcommand)]
    Gateways(GatewaysOpts),
    /// Direct HTLC subcommands to swap with a counterparty in the same
    /// federation without a gateway
    #[command(subcommand)]
    Htlc(HtlcOpts),
}

#[derive(Clone, Subcommand, Serialize)]
enum HtlcOpts {
    /// Fund an HTLC locked to the counterparty's claim public key. Requires
    /// exactly one of --payment-hash and --payment-point.
    Create {
        amount: Amount,
        claim_pk: PublicKey,
        expiration_delta: u64,
        #[arg(long)]
        payment_hash: Option<sha256::Hash>,
        #[arg(long)]
        payment_point: Option<PublicKey>,
    },
    /// Generate a random claim keypair to receive an HTLC with.
    NewClaimKeypair,
    /// Wait until the contract is funded at the outpoint and print the number
    /// of blocks remaining until its expiration.
    AwaitFunded {
        funding_txid: TransactionId,
        #[arg(long, default_value_t = 0)]
        out_idx: u64,
        contract: String,
    },
    /// Claim a funded HTLC with the preimage of its payment image.
    Claim {
        funding_txid: TransactionId,
        #[arg(long, default_value_t = 0)]
        out_idx: u64,
        contract: String,
        claim_sk: SecretKey,
        preimage: String,
    },
    /// Create a forfeit signature to fail an HTLC locked to our claim key
    /// cooperatively.
    Forfeit {
        contract: String,
        claim_sk: SecretKey,
    },
    /// Cancel an HTLC we created before its expiration with the
    /// counterparty's forfeit signature.
    Cancel {
        funding_txid: TransactionId,
        #[arg(long, default_value_t = 0)]
        out_idx: u64,
        contract: String,
        forfeit_signature: Signature,
    },
    /// Refund an HTLC we created after its expiration.
    Refund {
        funding_txid: TransactionId,
        #[arg(long, default_value_t = 0)]
        out_idx: u64,
        contract: String,
    },
    /// Wait until an HTLC we created is claimed, printing the preimage, or
    /// expired unclaimed, printing null.
    AwaitResolution {
        funding_txid: TransactionId,
        #[arg(long, default_value_t = 0)]
        out_idx: u64,
        contract: String,
    },
    /// Wait until the transaction of an HTLC operation is accepted and any
    /// ecash it issues has been minted.
    AwaitSettled { operation_id: OperationId },
}

#[derive(Clone, Subcommand, Serialize)]
enum LnurlOpts {
    /// Generate a new lnurl.
    Generate {
        recurringd: SafeUrl,
        #[arg(long)]
        gateway: Option<SafeUrl>,
    },
}

#[derive(Clone, Subcommand, Serialize)]
enum GatewaysOpts {
    /// Update the mapping from lightning node public keys to gateway api
    /// endpoints maintained in the module database to optimise gateway
    /// selection for a given invoice; this command is intended for testing.
    Map,
    /// Select an online vetted gateway; this command is intended for testing.
    Select {
        #[arg(long)]
        invoice: Option<Bolt11Invoice>,
    },
    /// List all vetted gateways.
    List {
        #[arg(long)]
        peer: Option<PeerId>,
    },
    /// Add a vetted gateway.
    Add { gateway: SafeUrl },
    /// Remove a vetted gateway.
    Remove { gateway: SafeUrl },
}

pub(crate) async fn handle_cli_command(
    lightning: &LightningClientModule,
    args: &[ffi::OsString],
) -> anyhow::Result<serde_json::Value> {
    let opts = Opts::parse_from(iter::once(&ffi::OsString::from("lnv2")).chain(args.iter()));

    let value = match opts {
        Opts::Send { gateway, invoice } => {
            json(lightning.send(invoice, gateway, Value::Null).await?)
        }
        Opts::AwaitSend { operation_id } => json(
            lightning
                .await_final_send_operation_state(operation_id)
                .await?,
        ),
        Opts::Receive { amount, gateway } => json(
            lightning
                .receive(
                    amount,
                    3600,
                    Bolt11InvoiceDescription::Direct(String::new()),
                    gateway,
                    Value::Null,
                )
                .await?,
        ),
        Opts::AwaitReceive { operation_id } => json(
            lightning
                .await_final_receive_operation_state(operation_id)
                .await?,
        ),
        Opts::Lnurl(lnurl_opts) => match lnurl_opts {
            LnurlOpts::Generate {
                recurringd,
                gateway,
            } => json(lightning.generate_lnurl(recurringd, gateway).await?),
        },
        Opts::Gateways(gateway_opts) => match gateway_opts {
            #[allow(clippy::unit_arg)]
            GatewaysOpts::Map => json(lightning.update_gateway_map().await),
            GatewaysOpts::Select { invoice } => json(lightning.select_gateway(invoice).await?.0),
            GatewaysOpts::List { peer } => json(lightning.list_gateways(peer).await?),
            GatewaysOpts::Add { gateway } => {
                let auth = lightning
                    .admin_auth
                    .clone()
                    .ok_or(anyhow::anyhow!("Admin auth not set"))?;

                json(lightning.module_api.add_gateway(auth, gateway).await?)
            }
            GatewaysOpts::Remove { gateway } => {
                let auth = lightning
                    .admin_auth
                    .clone()
                    .ok_or(anyhow::anyhow!("Admin auth not set"))?;

                json(lightning.module_api.remove_gateway(auth, gateway).await?)
            }
        },
        Opts::Htlc(htlc_opts) => handle_htlc_command(lightning, htlc_opts).await?,
    };

    Ok(value)
}

#[allow(clippy::too_many_lines)]
async fn handle_htlc_command(
    lightning: &LightningClientModule,
    htlc_opts: HtlcOpts,
) -> anyhow::Result<Value> {
    let value = match htlc_opts {
        HtlcOpts::Create {
            amount,
            claim_pk,
            expiration_delta,
            payment_hash,
            payment_point,
        } => {
            let payment_image = match (payment_hash, payment_point) {
                (Some(hash), None) => PaymentImage::Hash(hash),
                (None, Some(point)) => PaymentImage::Point(point),
                _ => anyhow::bail!("Specify exactly one of --payment-hash and --payment-point"),
            };

            let (operation_id, outpoint, contract) = lightning
                .create_htlc(
                    amount,
                    payment_image,
                    claim_pk,
                    expiration_delta,
                    Value::Null,
                )
                .await?;

            json(serde_json::json!({
                "operation_id": operation_id,
                "outpoint": outpoint,
                "contract": contract,
            }))
        }
        HtlcOpts::NewClaimKeypair => {
            let keypair = Keypair::new(secp256k1::SECP256K1, &mut rand::thread_rng());

            json(serde_json::json!({
                "secret_key": keypair.secret_key().display_secret().to_string(),
                "public_key": keypair.public_key(),
            }))
        }
        HtlcOpts::AwaitFunded {
            funding_txid,
            out_idx,
            contract,
        } => json(
            lightning
                .await_htlc_funded(outpoint(funding_txid, out_idx), &parse_contract(&contract)?)
                .await?,
        ),
        HtlcOpts::Claim {
            funding_txid,
            out_idx,
            contract,
            claim_sk,
            preimage,
        } => json(
            lightning
                .claim_htlc(
                    outpoint(funding_txid, out_idx),
                    parse_contract(&contract)?,
                    claim_sk.keypair(secp256k1::SECP256K1),
                    parse_preimage(&preimage)?,
                    Value::Null,
                )
                .await?,
        ),
        HtlcOpts::Forfeit { contract, claim_sk } => {
            json(LightningClientModule::create_htlc_forfeit_signature(
                &parse_contract(&contract)?,
                &claim_sk.keypair(secp256k1::SECP256K1),
            )?)
        }
        HtlcOpts::Cancel {
            funding_txid,
            out_idx,
            contract,
            forfeit_signature,
        } => json(
            lightning
                .cancel_htlc(
                    outpoint(funding_txid, out_idx),
                    parse_contract(&contract)?,
                    forfeit_signature,
                    Value::Null,
                )
                .await?,
        ),
        HtlcOpts::Refund {
            funding_txid,
            out_idx,
            contract,
        } => json(
            lightning
                .refund_htlc(
                    outpoint(funding_txid, out_idx),
                    parse_contract(&contract)?,
                    Value::Null,
                )
                .await?,
        ),
        HtlcOpts::AwaitResolution {
            funding_txid,
            out_idx,
            contract,
        } => json(
            lightning
                .await_htlc_resolution(outpoint(funding_txid, out_idx), &parse_contract(&contract)?)
                .await?
                .map(hex::encode),
        ),
        HtlcOpts::AwaitSettled { operation_id } => {
            lightning.await_htlc_operation_settled(operation_id).await?;

            json("settled")
        }
    };

    Ok(value)
}

fn outpoint(txid: TransactionId, out_idx: u64) -> OutPoint {
    OutPoint { txid, out_idx }
}

fn parse_contract(contract: &str) -> anyhow::Result<OutgoingContract> {
    serde_json::from_str(contract).context("Failed to parse the contract JSON")
}

fn parse_preimage(preimage: &str) -> anyhow::Result<[u8; 32]> {
    <[u8; 32]>::try_from(hex::decode(preimage).context("The preimage is not valid hex")?)
        .map_err(|_| anyhow::anyhow!("The preimage must be exactly 32 bytes"))
}

fn json<T: Serialize>(value: T) -> Value {
    serde_json::to_value(value).expect("JSON serialization failed")
}
