use bitcoin::hashes::sha256;
use chrono::{DateTime, Utc};
use clap::Subcommand;
use fedimint_core::Amount;
use fedimint_gateway_client::{
    close_channels_with_peer, create_invoice_for_self, create_offer, get_invoice, list_channels,
    list_transactions, open_channel, pay_invoice, pay_offer,
};
use fedimint_gateway_common::{
    CloseChannelsWithPeerRequest, CreateInvoiceForOperatorPayload, CreateOfferPayload,
    GetInvoiceRequest, ListTransactionsPayload, OpenChannelRequest, PayInvoiceForOperatorPayload,
    PayOfferPayload,
};
use fedimint_ln_common::client::GatewayApi;
use lightning_invoice::Bolt11Invoice;

use crate::{SafeUrl, print_response};

/// This API is intentionally kept very minimal, as its main purpose is to
/// provide a simple and consistent way to establish liquidity between gateways
/// in a test environment.
#[derive(Subcommand)]
pub enum LightningCommands {
    /// Create an invoice to receive lightning funds to the gateway.
    CreateInvoice {
        amount_msats: u64,

        #[clap(long)]
        expiry_secs: Option<u32>,

        #[clap(long)]
        description: Option<String>,
    },
    /// Pay a lightning invoice as the gateway (i.e. no e-cash exchange).
    PayInvoice { invoice: Bolt11Invoice },
    /// Open a channel with another lightning node.
    OpenChannel {
        /// The public key of the node to open a channel with
        #[clap(long)]
        pubkey: bitcoin::secp256k1::PublicKey,

        #[clap(long)]
        host: String,

        /// The amount to fund the channel with
        #[clap(long)]
        channel_size_sats: u64,

        /// The amount to push to the other side of the channel
        #[clap(long)]
        push_amount_sats: Option<u64>,
    },
    /// Close all channels with a peer, claiming the funds to the lightning
    /// node's on-chain wallet.
    CloseChannelsWithPeer {
        // The public key of the node to close channels with
        #[clap(long)]
        pubkey: bitcoin::secp256k1::PublicKey,

        #[clap(long)]
        force: bool,
    },
    /// List channels.
    ListChannels,
    /// List the Lightning transactions that the Lightning node has received and
    /// sent
    ListTransactions {
        /// The timestamp to start listing transactions from (e.g.,
        /// "2025-03-14T15:30:00Z")
        #[arg(long, value_parser = parse_datetime)]
        start_time: DateTime<Utc>,

        /// The timestamp to end listing transactions from (e.g.,
        /// "2025-03-15T15:30:00Z")
        #[arg(long, value_parser = parse_datetime)]
        end_time: DateTime<Utc>,
    },
    /// Get details about a specific invoice
    GetInvoice {
        /// The payment hash of the invoice
        #[clap(long)]
        payment_hash: sha256::Hash,
    },
    CreateOffer {
        #[clap(long)]
        amount_msat: Option<u64>,

        #[clap(long)]
        description: Option<String>,

        #[clap(long)]
        expiry_secs: Option<u32>,

        #[clap(long)]
        quantity: Option<u64>,
    },
    PayOffer {
        #[clap(long)]
        offer: String,

        #[clap(long)]
        amount_msat: Option<u64>,

        #[clap(long)]
        quantity: Option<u64>,

        #[clap(long)]
        payer_note: Option<String>,
    },
}

fn parse_datetime(s: &str) -> Result<DateTime<Utc>, chrono::ParseError> {
    s.parse::<DateTime<Utc>>()
}

impl LightningCommands {
    #![allow(clippy::too_many_lines)]
    pub async fn handle(self, client: &GatewayApi, base_url: &SafeUrl) -> anyhow::Result<()> {
        match self {
            Self::CreateInvoice {
                amount_msats,
                expiry_secs,
                description,
            } => {
                let response = create_invoice_for_self(
                    client,
                    base_url,
                    CreateInvoiceForOperatorPayload {
                        amount_msats,
                        expiry_secs,
                        description,
                    },
                )
                .await?;
                println!("{response}");
            }
            Self::PayInvoice { invoice } => {
                let response =
                    pay_invoice(client, base_url, PayInvoiceForOperatorPayload { invoice }).await?;
                println!("{response}");
            }
            Self::OpenChannel {
                pubkey,
                host,
                channel_size_sats,
                push_amount_sats,
            } => {
                let funding_txid = open_channel(
                    client,
                    base_url,
                    OpenChannelRequest {
                        pubkey,
                        host,
                        channel_size_sats,
                        push_amount_sats: push_amount_sats.unwrap_or(0),
                    },
                )
                .await?;
                println!("{funding_txid}");
            }
            Self::CloseChannelsWithPeer { pubkey, force } => {
                let response = close_channels_with_peer(
                    client,
                    base_url,
                    CloseChannelsWithPeerRequest { pubkey, force },
                )
                .await?;
                print_response(response);
            }
            Self::ListChannels => {
                let response = list_channels(client, base_url).await?;
                print_response(response);
            }
            Self::GetInvoice { payment_hash } => {
                let response =
                    get_invoice(client, base_url, GetInvoiceRequest { payment_hash }).await?;
                print_response(response);
            }
            Self::ListTransactions {
                start_time,
                end_time,
            } => {
                let start_secs = start_time.timestamp().try_into()?;
                let end_secs = end_time.timestamp().try_into()?;
                let response = list_transactions(
                    client,
                    base_url,
                    ListTransactionsPayload {
                        start_secs,
                        end_secs,
                    },
                )
                .await?;
                print_response(response);
            }
            Self::CreateOffer {
                amount_msat,
                description,
                expiry_secs,
                quantity,
            } => {
                let response = create_offer(
                    client,
                    base_url,
                    CreateOfferPayload {
                        amount: amount_msat.map(Amount::from_msats),
                        description,
                        expiry_secs,
                        quantity,
                    },
                )
                .await?;
                print_response(response);
            }
            Self::PayOffer {
                offer,
                amount_msat,
                quantity,
                payer_note,
            } => {
                let response = pay_offer(
                    client,
                    base_url,
                    PayOfferPayload {
                        offer,
                        amount: amount_msat.map(Amount::from_msats),
                        quantity,
                        payer_note,
                    },
                )
                .await?;
                print_response(response);
            }
        }

        Ok(())
    }
}
