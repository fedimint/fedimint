use clap::Subcommand;
use lightning_invoice::Bolt11Invoice;
use ln_gateway::rpc::rpc_client::GatewayRpcClient;
use ln_gateway::rpc::{CloseChannelsWithPeerPayload, OpenChannelPayload};

use crate::print_response;

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
    },
    /// List active channels.
    ListActiveChannels,
}

impl LightningCommands {
    #![allow(clippy::too_many_lines)]
    pub async fn handle(
        self,
        create_client: impl Fn() -> GatewayRpcClient + Send + Sync,
    ) -> anyhow::Result<()> {
        match self {
            Self::CreateInvoice {
                amount_msats,
                expiry_secs,
                description,
            } => {
                let response = create_client()
                    .create_invoice_for_self(ln_gateway::rpc::CreateInvoiceForOperatorPayload {
                        amount_msats,
                        expiry_secs,
                        description,
                    })
                    .await?;
                println!("{response}");
            }
            Self::PayInvoice { invoice } => {
                let response = create_client()
                    .pay_invoice(ln_gateway::rpc::PayInvoiceForOperatorPayload { invoice })
                    .await?;
                println!("{response}");
            }
            Self::OpenChannel {
                pubkey,
                host,
                channel_size_sats,
                push_amount_sats,
            } => {
                let funding_txid = create_client()
                    .open_channel(OpenChannelPayload {
                        pubkey,
                        host,
                        channel_size_sats,
                        push_amount_sats: push_amount_sats.unwrap_or(0),
                    })
                    .await?;
                println!("{funding_txid}");
            }
            Self::CloseChannelsWithPeer { pubkey } => {
                let response = create_client()
                    .close_channels_with_peer(CloseChannelsWithPeerPayload { pubkey })
                    .await?;
                print_response(response);
            }
            Self::ListActiveChannels => {
                let response = create_client().list_active_channels().await?;
                print_response(response);
            }
        };

        Ok(())
    }
}
