use bitcoin::address::NetworkUnchecked;
use clap::Subcommand;
use fedimint_core::BitcoinAmountOrAll;
use fedimint_gateway_client::{get_ln_onchain_address, send_onchain};
use fedimint_gateway_common::SendOnchainRequest;

use crate::{GatewayRpcClient, print_response};

#[derive(Subcommand)]
pub enum OnchainCommands {
    /// Get a Bitcoin address from the gateway's lightning node's onchain
    /// wallet.
    Address,
    /// Send funds from the lightning node's on-chain wallet to a specified
    /// address.
    Send {
        /// The address to withdraw funds to.
        #[clap(long)]
        address: bitcoin::Address<NetworkUnchecked>,

        /// The amount to withdraw.
        /// Can be "all" to withdraw all funds, an amount + unit (e.g. "1000
        /// sats"), or a raw amount (e.g. "1000") which is denominated in
        /// millisats.
        #[clap(long)]
        amount: BitcoinAmountOrAll,

        /// The fee rate to use in satoshis per vbyte.
        #[clap(long)]
        fee_rate_sats_per_vbyte: u64,
    },
}

impl OnchainCommands {
    pub async fn handle(self, client: &GatewayRpcClient) -> anyhow::Result<()> {
        match self {
            Self::Address => {
                let response = get_ln_onchain_address(client).await?.assume_checked();
                println!("{response}");
            }
            Self::Send {
                address,
                amount,
                fee_rate_sats_per_vbyte,
            } => {
                let response = send_onchain(
                    client,
                    SendOnchainRequest {
                        address,
                        amount,
                        fee_rate_sats_per_vbyte,
                    },
                )
                .await?;
                print_response(response);
            }
        }

        Ok(())
    }
}
