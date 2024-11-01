use bitcoin::address::NetworkUnchecked;
use clap::Subcommand;
use fedimint_core::BitcoinAmountOrAll;
use ln_gateway::rpc::rpc_client::GatewayRpcClient;
use ln_gateway::rpc::WithdrawOnchainPayload;

use crate::print_response;

#[derive(Subcommand)]
pub enum OnchainCommands {
    /// Get a Bitcoin address from the gateway's lightning node's onchain
    /// wallet.
    Address,
    /// Withdraw funds from the lightning node's on-chain wallet to a specified
    /// address.
    Withdraw {
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
    pub async fn handle(
        self,
        create_client: impl Fn() -> GatewayRpcClient + Send + Sync,
    ) -> anyhow::Result<()> {
        match self {
            Self::Address => {
                let response = create_client()
                    .get_ln_onchain_address()
                    .await?
                    .assume_checked();
                println!("{response}");
            }
            Self::Withdraw {
                address,
                amount,
                fee_rate_sats_per_vbyte,
            } => {
                let response = create_client()
                    .withdraw_onchain(WithdrawOnchainPayload {
                        address,
                        amount,
                        fee_rate_sats_per_vbyte,
                    })
                    .await?;
                print_response(response);
            }
        }

        Ok(())
    }
}
