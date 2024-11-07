use bitcoin::address::NetworkUnchecked;
use bitcoin::Address;
use clap::Subcommand;
use fedimint_core::config::FederationId;
use fedimint_core::{Amount, BitcoinAmountOrAll};
use fedimint_mint_client::OOBNotes;
use ln_gateway::rpc::rpc_client::GatewayRpcClient;
use ln_gateway::rpc::{
    BackupPayload, DepositAddressPayload, ReceiveEcashPayload, SpendEcashPayload, WithdrawPayload,
};

use crate::print_response;

#[derive(Subcommand)]
pub enum EcashCommands {
    /// Make a backup of snapshot of all e-cash.
    Backup {
        #[clap(long)]
        federation_id: FederationId,
    },
    /// Generate a new peg-in address to a federation that the gateway can claim
    /// e-cash for later.
    Pegin {
        #[clap(long)]
        federation_id: FederationId,
    },
    /// Claim funds from a gateway federation to an on-chain address.
    Pegout {
        #[clap(long)]
        federation_id: FederationId,
        /// The amount to withdraw
        #[clap(long)]
        amount: BitcoinAmountOrAll,
        /// The address to send the funds to
        #[clap(long)]
        address: Address<NetworkUnchecked>,
    },
    /// Send e-cash out of band
    Send {
        #[clap(long)]
        federation_id: FederationId,
        amount: Amount,
        #[clap(long)]
        allow_overpay: bool,
        #[clap(long, default_value_t = 60 * 60 * 24 * 7)]
        timeout: u64,
        #[clap(long)]
        include_invite: bool,
    },
    /// Receive e-cash out of band
    Receive {
        #[clap(long)]
        notes: OOBNotes,
        #[arg(long = "no-wait", action = clap::ArgAction::SetFalse)]
        wait: bool,
    },
}

impl EcashCommands {
    pub async fn handle(
        self,
        create_client: impl Fn() -> GatewayRpcClient + Send + Sync,
    ) -> anyhow::Result<()> {
        match self {
            Self::Backup { federation_id } => {
                create_client()
                    .backup(BackupPayload { federation_id })
                    .await?;
            }
            Self::Pegin { federation_id } => {
                let response = create_client()
                    .get_deposit_address(DepositAddressPayload { federation_id })
                    .await?;

                print_response(response);
            }
            Self::Pegout {
                federation_id,
                amount,
                address,
            } => {
                let response = create_client()
                    .withdraw(WithdrawPayload {
                        federation_id,
                        amount,
                        address,
                    })
                    .await?;

                print_response(response);
            }
            Self::Send {
                federation_id,
                amount,
                allow_overpay,
                timeout,
                include_invite,
            } => {
                let response = create_client()
                    .spend_ecash(SpendEcashPayload {
                        federation_id,
                        amount,
                        allow_overpay,
                        timeout,
                        include_invite,
                    })
                    .await?;

                print_response(response);
            }
            Self::Receive { notes, wait } => {
                let response = create_client()
                    .receive_ecash(ReceiveEcashPayload { notes, wait })
                    .await?;
                print_response(response);
            }
        }

        Ok(())
    }
}
