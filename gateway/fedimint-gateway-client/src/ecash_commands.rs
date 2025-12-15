use bitcoin::Address;
use bitcoin::address::NetworkUnchecked;
use clap::Subcommand;
use fedimint_core::config::FederationId;
use fedimint_core::util::SafeUrl;
use fedimint_core::{Amount, BitcoinAmountOrAll};
use fedimint_gateway_client::{
    backup, get_deposit_address, receive_ecash, recheck_address, spend_ecash, withdraw,
};
use fedimint_gateway_common::{
    BackupPayload, DepositAddressPayload, DepositAddressRecheckPayload, ReceiveEcashPayload,
    SpendEcashPayload, WithdrawPayload,
};
use fedimint_ln_common::client::GatewayApi;
use fedimint_mint_client::OOBNotes;

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
    /// Trigger a recheck for deposits on a deposit address
    PeginRecheck {
        #[clap(long)]
        address: bitcoin::Address<NetworkUnchecked>,
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
    pub async fn handle(self, client: &GatewayApi, base_url: &SafeUrl) -> anyhow::Result<()> {
        match self {
            Self::Backup { federation_id } => {
                backup(client, base_url, BackupPayload { federation_id }).await?;
            }
            Self::Pegin { federation_id } => {
                let response =
                    get_deposit_address(client, base_url, DepositAddressPayload { federation_id })
                        .await?;

                print_response(response);
            }
            Self::PeginRecheck {
                address,
                federation_id,
            } => {
                let response = recheck_address(
                    client,
                    base_url,
                    DepositAddressRecheckPayload {
                        address,
                        federation_id,
                    },
                )
                .await?;
                print_response(response);
            }
            Self::Pegout {
                federation_id,
                amount,
                address,
            } => {
                let response = withdraw(
                    client,
                    base_url,
                    WithdrawPayload {
                        federation_id,
                        amount,
                        address,
                        quoted_fees: None,
                    },
                )
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
                let response = spend_ecash(
                    client,
                    base_url,
                    SpendEcashPayload {
                        federation_id,
                        amount,
                        allow_overpay,
                        timeout,
                        include_invite,
                    },
                )
                .await?;

                print_response(response);
            }
            Self::Receive { notes, wait } => {
                let response =
                    receive_ecash(client, base_url, ReceiveEcashPayload { notes, wait }).await?;
                print_response(response);
            }
        }

        Ok(())
    }
}
