use bitcoin::Address;
use bitcoin::address::NetworkUnchecked;
use clap::Subcommand;
use fedimint_core::config::FederationId;
use fedimint_core::util::SafeUrl;
use fedimint_core::{Amount, BitcoinAmountOrAll};
use fedimint_gateway_client::{
    backup, get_deposit_address, pegin_from_onchain, receive_ecash, recheck_address, spend_ecash,
    withdraw, withdraw_to_onchain,
};
use fedimint_gateway_common::{
    BackupPayload, DepositAddressPayload, DepositAddressRecheckPayload, PeginFromOnchainPayload,
    ReceiveEcashPayload, SpendEcashPayload, WithdrawPayload, WithdrawToOnchainPayload,
};
use fedimint_ln_common::client::GatewayApi;
use fedimint_mint_client::OOBNotes;

use crate::{CliOutput, CliOutputResult};

/// Ecash management commands for pegging funds into a federation, pegging funds
/// out of a federation, or spending/receiving ecash.
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
    /// Send funds from the gateway's onchain wallet to the federation's ecash
    /// wallet
    PeginFromOnchain {
        #[clap(long)]
        federation_id: FederationId,
        /// The amount to pegin
        #[clap(long)]
        amount: BitcoinAmountOrAll,
        /// The fee rate to use in satoshis per vbyte.
        #[clap(long)]
        fee_rate_sats_per_vbyte: u64,
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
    /// Claim funds from a gateway federation to the gateway's onchain wallet
    PegoutToOnchain {
        #[clap(long)]
        federation_id: FederationId,
        /// The amount to withdraw
        #[clap(long)]
        amount: BitcoinAmountOrAll,
    },
    /// Send e-cash out of band
    Send {
        #[clap(long)]
        federation_id: FederationId,
        amount: Amount,
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
    pub async fn handle(self, client: &GatewayApi, base_url: &SafeUrl) -> CliOutputResult {
        match self {
            Self::Backup { federation_id } => {
                backup(client, base_url, BackupPayload { federation_id }).await?;
                Ok(CliOutput::Empty)
            }
            Self::Pegin { federation_id } => {
                let address =
                    get_deposit_address(client, base_url, DepositAddressPayload { federation_id })
                        .await?;

                Ok(CliOutput::DepositAddress { address })
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
                Ok(CliOutput::DepositRecheck(response))
            }
            Self::PeginFromOnchain {
                federation_id,
                amount,
                fee_rate_sats_per_vbyte,
            } => {
                let txid = pegin_from_onchain(
                    client,
                    base_url,
                    PeginFromOnchainPayload {
                        federation_id,
                        amount,
                        fee_rate_sats_per_vbyte,
                    },
                )
                .await?;

                Ok(CliOutput::PeginTxid { txid })
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

                Ok(CliOutput::Withdraw(response))
            }
            Self::PegoutToOnchain {
                federation_id,
                amount,
            } => {
                let response = withdraw_to_onchain(
                    client,
                    base_url,
                    WithdrawToOnchainPayload {
                        federation_id,
                        amount,
                    },
                )
                .await?;

                Ok(CliOutput::Withdraw(response))
            }
            Self::Send {
                federation_id,
                amount,
            } => {
                let response = spend_ecash(
                    client,
                    base_url,
                    SpendEcashPayload {
                        federation_id,
                        amount,
                    },
                )
                .await?;

                Ok(CliOutput::SpendEcash(response))
            }
            Self::Receive { notes, wait } => {
                let response =
                    receive_ecash(client, base_url, ReceiveEcashPayload { notes, wait }).await?;
                Ok(CliOutput::ReceiveEcash(response))
            }
        }
    }
}
