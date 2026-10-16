use clap::Subcommand;
use fedimint_core::Amount;
use fedimint_core::config::FederationId;
use fedimint_core::util::SafeUrl;
use fedimint_gateway_client::{get_config, get_info, set_fees, set_mnemonic, set_payment_policy};
use fedimint_gateway_common::{
    ConfigPayload, SetFeesPayload, SetMnemonicPayload, SetPaymentPolicyPayload,
};
use fedimint_ln_common::client::GatewayApi;

use crate::{CliOutput, CliOutputResult};

/// Management commands for changing or displaying configuration, including
/// setting fees per federation.
#[derive(Subcommand)]
pub enum ConfigCommands {
    /// Gets each connected federation's JSON client config
    ClientConfig {
        #[clap(long)]
        federation_id: Option<FederationId>,
    },
    /// Gets the Gateway's configured configuration for each federation
    Display {
        #[clap(long)]
        federation_id: Option<FederationId>,
    },
    /// Set the gateway's lightning or transaction fees
    SetFees {
        #[clap(long)]
        federation_id: Option<FederationId>,

        #[clap(long)]
        ln_base: Option<Amount>,

        #[clap(long)]
        ln_ppm: Option<u64>,

        #[clap(long)]
        tx_base: Option<Amount>,

        #[clap(long)]
        tx_ppm: Option<u64>,
    },
    /// Set which payments the gateway performs on behalf of a federation's
    /// clients. Applies to every connected federation unless a federation id
    /// is given.
    SetPaymentPolicy {
        #[clap(long)]
        federation_id: Option<FederationId>,

        /// Whether to accept incoming Lightning payments for the federation's
        /// clients. Turning this off also fails back the payments of invoices
        /// that were already issued.
        #[clap(long)]
        receive_enabled: Option<bool>,
    },
    /// Instructs the gateway to create a new mnemonic or set it to the provided
    /// mnemonic
    SetMnemonic {
        #[clap(long)]
        words: Option<String>,
    },
}

impl ConfigCommands {
    pub async fn handle(self, client: &GatewayApi, base_url: &SafeUrl) -> CliOutputResult {
        match self {
            Self::ClientConfig { federation_id } => {
                let response =
                    get_config(client, base_url, ConfigPayload { federation_id }).await?;

                Ok(CliOutput::Config(response))
            }
            Self::Display { federation_id } => {
                let info = get_info(client, base_url).await?;
                let federations = info
                    .federations
                    .into_iter()
                    .filter_map(|f| match federation_id {
                        Some(id) if id == f.federation_id => Some(f.config),
                        Some(_) => None,
                        None => Some(f.config),
                    })
                    .collect::<Vec<_>>();
                Ok(CliOutput::FederationConfigs(federations))
            }
            Self::SetFees {
                federation_id,
                ln_base,
                ln_ppm,
                tx_base,
                tx_ppm,
            } => {
                set_fees(
                    client,
                    base_url,
                    SetFeesPayload {
                        federation_id,
                        lightning_base: ln_base,
                        lightning_parts_per_million: ln_ppm,
                        transaction_base: tx_base,
                        transaction_parts_per_million: tx_ppm,
                    },
                )
                .await?;
                Ok(CliOutput::Empty)
            }
            Self::SetPaymentPolicy {
                federation_id,
                receive_enabled,
            } => {
                set_payment_policy(
                    client,
                    base_url,
                    SetPaymentPolicyPayload {
                        federation_id,
                        receive_enabled,
                    },
                )
                .await?;
                Ok(CliOutput::Empty)
            }
            Self::SetMnemonic { words } => {
                set_mnemonic(client, base_url, SetMnemonicPayload { words }).await?;
                Ok(CliOutput::Empty)
            }
        }
    }
}
