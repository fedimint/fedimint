use clap::Subcommand;
use fedimint_core::Amount;
use fedimint_core::config::FederationId;
use fedimint_gateway_client::GatewayRpcClient;
use fedimint_gateway_common::{ConfigPayload, SetFeesPayload};

use crate::print_response;

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
}

impl ConfigCommands {
    pub async fn handle(self, client: &GatewayRpcClient) -> anyhow::Result<()> {
        match self {
            Self::ClientConfig { federation_id } => {
                let response = client.get_config(ConfigPayload { federation_id }).await?;

                print_response(response);
            }
            Self::Display { federation_id } => {
                let info = client.get_info().await?;
                let federations = info
                    .federations
                    .into_iter()
                    .filter_map(|f| match federation_id {
                        Some(id) if id == f.federation_id => Some(f.config),
                        Some(_) => None,
                        None => Some(f.config),
                    })
                    .collect::<Vec<_>>();
                print_response(federations);
            }
            Self::SetFees {
                federation_id,
                ln_base,
                ln_ppm,
                tx_base,
                tx_ppm,
            } => {
                client
                    .set_fees(SetFeesPayload {
                        federation_id,
                        lightning_base: ln_base,
                        lightning_parts_per_million: ln_ppm,
                        transaction_base: tx_base,
                        transaction_parts_per_million: tx_ppm,
                    })
                    .await?;
            }
        }

        Ok(())
    }
}
