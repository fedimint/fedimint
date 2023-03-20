use bitcoin::Network;
use fedimint_core::config::ConfigGenParamsRegistry;
use fedimint_core::module::ServerModuleGen;
use fedimint_core::{Amount, Tiered};
use fedimint_mint_server::{MintGen, MintGenParams};
use fedimint_wallet_server::{WalletGen, WalletGenParams};

mod ui;

/// Module for creating `distributetgen` binary with custom modules
pub mod distributed_gen;
/// Module for creating `fedimintd` binary with custom modules
pub mod fedimintd;

/// Generates the configuration for the modules configured in the server binary
pub fn configure_modules(
    max_denomination: Amount,
    network: Network,
    finality_delay: u32,
) -> ConfigGenParamsRegistry {
    ConfigGenParamsRegistry::new()
        .attach_config_gen_params(
            WalletGen::kind(),
            WalletGenParams {
                network,
                // TODO this is not very elegant, but I'm planning to get rid of it in a next commit
                // anyway
                finality_delay,
            },
        )
        .attach_config_gen_params(
            MintGen::kind(),
            MintGenParams {
                mint_amounts: Tiered::gen_denominations(max_denomination)
                    .tiers()
                    .cloned()
                    .collect(),
            },
        )
}
