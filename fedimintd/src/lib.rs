use bitcoin::Network;
use fedimint_core::config::ConfigGenParams;
use fedimint_core::{Amount, Tiered};
use fedimint_mint_server::MintGenParams;
use fedimint_wallet_server::WalletGenParams;

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
) -> ConfigGenParams {
    ConfigGenParams::new()
        .attach(WalletGenParams {
            network,
            // TODO this is not very elegant, but I'm planning to get rid of it in a next commit
            // anyway
            finality_delay,
        })
        .attach(MintGenParams {
            mint_amounts: Tiered::gen_denominations(max_denomination)
                .tiers()
                .cloned()
                .collect(),
        })
}
