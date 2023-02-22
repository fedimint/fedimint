use bitcoin::Network;
use fedimint_core::config::ConfigGenParams;
use fedimint_core::{Amount, Tiered};
use fedimint_mint::MintGenParams;
use fedimint_wallet::WalletGenParams;

pub mod ui;

pub mod distributed_gen;
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
