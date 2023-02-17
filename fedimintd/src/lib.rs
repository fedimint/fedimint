use bitcoin::Network;
use fedimint_core::config::{ConfigGenParams, ModuleGenRegistry};
use fedimint_core::module::DynModuleGen;
use fedimint_core::{Amount, Tiered};
use fedimint_ln::{LightningGen, LightningGenParams};
use fedimint_mint::{MintGen, MintGenParams};
use fedimint_wallet::{WalletGen, WalletGenParams};

pub mod ui;

/// Generates the configuration for the modules configured in the server binary
// FIXME: Currently the client depends on this exact order being configured
pub fn configure_modules(
    max_denomination: Amount,
    network: Network,
    finality_delay: u32,
) -> ConfigGenParams {
    ConfigGenParams::new()
        .attach(LightningGenParams)
        .attach(MintGenParams {
            mint_amounts: Tiered::gen_denominations(max_denomination)
                .tiers()
                .cloned()
                .collect(),
        })
        .attach(WalletGenParams {
            network,
            // TODO this is not very elegant, but I'm planning to get rid of it in a next commit
            // anyway
            finality_delay,
        })
}

pub fn module_registry() -> ModuleGenRegistry {
    ModuleGenRegistry::from(vec![
        DynModuleGen::from(WalletGen),
        DynModuleGen::from(MintGen),
        DynModuleGen::from(LightningGen),
    ])
}
