use bitcoin::Network;
use fedimint_core::bitcoinrpc::BitcoinRpcConfig;
use fedimint_core::config::ServerModuleGenParamsRegistry;
use fedimint_core::core::{
    LEGACY_HARDCODED_INSTANCE_ID_LN, LEGACY_HARDCODED_INSTANCE_ID_MINT,
    LEGACY_HARDCODED_INSTANCE_ID_WALLET,
};
use fedimint_core::module::ServerModuleGen;
use fedimint_core::{Amount, Tiered};
use fedimint_ln_server::common::config::LightningGenParams;
use fedimint_ln_server::LightningGen;
use fedimint_mint_server::common::config::{MintGenParams, MintGenParamsConsensus};
use fedimint_mint_server::MintGen;
use fedimint_wallet_server::common::config::{
    WalletGenParams, WalletGenParamsConsensus, WalletGenParamsLocal,
};
use fedimint_wallet_server::WalletGen;

mod ui;

/// Module for creating `distributetgen` binary with custom modules
pub mod distributed_gen;
/// Module for creating `fedimintd` binary with custom modules
pub mod fedimintd;

/// Generates the configuration for the modules configured in the server binary
pub fn attach_default_module_gen_params(
    bitcoin_rpc: BitcoinRpcConfig,
    module_gen_params: &mut ServerModuleGenParamsRegistry,
    max_denomination: Amount,
    network: Network,
    finality_delay: u32,
) {
    module_gen_params
        .attach_config_gen_params(
            LEGACY_HARDCODED_INSTANCE_ID_WALLET,
            WalletGen::kind(),
            WalletGenParams {
                local: WalletGenParamsLocal {
                    bitcoin_rpc: bitcoin_rpc.clone(),
                },
                consensus: WalletGenParamsConsensus {
                    network,
                    // TODO this is not very elegant, but I'm planning to get rid of it in a next
                    // commit anyway
                    finality_delay,
                },
            },
        )
        .attach_config_gen_params(
            LEGACY_HARDCODED_INSTANCE_ID_MINT,
            MintGen::kind(),
            MintGenParams {
                local: Default::default(),
                consensus: MintGenParamsConsensus {
                    mint_amounts: Tiered::gen_denominations(max_denomination)
                        .tiers()
                        .cloned()
                        .collect(),
                },
            },
        )
        .attach_config_gen_params(
            LEGACY_HARDCODED_INSTANCE_ID_LN,
            LightningGen::kind(),
            LightningGenParams::new(bitcoin_rpc),
        );
}
