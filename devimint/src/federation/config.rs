use bitcoincore_rpc::bitcoin::Network;
use fedimint_core::bitcoinrpc::BitcoinRpcConfig;
use fedimint_core::config::ServerModuleConfigGenParamsRegistry;
use fedimint_core::envs::{is_env_var_set, FM_USE_UNKNOWN_MODULE_ENV};
use fedimint_core::module::ServerModuleInit as _;
use fedimint_ln_server::common::config::{
    LightningGenParams, LightningGenParamsConsensus, LightningGenParamsLocal,
};
use fedimint_ln_server::LightningInit;
use fedimint_meta_server::{MetaGenParams, MetaInit};
use fedimint_mint_server::common::config::{FeeConsensus, MintGenParams, MintGenParamsConsensus};
use fedimint_mint_server::MintInit;
use fedimint_unknown_server::common::config::UnknownGenParams;
use fedimint_unknown_server::UnknownInit;
use fedimint_wallet_client::config::{
    WalletGenParams, WalletGenParamsConsensus, WalletGenParamsLocal,
};
use fedimint_wallet_server::WalletInit;
use fedimintd::default_esplora_server;
use fedimintd::envs::FM_DISABLE_META_MODULE_ENV;

/// Duplicate default fedimint module setup
pub fn attach_default_module_init_params(
    bitcoin_rpc: BitcoinRpcConfig,
    module_init_params: &mut ServerModuleConfigGenParamsRegistry,
    network: Network,
    finality_delay: u32,
) {
    module_init_params
        .attach_config_gen_params(
            LightningInit::kind(),
            LightningGenParams {
                local: LightningGenParamsLocal {
                    bitcoin_rpc: bitcoin_rpc.clone(),
                },
                consensus: LightningGenParamsConsensus { network },
            },
        )
        .attach_config_gen_params(
            MintInit::kind(),
            MintGenParams {
                local: Default::default(),
                consensus: MintGenParamsConsensus::new(2, FeeConsensus::default()),
            },
        )
        .attach_config_gen_params(
            WalletInit::kind(),
            WalletGenParams {
                local: WalletGenParamsLocal {
                    bitcoin_rpc: bitcoin_rpc.clone(),
                },
                consensus: WalletGenParamsConsensus {
                    network,
                    // TODO this is not very elegant, but I'm planning to get rid of it in a next
                    // commit anyway
                    finality_delay,
                    client_default_bitcoin_rpc: default_esplora_server(network),
                },
            },
        );

    if !is_env_var_set(FM_DISABLE_META_MODULE_ENV) {
        module_init_params.attach_config_gen_params(MetaInit::kind(), MetaGenParams::default());
    }

    if is_env_var_set(FM_USE_UNKNOWN_MODULE_ENV) {
        module_init_params
            .attach_config_gen_params(UnknownInit::kind(), UnknownGenParams::default());
    }
}
