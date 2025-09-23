use bitcoincore_rpc::bitcoin::Network;
use fedimint_core::config::{EmptyGenParams, ServerModuleConfigGenParamsRegistry};
use fedimint_core::default_esplora_server;
use fedimint_core::envs::{BitcoinRpcConfig, FM_USE_UNKNOWN_MODULE_ENV, is_env_var_set};
use fedimint_ln_server::LightningInit;
use fedimint_ln_server::common::config::{
    LightningGenParams, LightningGenParamsConsensus, LightningGenParamsLocal,
};
use fedimint_meta_server::{MetaGenParams, MetaInit};
use fedimint_mint_server::MintInit;
use fedimint_mint_server::common::config::{MintGenParams, MintGenParamsConsensus};
use fedimint_server::core::ServerModuleInit as _;
use fedimint_unknown_server::UnknownInit;
use fedimint_unknown_server::common::config::UnknownGenParams;
use fedimint_wallet_client::config::{
    WalletGenParams, WalletGenParamsConsensus, WalletGenParamsLocal,
};
use fedimint_wallet_server::WalletInit;
use fedimintd_envs::{FM_DISABLE_META_MODULE_ENV, FM_PORT_ESPLORA_ENV};

use crate::util::supports_lnv2;

/// Duplicate default fedimint module setup
pub fn attach_default_module_init_params(
    bitcoin_rpc: &BitcoinRpcConfig,
    module_init_params: &mut ServerModuleConfigGenParamsRegistry,
    network: Network,
    finality_delay: u32,
) {
    module_init_params.attach_config_gen_params(
        LightningInit::kind(),
        LightningGenParams {
            local: LightningGenParamsLocal {
                bitcoin_rpc: bitcoin_rpc.clone(),
            },
            consensus: LightningGenParamsConsensus { network },
        },
    );

    module_init_params.attach_config_gen_params(
        MintInit::kind(),
        MintGenParams {
            local: EmptyGenParams::default(),
            consensus: MintGenParamsConsensus::new(
                2,
                Some(fedimint_mint_common::config::FeeConsensus::zero()),
            ),
        },
    );

    module_init_params.attach_config_gen_params(
        WalletInit::kind(),
        WalletGenParams {
            local: WalletGenParamsLocal {
                bitcoin_rpc: bitcoin_rpc.clone(),
            },
            consensus: WalletGenParamsConsensus {
                network,
                finality_delay,
                client_default_bitcoin_rpc: default_esplora_server(
                    network,
                    std::env::var(FM_PORT_ESPLORA_ENV).ok(),
                ),
                fee_consensus: fedimint_wallet_client::config::FeeConsensus::default(),
            },
        },
    );

    if supports_lnv2() {
        module_init_params.attach_config_gen_params(
            fedimint_lnv2_server::LightningInit::kind(),
            fedimint_lnv2_common::config::LightningGenParams {
                local: fedimint_lnv2_common::config::LightningGenParamsLocal {
                    bitcoin_rpc: bitcoin_rpc.clone(),
                },
                consensus: fedimint_lnv2_common::config::LightningGenParamsConsensus {
                    fee_consensus: Some(
                        fedimint_lnv2_common::config::FeeConsensus::new(1000)
                            .expect("Relative fee is within range"),
                    ),
                    network,
                },
            },
        );
    }

    if !is_env_var_set(FM_DISABLE_META_MODULE_ENV) {
        module_init_params.attach_config_gen_params(MetaInit::kind(), MetaGenParams::default());
    }

    if is_env_var_set(FM_USE_UNKNOWN_MODULE_ENV) {
        module_init_params
            .attach_config_gen_params(UnknownInit::kind(), UnknownGenParams::default());
    }
}
