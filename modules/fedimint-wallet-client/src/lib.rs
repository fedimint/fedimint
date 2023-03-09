use fedimint_client::module::gen::ClientModuleGen;
use fedimint_core::module::ExtendsCommonModuleGen;
use fedimint_core::{apply, async_trait_maybe_send};
pub use fedimint_wallet_common::*;

#[derive(Debug, Clone)]
pub struct WalletClientGen;

impl ExtendsCommonModuleGen for WalletClientGen {
    type Common = WalletCommonGen;
}

#[apply(async_trait_maybe_send!)]
impl ClientModuleGen for WalletClientGen {}
