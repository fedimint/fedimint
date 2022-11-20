use fedimint_api::core::client::ModuleClient;
use fedimint_api::core::{ModuleKey, MODULE_KEY_WALLET};
use fedimint_api::module::TransactionItemAmount;
use fedimint_api::ServerModulePlugin;
use fedimint_core::modules::wallet::Wallet;

#[derive(Debug)]
pub struct WalletDecoder;

impl ModuleClient for WalletDecoder {
    type Decoder = <Wallet as ServerModulePlugin>::Decoder;
    type Module = Wallet;
    const MODULE_KEY: ModuleKey = MODULE_KEY_WALLET;

    fn input_amount(
        &self,
        _input: &<Self::Module as ServerModulePlugin>::Input,
    ) -> TransactionItemAmount {
        unimplemented!()
    }

    fn output_amount(
        &self,
        _output: &<Self::Module as ServerModulePlugin>::Output,
    ) -> TransactionItemAmount {
        unimplemented!()
    }
}
