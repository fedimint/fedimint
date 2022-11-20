use fedimint_api::core::client::ModuleClient;
use fedimint_api::core::{ModuleKey, MODULE_KEY_LN};
use fedimint_api::module::TransactionItemAmount;
use fedimint_api::ServerModulePlugin;
use fedimint_core::modules::ln::LightningModule;

#[derive(Debug)]
pub struct LnDecoder;

impl ModuleClient for LnDecoder {
    type Decoder = <LightningModule as ServerModulePlugin>::Decoder;
    type Module = LightningModule;
    const MODULE_KEY: ModuleKey = MODULE_KEY_LN;

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
