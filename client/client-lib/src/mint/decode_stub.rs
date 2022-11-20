use fedimint_api::core::client::ModuleClient;
use fedimint_api::core::{ModuleKey, MODULE_KEY_MINT};
use fedimint_api::module::TransactionItemAmount;
use fedimint_api::ServerModulePlugin;
use fedimint_core::modules::mint::Mint;

#[derive(Debug)]
pub struct MintDecoder;

impl ModuleClient for MintDecoder {
    type Decoder = <Mint as ServerModulePlugin>::Decoder;
    type Module = Mint;
    const MODULE_KEY: ModuleKey = MODULE_KEY_MINT;

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
