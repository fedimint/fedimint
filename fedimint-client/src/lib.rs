use fedimint_api::Amount;
use fedimint_core_client::{ClientModule, ModuleKey, Output, SpendableOutput, Transaction};
use std::collections::BTreeMap;
use thiserror::Error;

/// Transaction, without a signature yet
pub struct UnsignedTransaction {
    pub inputs: Vec<SpendableOutput>,
    pub outputs: Vec<Output>,
}

#[derive(Debug, Error)]
pub enum TransactionError {
    #[error("your inputs are too low")]
    NotEnoughInputs,
}

impl UnsignedTransaction {
    /// Generate change outputs using `module`
    pub fn get_changed_needed(&mut self) -> Result<Amount, TransactionError> {
        todo!()
    }

    /// Sign into [`Transaction`] and return new [`SpendableOutput`]s
    pub fn sign(
        &self,
        _rng: &mut DeterministicRandomnessTracker,
    ) -> (Transaction, Vec<SpendableOutput>) {
        // check if inputs == outputs
        // validate input sigs?
        // calculate txid
        // convert all the `SpendableOutput`s to `Inputs`
        // use keys to sign tx
        todo!()
    }
}

/// Something that keeps tracks of which nonces (and any other deterministic randomness we need)
///
/// Details to be flushed out.
pub struct DeterministicRandomnessTracker;

#[derive(Default)]
pub struct Client {
    modules: BTreeMap<ModuleKey, ClientModule>,
}

#[derive(Debug, Error)]
pub enum DBError {
    #[error("not found")]
    NotFound,
}

impl Client {
    pub fn register_module(&mut self, module: ClientModule) -> &mut Self {
        if self.modules.insert(module.module_key(), module).is_some() {
            panic!("Must not register modules with key conflict");
        }
        self
    }

    pub fn register_module_with_id(&mut self, id: ModuleKey, module: ClientModule) -> &mut Self {
        if self.modules.insert(id, module).is_some() {
            panic!("Must not register modules with key conflict");
        }
        self
    }

    pub fn load_module_assets(&self, _module_key: ModuleKey) -> Result<Vec<Vec<u8>>, DBError> {
        todo!();
    }

    pub fn load_all_assets(&self) -> Result<Vec<SpendableOutput>, DBError> {
        let mut assets = vec![];
        for (&module_key, module) in &self.modules {
            for raw_asset in self.load_module_assets(module_key)? {
                assets.push(
                    module
                        .decode_spendable_output(&mut raw_asset.as_slice())
                        .expect("corrupted asset in the db"),
                );
            }
        }

        Ok(assets)
    }

    pub fn load_deterministic_rng_tracker(
        &self,
    ) -> Result<DeterministicRandomnessTracker, DBError> {
        Ok(DeterministicRandomnessTracker)
    }

    pub fn start_db_transaction(&self) -> DBTransaction {
        DBTransaction
    }

    pub fn delete_used_spendable_outputs(
        &self,
        _inputs: &[SpendableOutput],
    ) -> Result<(), DBError> {
        todo!()
    }

    pub fn store_spendable_outputs(
        &self,
        _new_spendable: &[SpendableOutput],
    ) -> Result<(), DBError> {
        todo!()
    }
}

/// Database transaaction object
///
/// Just a placeholder, don't pay too much attention to it.
pub struct DBTransaction;

impl DBTransaction {
    pub fn commit(&self) -> Result<(), DBError> {
        todo!()
    }
}

#[ignore]
#[test]
fn example_workflow() -> Result<(), Box<dyn std::error::Error>> {
    use fedimint_api::encoding::Encodable;
    use fedimint_mint_client::{MintClientModule, MintModuleClientConfig};

    let mint_module = MintClientModule::from_config(MintModuleClientConfig { some_number: 2 });

    let mut client = Client::default();
    client.register_module(mint_module.clone().into());

    let mut rng_tracker = client.load_deterministic_rng_tracker()?;

    let all_assets = client.load_all_assets()?;

    let mut unsig_tx = UnsignedTransaction {
        inputs: all_assets,
        outputs: vec![],
    };

    let change_output = mint_module.generate_outputs(unsig_tx.get_changed_needed()?, || todo!());
    unsig_tx
        .outputs
        .extend(change_output.iter().map(|v| v.0.clone()));

    let (tx, new_spendable) = unsig_tx.sign(&mut rng_tracker);

    let db_trans = client.start_db_transaction();

    client.delete_used_spendable_outputs(&unsig_tx.inputs)?;
    client.store_spendable_outputs(&new_spendable)?;

    db_trans.commit()?;

    let mut v = vec![];
    tx.consensus_encode(&mut v).expect("can't fail");
    dbg!(v);

    Ok(())
}
