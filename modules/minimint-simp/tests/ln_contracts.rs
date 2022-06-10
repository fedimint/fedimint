use bitcoin_hashes::sha256::Hash as Sha256;
use bitcoin_hashes::Hash;
use minimint_api::module::testing::FakeFed;
use minimint_api::{Amount, OutPoint};
use minimint_simp::config::LightningModuleClientConfig;
use minimint_simp::contracts::IdentifyableContract;
use minimint_simp::{AccountContract, Preimage};
use minimint_simp::{ContractInput, LightningModule};
use std::sync::Arc;

#[test_log::test(tokio::test)]
async fn test_simp_account() {
    let mut fed = FakeFed::<LightningModule, LightningModuleClientConfig>::new(
        4,
        1,
        |cfg, db| async { LightningModule::new(cfg, Arc::new(db)) },
        &(),
    )
    .await;

    let preimage = Preimage([0; 32]);
    let bad_preimage = Preimage([1; 32]);
    let hash = Sha256::hash(&preimage.0);
    let contract = AccountContract {
        amount: Amount::from_sat(42),
        hash: hash,
    };

    let account_out_point = OutPoint {
        txid: Default::default(),
        out_idx: 0,
    };

    let outputs = [(account_out_point, contract.clone())];

    fed.consensus_round(&[], &outputs).await;
    let outcome_contract_id = fed.output_outcome(account_out_point).unwrap();
    assert_eq!(contract.contract_id(), outcome_contract_id);

    // Fail to claim with bad hash
    let account_input = ContractInput {
        contract_id: contract.contract_id(),
        amount: Amount::from_sat(42),
        witness: bad_preimage,
    };
    assert!(fed.verify_input(&account_input).is_err());

    // Successful with correct hash
    let account_input = ContractInput {
        contract_id: contract.contract_id(),
        amount: Amount::from_sat(42),
        witness: preimage,
    };
    let meta = fed.verify_input(&account_input).unwrap();
    assert_eq!(meta.keys, vec![]); // doesn't return any keys

    // You can only do it once
    fed.consensus_round(&[account_input.clone()], &[]).await;
    assert!(fed.verify_input(&account_input).is_err());
}
