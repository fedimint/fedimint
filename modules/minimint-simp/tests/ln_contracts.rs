use minimint_api::module::testing::FakeFed;
use minimint_api::{Amount, OutPoint};
use minimint_simp::config::LightningModuleClientConfig;
use minimint_simp::contracts::IdentifyableContract;
use minimint_simp::AccountContract;
use minimint_simp::{ContractInput, LightningModule};
use std::sync::Arc;

#[test_log::test(tokio::test)]
async fn test_simp_account() {
    let mut rng = secp256k1::rand::rngs::OsRng::new().unwrap();

    let mut fed = FakeFed::<LightningModule, LightningModuleClientConfig>::new(
        4,
        1,
        |cfg, db| async { LightningModule::new(cfg, Arc::new(db)) },
        &(),
    )
    .await;

    let (_sk, pk) = secp256k1::SECP256K1.generate_schnorrsig_keypair(&mut rng);
    let contract = AccountContract {
        amount: Amount::from_sat(42),
        key: pk,
    };

    let account_out_point = OutPoint {
        txid: Default::default(),
        out_idx: 0,
    };

    let outputs = [(account_out_point, contract.clone())];

    fed.consensus_round(&[], &outputs).await;
    let outcome_contract_id = fed.output_outcome(account_out_point).unwrap();
    assert_eq!(contract.contract_id(), outcome_contract_id);

    let account_input = ContractInput {
        crontract_id: contract.contract_id(),
        amount: Amount::from_sat(42),
        witness: None,
    };
    let meta = fed.verify_input(&account_input).unwrap();
    assert_eq!(meta.keys, vec![pk]);

    fed.consensus_round(&[account_input.clone()], &[]).await;

    assert!(fed.verify_input(&account_input).is_err());
}
