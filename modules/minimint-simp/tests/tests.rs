use bitcoin_hashes::sha256::Hash as Sha256;
use bitcoin_hashes::Hash;
use minimint_api::module::testing::FakeFed;
use minimint_api::{Amount, OutPoint};
use minimint_simp::config::SimplicityModuleClientConfig;
use minimint_simp::contracts::ContractId;
use minimint_simp::AccountContract;
use minimint_simp::{ContractInput, SimplicityModule};
use simplicity::merkle::common::MerkleRoot;
use simplicity::minimint::{get_hash_cmr, get_hash_commitment, get_hash_redemption};
use std::sync::Arc;

#[test_log::test(tokio::test)]
async fn test_simp_account() {
    let mut fed = FakeFed::<SimplicityModule, SimplicityModuleClientConfig>::new(
        4,
        1,
        |cfg, db| async { SimplicityModule::new(cfg, Arc::new(db)) },
        &(),
    )
    .await;

    let preimage = [0; 32];
    let bad_preimage = [1; 32];
    let hash = Sha256::hash(&preimage);
    let commitment = get_hash_commitment(&hash);
    let cmr = get_hash_cmr(commitment.clone());

    let contract = AccountContract {
        amount: Amount::from_sat(42),
        id: ContractId(cmr.into_inner()),
    };
    let account_out_point = OutPoint {
        txid: Default::default(),
        out_idx: 0,
    };

    let outputs = [(account_out_point, contract.clone())];

    fed.consensus_round(&[], &outputs).await;
    let outcome_contract_id = fed.output_outcome(account_out_point).unwrap();
    assert_eq!(contract.id, outcome_contract_id);

    // Fail to claim with bad hash
    let account_input = ContractInput {
        contract_id: contract.id,
        amount: Amount::from_sat(42),
        program: get_hash_redemption(commitment.clone(), &bad_preimage),
    };
    assert!(fed.verify_input(&account_input.clone()).is_err());

    // Successful with correct hash
    let account_input = ContractInput {
        contract_id: contract.id,
        amount: Amount::from_sat(42),
        program: get_hash_redemption(commitment.clone(), &preimage),
    };
    let meta = fed.verify_input(&account_input.clone()).unwrap();
    assert_eq!(meta.keys, vec![]); // doesn't return any keys

    // You can only do it once
    fed.consensus_round(&[account_input.clone()], &[]).await;
    assert!(fed.verify_input(&account_input.clone()).is_err());
}
