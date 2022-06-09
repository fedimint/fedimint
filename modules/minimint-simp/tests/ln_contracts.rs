use bitcoin_hashes::Hash as BitcoinHash;
use minimint_api::module::testing::FakeFed;
use minimint_api::{Amount, OutPoint};
use minimint_simp::config::LightningModuleClientConfig;
use minimint_simp::contracts::incoming::{
    DecryptedPreimage, EncryptedPreimage, IncomingContract, IncomingContractOffer,
};
use minimint_simp::contracts::outgoing::{OutgoingContract, Preimage};
use minimint_simp::contracts::{Contract, ContractOutcome, IdentifyableContract};
use minimint_simp::AccountContract;
use minimint_simp::{ContractInput, LightningModule, LightningModuleError};
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

    // let account_output = ContractOrOfferOutput::Contract(ContractOutput {
    //     amount: Amount::from_sat(42),
    //     contract: contract.clone(),
    // });
    // let account_output = ContractOutput {
    //     amount: Amount::from_sat(42),
    //     contract: contract.clone(),
    // };
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

// #[test_log::test(tokio::test)]
// async fn test_outgoing() {
//     let mut rng = secp256k1::rand::rngs::OsRng::new().unwrap();

//     let mut fed = FakeFed::<LightningModule, LightningModuleClientConfig>::new(
//         4,
//         1,
//         |cfg, db| async { LightningModule::new(cfg, Arc::new(db)) },
//         &(),
//     )
//     .await;

//     let (_, gw_pk) = secp256k1::SECP256K1.generate_schnorrsig_keypair(&mut rng);
//     let (_, user_pk) = secp256k1::SECP256K1.generate_schnorrsig_keypair(&mut rng);
//     let preimage = [42u8; 32];
//     let hash = secp256k1::hashes::sha256::Hash::hash(&preimage);

//     let contract = Contract::Outgoing(OutgoingContract {
//         hash,
//         gateway_key: gw_pk,
//         timelock: 42,
//         user_key: user_pk,
//         invoice: "not enforced yet".to_string(),
//     });

//     let outgoing_output = ContractOrOfferOutput::Contract(ContractOutput {
//         amount: Amount::from_sat(42),
//         contract: contract.clone(),
//     });
//     let outgoing_out_point = OutPoint {
//         txid: Default::default(),
//         out_idx: 0,
//     };
//     let outputs = [(outgoing_out_point, outgoing_output)];

//     fed.consensus_round(&[], &outputs).await;
//     match fed.output_outcome(outgoing_out_point).unwrap() {
//         OutputOutcome::Contract { outcome, .. } => {
//             assert_eq!(outcome, ContractOutcome::Outgoing);
//         }
//         _ => panic!(),
//     };

//     // Test case 1: before timeout
//     fed.set_block_height(0);

//     // Error: Missing preimage
//     let account_input_no_witness = ContractInput {
//         crontract_id: contract.contract_id(),
//         amount: Amount::from_sat(42),
//         witness: None,
//     };
//     let err = fed.verify_input(&account_input_no_witness).unwrap_err();
//     assert_eq!(err, LightningModuleError::MissingPreimage);

//     // Ok
//     let account_input_witness = ContractInput {
//         crontract_id: contract.contract_id(),
//         amount: Amount::from_sat(42),
//         witness: Some(Preimage(preimage)),
//     };
//     let meta = fed.verify_input(&account_input_witness).unwrap();
//     assert_eq!(meta.keys, vec![gw_pk]);

//     // Test case 2: after timeout
//     fed.set_block_height(42);
//     let meta = fed.verify_input(&account_input_no_witness).unwrap();
//     assert_eq!(meta.keys, vec![user_pk]);

//     fed.consensus_round(&[account_input_no_witness], &[]).await;
// }

// #[test_log::test(tokio::test)]
// async fn test_incoming() {
//     let mut rng = secp256k1::rand::rngs::OsRng::new().unwrap();

//     let mut fed = FakeFed::<LightningModule, LightningModuleClientConfig>::new(
//         4,
//         1,
//         |cfg, db| async { LightningModule::new(cfg, Arc::new(db)) },
//         &(),
//     )
//     .await;

//     let (_, gw_pk) = secp256k1::SECP256K1.generate_schnorrsig_keypair(&mut rng);
//     let (_, user_pk) = secp256k1::SECP256K1.generate_schnorrsig_keypair(&mut rng);

//     let preimage = user_pk.serialize();
//     let hash = secp256k1::hashes::sha256::Hash::hash(&preimage);

//     let offer = IncomingContractOffer {
//         amount: Amount::from_sat(42),
//         hash,
//         encrypted_preimage: EncryptedPreimage::new(preimage, &fed.client_cfg().threshold_pub_key),
//     };
//     let offer_output = ContractOrOfferOutput::Offer(offer.clone());
//     let offer_out_point = OutPoint {
//         txid: Default::default(),
//         out_idx: 0,
//     };

//     fed.consensus_round(&[], &[(offer_out_point, offer_output)])
//         .await;
//     let offers = fed.fetch_from_all(|m| m.get_offers());
//     assert_eq!(offers, vec![offer.clone()]);

//     let contract = Contract::Incoming(IncomingContract {
//         hash, // TODO: check unknown hash
//         encrypted_preimage: offer.encrypted_preimage,
//         decrypted_preimage: DecryptedPreimage::Pending, // TODO: check what happens if this is not pending
//         gateway_key: gw_pk,
//     });
//     let incoming_output = ContractOrOfferOutput::Contract(ContractOutput {
//         amount: Amount::from_sat(42),
//         contract: contract.clone(),
//     });
//     let incoming_out_point = OutPoint {
//         txid: Default::default(),
//         out_idx: 1,
//     };
//     let outputs = [(incoming_out_point, incoming_output)];

//     fed.consensus_round(&[], &outputs).await;
//     match fed.output_outcome(incoming_out_point).unwrap() {
//         OutputOutcome::Contract { outcome, .. } => {
//             assert_eq!(
//                 outcome,
//                 ContractOutcome::Incoming(DecryptedPreimage::Pending)
//             );
//         }
//         _ => panic!(),
//     };

//     let incoming_input = ContractInput {
//         crontract_id: contract.contract_id(),
//         amount: Amount::from_sat(42),
//         witness: None,
//     };
//     let error = fed.verify_input(&incoming_input).unwrap_err();
//     assert_eq!(error, LightningModuleError::ContractNotReady);

//     fed.consensus_round(&[], &[]).await;
//     match fed.output_outcome(incoming_out_point).unwrap() {
//         OutputOutcome::Contract { outcome, .. } => {
//             assert_eq!(
//                 outcome,
//                 ContractOutcome::Incoming(DecryptedPreimage::Some(
//                     minimint_simp::contracts::incoming::Preimage(user_pk)
//                 ))
//             );
//         }
//         _ => panic!(),
//     };

//     let meta = fed.verify_input(&incoming_input).unwrap();
//     assert_eq!(meta.keys, vec![user_pk]);

//     // TODO: test faulty encrypted preimage
// }
