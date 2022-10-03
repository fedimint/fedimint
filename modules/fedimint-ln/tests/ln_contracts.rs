use bitcoin_hashes::Hash as BitcoinHash;
use fedimint_api::module::testing::FakeFed;
use fedimint_api::{Amount, OutPoint};
use fedimint_ln::config::LightningModuleClientConfig;
use fedimint_ln::contracts::account::AccountContract;
use fedimint_ln::contracts::incoming::{IncomingContract, IncomingContractOffer};
use fedimint_ln::contracts::outgoing::OutgoingContract;
use fedimint_ln::contracts::{
    AccountContractOutcome, Contract, ContractOutcome, DecryptedPreimage, EncryptedPreimage,
    IdentifyableContract, OutgoingContractOutcome, Preimage,
};
use fedimint_ln::{
    ContractInput, ContractOrOfferOutput, ContractOutput, LightningModule, LightningModuleError,
    OutputOutcome,
};
use secp256k1::KeyPair;

#[test_log::test(tokio::test)]
async fn test_account() {
    let mut rng = secp256k1::rand::rngs::OsRng::new().unwrap();

    let mut fed = FakeFed::<LightningModule, LightningModuleClientConfig>::new(
        4,
        |cfg, db| async { LightningModule::new(cfg, db) },
        &(),
    )
    .await;

    let ctx = secp256k1::Secp256k1::new();
    let kp = KeyPair::new(&ctx, &mut rng);
    let contract = Contract::Account(AccountContract {
        key: kp.public_key(),
    });

    let account_output = ContractOrOfferOutput::Contract(ContractOutput {
        amount: Amount::from_sat(42),
        contract: contract.clone(),
    });
    let account_out_point = OutPoint {
        txid: Default::default(),
        out_idx: 0,
    };
    let outputs = [(account_out_point, account_output)];

    fed.consensus_round(&[], &outputs).await;
    match fed.output_outcome(account_out_point).unwrap() {
        OutputOutcome::Contract { outcome, .. } => {
            assert_eq!(outcome, ContractOutcome::Account(AccountContractOutcome {}));
        }
        _ => panic!(),
    };

    let account_input = ContractInput {
        contract_id: contract.contract_id(),
        amount: Amount::from_sat(42),
        witness: None,
    };
    let meta = fed.verify_input(&account_input).unwrap();
    assert_eq!(meta.keys, vec![kp.public_key()]);

    fed.consensus_round(&[account_input.clone()], &[]).await;

    assert!(fed.verify_input(&account_input).is_err());
}

#[test_log::test(tokio::test)]
async fn test_outgoing() {
    let mut rng = secp256k1::rand::rngs::OsRng::new().unwrap();

    let mut fed = FakeFed::<LightningModule, LightningModuleClientConfig>::new(
        4,
        |cfg, db| async { LightningModule::new(cfg, db) },
        &(),
    )
    .await;

    let ctx = secp256k1::Secp256k1::new();
    let gw_pk = KeyPair::new(&ctx, &mut rng).public_key();
    let user_pk = KeyPair::new(&ctx, &mut rng).public_key();
    let preimage = Preimage([42u8; 32]);
    let hash = secp256k1::hashes::sha256::Hash::hash(&preimage.0);

    let contract = Contract::Outgoing(OutgoingContract {
        hash,
        gateway_key: gw_pk,
        timelock: 42,
        user_key: user_pk,
        invoice: "not enforced yet".to_string(),
        cancelled: false,
    });

    let outgoing_output = ContractOrOfferOutput::Contract(ContractOutput {
        amount: Amount::from_sat(42),
        contract: contract.clone(),
    });
    let outgoing_out_point = OutPoint {
        txid: Default::default(),
        out_idx: 0,
    };
    let outputs = [(outgoing_out_point, outgoing_output)];

    fed.consensus_round(&[], &outputs).await;
    match fed.output_outcome(outgoing_out_point).unwrap() {
        OutputOutcome::Contract { outcome, .. } => {
            assert_eq!(
                outcome,
                ContractOutcome::Outgoing(OutgoingContractOutcome {})
            );
        }
        _ => panic!(),
    };

    // Test case 1: before timeout
    fed.set_block_height(0);

    // Error: Missing preimage
    let account_input_no_witness = ContractInput {
        contract_id: contract.contract_id(),
        amount: Amount::from_sat(42),
        witness: None,
    };
    let err = fed.verify_input(&account_input_no_witness).unwrap_err();
    assert_eq!(err, LightningModuleError::MissingPreimage);

    // Ok
    let account_input_witness = ContractInput {
        contract_id: contract.contract_id(),
        amount: Amount::from_sat(42),
        witness: Some(preimage),
    };
    let meta = fed.verify_input(&account_input_witness).unwrap();
    assert_eq!(meta.keys, vec![gw_pk]);

    // Test case 2: after timeout
    fed.set_block_height(42);
    let meta = fed.verify_input(&account_input_no_witness).unwrap();
    assert_eq!(meta.keys, vec![user_pk]);

    fed.consensus_round(&[account_input_no_witness], &[]).await;
}

#[test_log::test(tokio::test)]
async fn test_incoming() {
    let mut rng = secp256k1::rand::rngs::OsRng::new().unwrap();

    let mut fed = FakeFed::<LightningModule, LightningModuleClientConfig>::new(
        4,
        |cfg, db| async { LightningModule::new(cfg, db) },
        &(),
    )
    .await;

    let ctx = secp256k1::Secp256k1::new();
    let gw_pk = KeyPair::new(&ctx, &mut rng).public_key();
    let user_pk = KeyPair::new(&ctx, &mut rng).public_key();

    let preimage = Preimage(user_pk.serialize());
    let hash = secp256k1::hashes::sha256::Hash::hash(&preimage.0);

    let offer = IncomingContractOffer {
        amount: Amount::from_sat(42),
        hash,
        encrypted_preimage: EncryptedPreimage::new(
            preimage.clone(),
            &fed.client_cfg().threshold_pub_key,
        ),
        expiry_time: None,
    };
    let offer_output = ContractOrOfferOutput::Offer(offer.clone());
    let offer_out_point = OutPoint {
        txid: Default::default(),
        out_idx: 0,
    };

    fed.consensus_round(&[], &[(offer_out_point, offer_output)])
        .await;
    let offers = fed.fetch_from_all(|m| m.get_offers());
    assert_eq!(offers, vec![offer.clone()]);

    let contract = Contract::Incoming(IncomingContract {
        hash, // TODO: check unknown hash
        encrypted_preimage: offer.encrypted_preimage,
        decrypted_preimage: DecryptedPreimage::Pending, // TODO: check what happens if this is not pending
        gateway_key: gw_pk,
    });
    let incoming_output = ContractOrOfferOutput::Contract(ContractOutput {
        amount: Amount::from_sat(42),
        contract: contract.clone(),
    });
    let incoming_out_point = OutPoint {
        txid: Default::default(),
        out_idx: 1,
    };
    let outputs = [(incoming_out_point, incoming_output)];

    fed.consensus_round(&[], &outputs).await;
    match fed.output_outcome(incoming_out_point).unwrap() {
        OutputOutcome::Contract { outcome, .. } => {
            assert_eq!(
                outcome,
                ContractOutcome::Incoming(DecryptedPreimage::Pending)
            );
        }
        _ => panic!(),
    };

    let incoming_input = ContractInput {
        contract_id: contract.contract_id(),
        amount: Amount::from_sat(42),
        witness: None,
    };
    let error = fed.verify_input(&incoming_input).unwrap_err();
    assert_eq!(error, LightningModuleError::ContractNotReady);

    fed.consensus_round(&[], &[]).await;
    match fed.output_outcome(incoming_out_point).unwrap() {
        OutputOutcome::Contract { outcome, .. } => {
            assert_eq!(
                outcome,
                ContractOutcome::Incoming(DecryptedPreimage::Some(preimage))
            );
        }
        _ => panic!(),
    };

    let meta = fed.verify_input(&incoming_input).unwrap();
    assert_eq!(meta.keys, vec![user_pk]);

    // TODO: test faulty encrypted preimage
}
