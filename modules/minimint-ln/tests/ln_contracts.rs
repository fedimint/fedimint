use bitcoin_hashes::Hash as BitcoinHash;
use minimint_api::db::Database;
use minimint_api::module::testing::FakeFed;
use minimint_api::{Amount, OutPoint};
use minimint_ln::config::LightningModuleClientConfig;
use minimint_ln::contracts::account::AccountContract;
use minimint_ln::contracts::incoming::{
    DecryptedPreimage, EncryptedPreimage, IncomingContract, IncomingContractOffer,
};
use minimint_ln::contracts::outgoing::{OutgoingContract, Preimage};
use minimint_ln::contracts::{Contract, ContractOutcome, IdentifyableContract};
use minimint_ln::{
    ContractInput, ContractOrOfferOutput, ContractOutput, LightningModule, LightningModuleError,
    OutputOutcome,
};
use std::fmt::Debug;
use std::sync::Arc;

#[tokio::test]
async fn test_account() {
    let mut rng = secp256k1::rand::rngs::OsRng::new().unwrap();

    let mut fed = FakeFed::<LightningModule, LightningModuleClientConfig>::new(
        4,
        1,
        |cfg, db| async { LightningModule::new(cfg, Arc::new(db)) },
        &(),
    )
    .await;

    let (_sk, pk) = secp256k1::SECP256K1.generate_schnorrsig_keypair(&mut rng);
    let contract = Contract::Account(AccountContract { key: pk });

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
            assert_eq!(outcome, ContractOutcome::Account);
        }
        _ => panic!(),
    };

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

#[tokio::test]
async fn test_outgoing() {
    let mut rng = secp256k1::rand::rngs::OsRng::new().unwrap();

    let mut fed = FakeFed::<LightningModule, LightningModuleClientConfig>::new(
        4,
        1,
        |cfg, db| async { LightningModule::new(cfg, Arc::new(db)) },
        &(),
    )
    .await;

    let (_, gw_pk) = secp256k1::SECP256K1.generate_schnorrsig_keypair(&mut rng);
    let (_, user_pk) = secp256k1::SECP256K1.generate_schnorrsig_keypair(&mut rng);
    let preimage = [42u8; 32];
    let hash = secp256k1::hashes::sha256::Hash::hash(&preimage);

    let contract = Contract::Outgoing(OutgoingContract {
        hash,
        gateway_key: gw_pk,
        timelock: 42,
        user_key: user_pk,
        invoice: "not enforced yet".to_string(),
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
            assert_eq!(outcome, ContractOutcome::Outgoing);
        }
        _ => panic!(),
    };

    // Test case 1: before timeout
    fed.patch_dbs(|db| set_block_height(db, 0));

    // Error: Missing preimage
    let account_input_no_witness = ContractInput {
        crontract_id: contract.contract_id(),
        amount: Amount::from_sat(42),
        witness: None,
    };
    let err = fed.verify_input(&account_input_no_witness).unwrap_err();
    assert_eq!(err, LightningModuleError::MissingPreimage);

    // Ok
    let account_input_witness = ContractInput {
        crontract_id: contract.contract_id(),
        amount: Amount::from_sat(42),
        witness: Some(Preimage(preimage)),
    };
    let meta = fed.verify_input(&account_input_witness).unwrap();
    assert_eq!(meta.keys, vec![gw_pk]);

    // Test case 2: after timeout
    fed.patch_dbs(|db| set_block_height(db, 42));
    let meta = fed.verify_input(&account_input_no_witness).unwrap();
    assert_eq!(meta.keys, vec![user_pk]);

    fed.consensus_round(&[account_input_no_witness], &[]).await;
}

#[tokio::test]
async fn test_incoming() {
    let mut rng = secp256k1::rand::rngs::OsRng::new().unwrap();

    let mut fed = FakeFed::<LightningModule, LightningModuleClientConfig>::new(
        4,
        1,
        |cfg, db| async { LightningModule::new(cfg, Arc::new(db)) },
        &(),
    )
    .await;

    let (_, gw_pk) = secp256k1::SECP256K1.generate_schnorrsig_keypair(&mut rng);
    let (_, user_pk) = secp256k1::SECP256K1.generate_schnorrsig_keypair(&mut rng);

    let preimage = user_pk.serialize();
    let hash = secp256k1::hashes::sha256::Hash::hash(&preimage);

    let offer = IncomingContractOffer {
        amount: Amount::from_sat(42),
        hash,
        encrypted_preimage: EncryptedPreimage::new(preimage, &fed.client_cfg().threshold_pub_key),
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
        crontract_id: contract.contract_id(),
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
                ContractOutcome::Incoming(DecryptedPreimage::Some(
                    minimint_ln::contracts::incoming::Preimage(user_pk)
                ))
            );
        }
        _ => panic!(),
    };

    let meta = fed.verify_input(&incoming_input).unwrap();
    assert_eq!(meta.keys, vec![user_pk]);

    // TODO: test faulty encrypted preimage
}

/// Hack to set consensus height of wallet module which is being used by the LN module too for now.
fn set_block_height(db: &mut dyn Database, block_height: u32) {
    use minimint_api::encoding::{Decodable, Encodable};

    const DB_PREFIX_ROUND_CONSENSUS: u8 = 0x32;

    #[derive(Clone, Debug, Encodable, Decodable)]
    pub struct RoundConsensusKey;

    impl minimint_api::db::DatabaseKeyPrefixConst for RoundConsensusKey {
        const DB_PREFIX: u8 = DB_PREFIX_ROUND_CONSENSUS;
        type Key = Self;
        type Value = RoundConsensus;
    }

    #[derive(Debug, Encodable, Decodable)]
    pub struct RoundConsensus {
        block_height: u32,
        fee_rate: u64,
        randomness_beacon: [u8; 32],
    }

    db.insert_entry(
        &RoundConsensusKey,
        &RoundConsensus {
            block_height,
            fee_rate: 0,
            randomness_beacon: [0; 32],
        },
    )
    .unwrap();
}
