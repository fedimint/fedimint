use bitcoin_hashes::sha256;
use bitcoin_hashes::Hash as BitcoinHash;
use fedimint_api::config::ConfigGenParams;
use fedimint_api::core::{Decoder, MODULE_KEY_LN};
use fedimint_api::module::registry::ModuleDecoderRegistry;
use fedimint_api::{Amount, OutPoint};
use fedimint_ln::config::LightningModuleClientConfig;
use fedimint_ln::contracts::account::AccountContract;
use fedimint_ln::contracts::incoming::{IncomingContract, IncomingContractOffer};
use fedimint_ln::contracts::outgoing::OutgoingContract;
use fedimint_ln::contracts::{
    AccountContractOutcome, Contract, ContractOutcome, DecryptedPreimage, EncryptedPreimage,
    IdentifyableContract, OutgoingContractOutcome, Preimage,
};
use fedimint_ln::LightningModuleConfigGen;
use fedimint_ln::{
    ContractOutput, LightningInput, LightningModule, LightningModuleError, LightningOutput,
    LightningOutputOutcome,
};
use fedimint_testing::FakeFed;
use secp256k1::KeyPair;

fn ln_decoders() -> ModuleDecoderRegistry {
    ModuleDecoderRegistry::new([(
        MODULE_KEY_LN,
        Decoder::from_typed(&fedimint_ln::common::LightningModuleDecoder),
    )])
}

#[test_log::test(tokio::test)]
async fn test_account() {
    let mut rng = secp256k1::rand::rngs::OsRng;

    let mut fed = FakeFed::<LightningModule>::new(
        4,
        |cfg, _db| async move { Ok(LightningModule::new(cfg.to_typed()?)) },
        &ConfigGenParams::new(),
        &LightningModuleConfigGen,
    )
    .await
    .unwrap();

    let ctx = secp256k1::Secp256k1::new();
    let kp = KeyPair::new(&ctx, &mut rng);
    let contract = Contract::Account(AccountContract {
        key: kp.x_only_public_key().0,
    });

    let account_output = LightningOutput::Contract(ContractOutput {
        amount: Amount::from_sats(42),
        contract: contract.clone(),
    });
    let account_out_point = OutPoint {
        txid: sha256::Hash::hash(b"").into(),
        out_idx: 0,
    };
    let outputs = [(account_out_point, account_output)];

    fed.consensus_round(&[], &outputs).await;
    match fed.output_outcome(account_out_point).await.unwrap() {
        LightningOutputOutcome::Contract { outcome, .. } => {
            assert_eq!(outcome, ContractOutcome::Account(AccountContractOutcome {}));
        }
        _ => panic!(),
    };

    let account_input = LightningInput {
        contract_id: contract.contract_id(),
        amount: Amount::from_sats(42),
        witness: None,
    };
    let meta = fed.verify_input(&account_input).await.unwrap();
    assert_eq!(meta.keys, vec![kp.x_only_public_key().0]);

    fed.consensus_round(&[account_input.clone()], &[]).await;

    assert!(fed.verify_input(&account_input).await.is_err());
}

#[test_log::test(tokio::test)]
async fn test_outgoing() {
    let mut rng = secp256k1::rand::rngs::OsRng;

    let mut fed = FakeFed::<LightningModule>::new(
        4,
        |cfg, _db| async move { Ok(LightningModule::new(cfg.to_typed()?)) },
        &ConfigGenParams::new(),
        &LightningModuleConfigGen,
    )
    .await
    .unwrap();

    let ctx = secp256k1::Secp256k1::new();
    let gw_pk = KeyPair::new(&ctx, &mut rng).x_only_public_key().0;
    let user_pk = KeyPair::new(&ctx, &mut rng).x_only_public_key().0;
    let preimage = Preimage([42u8; 32]);
    let hash = secp256k1::hashes::sha256::Hash::hash(&preimage.0);

    let invoice: lightning_invoice::Invoice =
        "lnbc100p1psj9jhxdqud3jxktt5w46x7unfv9kz6mn0v3jsnp4q0d3p2sfluzdx45tqcs\
h2pu5qc7lgq0xs578ngs6s0s68ua4h7cvspp5q6rmq35js88zp5dvwrv9m459tnk2zunwj5jalqtyxqulh0l\
5gflssp5nf55ny5gcrfl30xuhzj3nphgj27rstekmr9fw3ny5989s300gyus9qyysgqcqpcrzjqw2sxwe993\
h5pcm4dxzpvttgza8zhkqxpgffcrf5v25nwpr3cmfg7z54kuqq8rgqqqqqqqq2qqqqq9qq9qrzjqd0ylaqcl\
j9424x9m8h2vcukcgnm6s56xfgu3j78zyqzhgs4hlpzvznlugqq9vsqqqqqqqlgqqqqqeqq9qrzjqwldmj9d\
ha74df76zhx6l9we0vjdquygcdt3kssupehe64g6yyp5yz5rhuqqwccqqyqqqqlgqqqqjcqq9qrzjqf9e58a\
guqr0rcun0ajlvmzq3ek63cw2w282gv3z5uupmuwvgjtq2z55qsqqg6qqqyqqqrtnqqqzq3cqygrzjqvphms\
ywntrrhqjcraumvc4y6r8v4z5v593trte429v4hredj7ms5z52usqq9ngqqqqqqqlgqqqqqqgq9qrzjq2v0v\
p62g49p7569ev48cmulecsxe59lvaw3wlxm7r982zxa9zzj7z5l0cqqxusqqyqqqqlgqqqqqzsqygarl9fh3\
8s0gyuxjjgux34w75dnc6xp2l35j7es3jd4ugt3lu0xzre26yg5m7ke54n2d5sym4xcmxtl8238xxvw5h5h5\
j5r6drg6k6zcqj0fcwg"
            .parse()
            .unwrap();

    let contract = Contract::Outgoing(OutgoingContract {
        hash,
        gateway_key: gw_pk,
        timelock: 42,
        user_key: user_pk,
        invoice,
        cancelled: false,
    });

    let outgoing_output = LightningOutput::Contract(ContractOutput {
        amount: Amount::from_sats(42),
        contract: contract.clone(),
    });
    let outgoing_out_point = OutPoint {
        txid: sha256::Hash::hash(b"x").into(),
        out_idx: 0,
    };
    let outputs = [(outgoing_out_point, outgoing_output)];

    fed.consensus_round(&[], &outputs).await;
    match fed.output_outcome(outgoing_out_point).await.unwrap() {
        LightningOutputOutcome::Contract { outcome, .. } => {
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
    let account_input_no_witness = LightningInput {
        contract_id: contract.contract_id(),
        amount: Amount::from_sats(42),
        witness: None,
    };
    let err = fed
        .verify_input(&account_input_no_witness)
        .await
        .unwrap_err();
    assert_eq!(
        format!("{err}"),
        format!("{}", LightningModuleError::MissingPreimage)
    );

    // Ok
    let account_input_witness = LightningInput {
        contract_id: contract.contract_id(),
        amount: Amount::from_sats(42),
        witness: Some(preimage),
    };
    let meta = fed.verify_input(&account_input_witness).await.unwrap();
    assert_eq!(meta.keys, vec![gw_pk]);

    // Test case 2: after timeout
    fed.set_block_height(42);
    let meta = fed.verify_input(&account_input_no_witness).await.unwrap();
    assert_eq!(meta.keys, vec![user_pk]);

    fed.consensus_round(&[account_input_no_witness], &[]).await;
}

#[test_log::test(tokio::test)]
async fn test_incoming() {
    let mut rng = secp256k1::rand::rngs::OsRng;

    let mut fed = FakeFed::<LightningModule>::new(
        4,
        |cfg, _db| async move { Ok(LightningModule::new(cfg.to_typed()?)) },
        &ConfigGenParams::new(),
        &LightningModuleConfigGen,
    )
    .await
    .unwrap();

    let ctx = secp256k1::Secp256k1::new();
    let gw_pk = KeyPair::new(&ctx, &mut rng).x_only_public_key().0;
    let user_pk = KeyPair::new(&ctx, &mut rng).x_only_public_key().0;

    let preimage = Preimage(user_pk.serialize());
    let hash = secp256k1::hashes::sha256::Hash::hash(&preimage.0);

    let offer = IncomingContractOffer {
        amount: Amount::from_sats(42),
        hash,
        encrypted_preimage: EncryptedPreimage::new(
            preimage.clone(),
            &fed.client_cfg_typed::<LightningModuleClientConfig>()
                .unwrap()
                .threshold_pub_key,
        ),
        expiry_time: None,
    };
    let offer_output = LightningOutput::Offer(offer.clone());
    let offer_out_point = OutPoint {
        txid: sha256::Hash::hash(b"").into(),
        out_idx: 0,
    };

    fed.consensus_round(&[], &[(offer_out_point, offer_output)])
        .await;
    let offers = fed
        .fetch_from_all(|m, db| async {
            m.get_offers(&mut db.begin_readonly_transaction(ln_decoders()).await)
                .await
        })
        .await;
    assert_eq!(offers, vec![offer.clone()]);

    let contract = Contract::Incoming(IncomingContract {
        hash, // TODO: check unknown hash
        encrypted_preimage: offer.encrypted_preimage,
        decrypted_preimage: DecryptedPreimage::Pending, // TODO: check what happens if this is not pending
        gateway_key: gw_pk,
    });
    let incoming_output = LightningOutput::Contract(ContractOutput {
        amount: Amount::from_sats(42),
        contract: contract.clone(),
    });
    let incoming_out_point = OutPoint {
        txid: sha256::Hash::hash(b"").into(),
        out_idx: 1,
    };
    let outputs = [(incoming_out_point, incoming_output)];

    fed.consensus_round(&[], &outputs).await;
    match fed.output_outcome(incoming_out_point).await.unwrap() {
        LightningOutputOutcome::Contract { outcome, .. } => {
            assert_eq!(
                outcome,
                ContractOutcome::Incoming(DecryptedPreimage::Pending)
            );
        }
        _ => panic!(),
    };

    let incoming_input = LightningInput {
        contract_id: contract.contract_id(),
        amount: Amount::from_sats(42),
        witness: None,
    };
    let error = fed.verify_input(&incoming_input).await.unwrap_err();
    assert_eq!(
        format!("{error}"),
        format!("{}", LightningModuleError::ContractNotReady)
    );

    fed.consensus_round(&[], &[]).await;
    match fed.output_outcome(incoming_out_point).await.unwrap() {
        LightningOutputOutcome::Contract { outcome, .. } => {
            assert_eq!(
                outcome,
                ContractOutcome::Incoming(DecryptedPreimage::Some(preimage))
            );
        }
        _ => panic!(),
    };

    let meta = fed.verify_input(&incoming_input).await.unwrap();
    assert_eq!(meta.keys, vec![user_pk]);

    // TODO: test faulty encrypted preimage
}
