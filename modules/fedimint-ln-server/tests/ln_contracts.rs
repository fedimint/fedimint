use bitcoin::secp256k1::{PublicKey, SecretKey};
use bitcoin_hashes::{sha256, Hash as BitcoinHash};
use fedimint_core::config::ConfigGenParams;
use fedimint_core::core::LEGACY_HARDCODED_INSTANCE_ID_LN;
use fedimint_core::{Amount, OutPoint};
use fedimint_ln_common::config::LightningClientConfig;
use fedimint_ln_common::contracts::incoming::{IncomingContract, IncomingContractOffer};
use fedimint_ln_common::contracts::outgoing::OutgoingContract;
use fedimint_ln_common::contracts::{
    Contract, ContractOutcome, DecryptedPreimage, EncryptedPreimage, IdentifiableContract,
    OutgoingContractOutcome, Preimage,
};
use fedimint_ln_common::{
    ContractOutput, LightningError, LightningInput, LightningOutput, LightningOutputOutcome,
};
use fedimint_ln_server::{Lightning, LightningGen};
use fedimint_testing::FakeFed;
use lightning::ln::PaymentSecret;
use lightning_invoice::{Currency, InvoiceBuilder};
use rand::rngs::OsRng;
use secp256k1::KeyPair;

#[test_log::test(tokio::test)]
async fn test_outgoing() {
    let mut rng = secp256k1::rand::rngs::OsRng;

    let mut fed = FakeFed::<Lightning>::new(
        4,
        |cfg, _db| async move { Ok(Lightning::new(cfg.to_typed()?)) },
        &ConfigGenParams::null(),
        &LightningGen,
        LEGACY_HARDCODED_INSTANCE_ID_LN,
    )
    .await
    .unwrap();

    let ctx = secp256k1::Secp256k1::new();
    let kp = KeyPair::new(&ctx, &mut OsRng);
    let gw_pk = PublicKey::from_keypair(&kp).x_only_public_key().0;
    let sec_key = SecretKey::from_keypair(&kp);
    let user_pk = KeyPair::new(&ctx, &mut rng).x_only_public_key().0;
    let preimage = Preimage([42u8; 32]);
    let hash = secp256k1::hashes::sha256::Hash::hash(&preimage.0);

    let invoice = InvoiceBuilder::new(Currency::Bitcoin)
        .description("".to_string())
        .payment_hash(hash)
        .current_timestamp()
        .min_final_cltv_expiry(0)
        .payment_secret(PaymentSecret([0; 32]))
        .amount_milli_satoshis(42000)
        .build_signed(|m| ctx.sign_ecdsa_recoverable(m, &sec_key))
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
        format!("{}", LightningError::MissingPreimage)
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

    let mut fed = FakeFed::<Lightning>::new(
        4,
        |cfg, _db| async move { Ok(Lightning::new(cfg.to_typed()?)) },
        &ConfigGenParams::null(),
        &LightningGen,
        LEGACY_HARDCODED_INSTANCE_ID_LN,
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
            &fed.client_cfg_typed::<LightningClientConfig>()
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
        .fetch_from_all(|m, db, module_instance_id| async {
            m.get_offers(
                &mut db
                    .begin_transaction()
                    .await
                    .with_module_prefix(*module_instance_id),
            )
            .await
        })
        .await;
    assert_eq!(offers, vec![offer.clone()]);

    let contract = Contract::Incoming(IncomingContract {
        hash, // TODO: check unknown hash
        encrypted_preimage: offer.encrypted_preimage,
        decrypted_preimage: DecryptedPreimage::Pending, /* TODO: check what happens if this is
                                                         * not pending */
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
        format!("{}", LightningError::ContractNotReady)
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
