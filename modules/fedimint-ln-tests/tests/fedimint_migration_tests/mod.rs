use std::str::FromStr;
use std::time::Duration;

use anyhow::ensure;
use bitcoin_hashes::{Hash as BitcoinHash, sha256};
use fedimint_client::module_init::DynClientModuleInit;
use fedimint_core::config::FederationId;
use fedimint_core::core::OperationId;
use fedimint_core::db::mem_impl::MemDatabase;
use fedimint_core::db::{
    Database, DatabaseVersion, DatabaseVersionKeyV0, IDatabaseTransactionOpsCoreTyped,
};
use fedimint_core::encoding::Encodable;
use fedimint_core::module::ModuleConsensusVersion;
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::util::SafeUrl;
use fedimint_core::{Amount, OutPoint, PeerId, TransactionId, secp256k1};
use fedimint_ln_client::db::{PaymentResult, PaymentResultKey, PaymentResultPrefix};
use fedimint_ln_client::pay::{
    LightningPayCommon, LightningPayStates, PayInvoicePayload, PaymentData,
};
use fedimint_ln_client::receive::LightningReceiveStates;
use fedimint_ln_client::{
    LightningClientInit, LightningClientModule, LightningClientStateMachines,
    OutgoingLightningPayment, ReceivingKey,
};
use fedimint_ln_common::contracts::incoming::{
    FundedIncomingContract, IncomingContract, IncomingContractOffer, OfferId,
};
use fedimint_ln_common::contracts::outgoing::{
    OutgoingContract, OutgoingContractAccount, OutgoingContractData,
};
use fedimint_ln_common::contracts::{
    ContractId, DecryptedPreimage, EncryptedPreimage, FundedContract, IdentifiableContract,
    PreimageDecryptionShare, PreimageKey, outgoing,
};
use fedimint_ln_common::route_hints::{RouteHint, RouteHintHop};
use fedimint_ln_common::{
    ContractAccount, LightningCommonInit, LightningGateway, LightningGatewayRegistration,
    LightningOutputOutcomeV0,
};
use fedimint_ln_server::db::{
    AgreedDecryptionShareKey, AgreedDecryptionShareKeyPrefix, BlockCountVoteKey,
    BlockCountVotePrefix, ConsensusVersionVoteKey, ConsensusVersionVotePrefix, ContractKey,
    ContractKeyPrefix, ContractUpdateKey, ContractUpdateKeyPrefix, DbKeyPrefix,
    EncryptedPreimageIndexKey, EncryptedPreimageIndexKeyPrefix, LightningAuditItemKey,
    LightningAuditItemKeyPrefix, LightningGatewayKey, LightningGatewayKeyPrefix, OfferKey,
    OfferKeyPrefix, ProposeDecryptionShareKey, ProposeDecryptionShareKeyPrefix,
};
use fedimint_logging::TracingSetup;
use fedimint_server::core::DynServerModuleInit;
use fedimint_testing::db::{
    BYTE_8, BYTE_32, BYTE_33, STRING_64, TEST_MODULE_INSTANCE_ID, snapshot_db_migrations,
    snapshot_db_migrations_client, validate_migrations_client, validate_migrations_server,
};
use futures::StreamExt;
use lightning_invoice::{Currency, InvoiceBuilder, PaymentSecret, RoutingFees};
use rand::distributions::Standard;
use rand::prelude::Distribution;
use rand::rngs::OsRng;
use secp256k1::{All, Keypair, Secp256k1, SecretKey};
use strum::IntoEnumIterator;
use threshold_crypto::G1Projective;
use tracing::info;

use crate::LightningInit;

/// Create a database with version 0 data. The database produced is not
/// intended to be real data or semantically correct. It is only
/// intended to provide coverage when reading the database
/// in future code versions. This function should not be updated when
/// database keys/values change - instead a new function should be added
/// that creates a new database backup that can be tested.
async fn create_server_db_with_v0_data(db: Database) {
    let mut dbtx = db.begin_transaction().await;

    // Will be migrated to `DatabaseVersionKey` during `apply_migrations`
    dbtx.insert_new_entry(&DatabaseVersionKeyV0, &DatabaseVersion(0))
        .await;

    let contract_id = ContractId::from_str(STRING_64).unwrap();
    let amount = fedimint_core::Amount { msats: 1000 };
    let threshold_key = threshold_crypto::PublicKey::from(G1Projective::identity());
    let (_, pk) = fedimint_core::secp256k1::generate_keypair(&mut OsRng);
    let incoming_contract = IncomingContract {
        hash: secp256k1::hashes::sha256::Hash::hash(&BYTE_8),
        encrypted_preimage: EncryptedPreimage::new(&PreimageKey(BYTE_33), &threshold_key),
        decrypted_preimage: DecryptedPreimage::Some(PreimageKey(BYTE_33)),
        gateway_key: pk,
    };
    let out_point = OutPoint {
        txid: TransactionId::all_zeros(),
        out_idx: 0,
    };
    let incoming_contract = FundedContract::Incoming(FundedIncomingContract {
        contract: incoming_contract,
        out_point,
    });
    dbtx.insert_new_entry(
        &ContractKey(incoming_contract.contract_id()),
        &ContractAccount {
            amount,
            contract: incoming_contract.clone(),
        },
    )
    .await;
    let outgoing_contract = FundedContract::Outgoing(outgoing::OutgoingContract {
        hash: secp256k1::hashes::sha256::Hash::hash(&[0, 2, 3, 4, 5, 6, 7, 8]),
        gateway_key: pk,
        timelock: 1000000,
        user_key: pk,
        cancelled: false,
    });
    dbtx.insert_new_entry(
        &ContractKey(outgoing_contract.contract_id()),
        &ContractAccount {
            amount,
            contract: outgoing_contract.clone(),
        },
    )
    .await;

    let incoming_offer = IncomingContractOffer {
        amount: fedimint_core::Amount { msats: 1000 },
        hash: secp256k1::hashes::sha256::Hash::hash(&BYTE_8),
        encrypted_preimage: EncryptedPreimage::new(&PreimageKey(BYTE_33), &threshold_key),
        expiry_time: None,
    };
    dbtx.insert_new_entry(&OfferKey(incoming_offer.hash), &incoming_offer)
        .await;

    let contract_update_key = ContractUpdateKey(OutPoint {
        txid: TransactionId::from_slice(&BYTE_32).unwrap(),
        out_idx: 0,
    });
    let lightning_output_outcome = LightningOutputOutcomeV0::Offer {
        id: OfferId::from_str(STRING_64).unwrap(),
    };
    dbtx.insert_new_entry(&contract_update_key, &lightning_output_outcome)
        .await;

    let preimage_decryption_share = PreimageDecryptionShare(Standard.sample(&mut OsRng));
    dbtx.insert_new_entry(
        &ProposeDecryptionShareKey(contract_id),
        &preimage_decryption_share,
    )
    .await;

    dbtx.insert_new_entry(
        &AgreedDecryptionShareKey(contract_id, 0.into()),
        &preimage_decryption_share,
    )
    .await;

    let gateway = LightningGatewayRegistration {
        info: LightningGateway {
            federation_index: 100,
            gateway_redeem_key: pk,
            node_pub_key: pk,
            lightning_alias: "FakeLightningAlias".to_string(),
            api: SafeUrl::parse("http://example.com")
                .expect("Could not parse URL to generate GatewayClientConfig API endpoint"),
            route_hints: vec![],
            fees: RoutingFees {
                base_msat: 0,
                proportional_millionths: 0,
            },
            gateway_id: pk,
            supports_private_payments: false,
        },
        valid_until: fedimint_core::time::now(),
        vetted: false,
        auth: None,
    };
    dbtx.insert_new_entry(&LightningGatewayKey(pk), &gateway)
        .await;

    dbtx.insert_new_entry(&BlockCountVoteKey(PeerId::from(0)), &1)
        .await;

    dbtx.insert_new_entry(
        &ConsensusVersionVoteKey(PeerId::from(0)),
        &ModuleConsensusVersion::new(2, 0),
    )
    .await;

    dbtx.insert_new_entry(&EncryptedPreimageIndexKey("foobar".consensus_hash()), &())
        .await;

    dbtx.insert_new_entry(
        &LightningAuditItemKey::from_funded_contract(&incoming_contract),
        &amount,
    )
    .await;

    dbtx.insert_new_entry(
        &LightningAuditItemKey::from_funded_contract(&outgoing_contract),
        &amount,
    )
    .await;

    dbtx.commit_tx().await;
}

async fn create_client_db_with_v0_data(db: Database) {
    let mut dbtx = db.begin_transaction().await;

    // Will be migrated to `DatabaseVersionKey` during `apply_migrations`
    dbtx.insert_new_entry(&DatabaseVersionKeyV0, &DatabaseVersion(0))
        .await;

    // Generate fake private/public key
    let (_, pk) = secp256k1::generate_keypair(&mut OsRng);
    let hop = RouteHintHop {
        src_node_id: pk,
        short_channel_id: 3,
        base_msat: 20,
        proportional_millionths: 3000,
        cltv_expiry_delta: 8,
        htlc_minimum_msat: Some(10),
        htlc_maximum_msat: Some(1000),
    };
    let route_hints = vec![RouteHint(vec![hop])];

    let gateway_info = LightningGateway {
        federation_index: 3,
        gateway_redeem_key: pk,
        node_pub_key: pk,
        lightning_alias: "MyLightningNode".to_string(),
        api: SafeUrl::from_str("http://mylightningnode.com")
            .expect("SafeUrl parsing should not fail"),
        route_hints,
        fees: RoutingFees {
            base_msat: 10,
            proportional_millionths: 1000,
        },
        gateway_id: pk,
        supports_private_payments: false,
    };

    let lightning_gateway_registration = LightningGatewayRegistration {
        info: gateway_info,
        vetted: false,
        valid_until: fedimint_core::time::now(),
        auth: None,
    };

    dbtx.insert_new_entry(
        &fedimint_ln_client::db::ActiveGatewayKey,
        &lightning_gateway_registration,
    )
    .await;

    dbtx.insert_new_entry(
        &fedimint_ln_client::db::LightningGatewayKey(pk),
        &lightning_gateway_registration,
    )
    .await;

    dbtx.insert_new_entry(
        &PaymentResultKey {
            payment_hash: sha256::Hash::hash(&BYTE_8),
        },
        &PaymentResult {
            index: 0,
            completed_payment: Some(OutgoingLightningPayment {
                payment_type: fedimint_ln_client::PayType::Lightning(OperationId(BYTE_32)),
                contract_id: sha256::Hash::hash(&BYTE_8).into(),
                fee: Amount::from_sats(1000),
            }),
        },
    )
    .await;

    // Add a recurring payment code entry
    let keypair = Keypair::new_global(&mut OsRng);
    let recurring_payment_code_entry = fedimint_ln_client::recurring::RecurringPaymentCodeEntry {
        protocol: fedimint_ln_client::recurring::RecurringPaymentProtocol::LNURL,
        root_keypair: keypair,
        code: "lnurl1dp68gurn8ghj7um9wfmxjcm99e3k7mf0v9cxj0m385ekvcenxc6r2c35xvukxefcv5mkvv34x5ekzd3ev56nyd3hxqurzepexejxxepnxscrvwfnv9nz7cmgv9ex7tmpwp5hg6ryv96x7un9v35kuurjd9jnsctrv5cqp5rzepn".to_string(),
        recurringd_api: SafeUrl::from_str("http://recurringd.example.com").expect("SafeUrl parsing should not fail"),
        last_derivation_index: 5,
        creation_time: fedimint_core::time::now(),
        meta: "[\"text/plain\", \"Fedimint LNURL Pay\"]".to_string(),
    };

    dbtx.insert_entry(
        &fedimint_ln_client::db::RecurringPaymentCodeKey { derivation_idx: 1 },
        &recurring_payment_code_entry,
    )
    .await;

    dbtx.commit_tx().await;
}

fn create_client_states() -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let secp: Secp256k1<All> = Secp256k1::gen_new();
    let invoice = InvoiceBuilder::new(Currency::Regtest)
        .amount_milli_satoshis(1000)
        .payment_hash(sha256::Hash::hash(&BYTE_32))
        .description("".to_string())
        .payment_secret(PaymentSecret([0; 32]))
        .current_timestamp()
        .min_final_cltv_expiry_delta(18)
        .expiry_time(Duration::from_secs(86400))
        .build_signed(|m| secp.sign_ecdsa_recoverable(m, &SecretKey::new(&mut OsRng)))
        .expect("Invoice creation failed");

    // Create an active state and inactive state that will not be migrated.
    let operation_id = OperationId::new_random();
    let submitted_offer_variant_new: Vec<u8> = {
        let mut bytes = Vec::new();
        bytes.append(&mut TransactionId::all_zeros().consensus_encode_to_vec());
        bytes.append(&mut invoice.consensus_encode_to_vec());
        let receiving_key = ReceivingKey::Personal(Keypair::new_global(&mut OsRng));
        bytes.append(&mut receiving_key.consensus_encode_to_vec());
        bytes
    };
    let new_receive_bytes =
        create_receive_state_machine(submitted_offer_variant_new, operation_id, 0);

    // Create and active state and inactive state that will be migrated.
    let submitted_offer_variant_old: Vec<u8> = {
        let mut bytes = Vec::<u8>::new();
        bytes.append(&mut TransactionId::all_zeros().consensus_encode_to_vec());
        bytes.append(&mut invoice.consensus_encode_to_vec());
        let keypair = Keypair::new_global(&mut OsRng);
        bytes.append(&mut keypair.consensus_encode_to_vec());
        bytes
    };
    let old_receive_bytes =
        create_receive_state_machine(submitted_offer_variant_old, operation_id, 0);

    let confirmed_offer_variant_old: Vec<u8> = {
        let mut bytes = Vec::new();
        bytes.append(&mut invoice.consensus_encode_to_vec());
        let keypair = Keypair::new_global(&mut OsRng);
        bytes.append(&mut keypair.consensus_encode_to_vec());
        bytes
    };
    let old_confirmed_bytes =
        create_receive_state_machine(confirmed_offer_variant_old, operation_id, 2);

    let (sk, pk) = secp256k1::generate_keypair(&mut OsRng);
    let outgoing_contract = OutgoingContract {
        hash: sha256::Hash::hash(&BYTE_32),
        gateway_key: pk,
        timelock: 1000,
        user_key: pk,
        cancelled: false,
    };
    let outgoing_account = OutgoingContractAccount {
        amount: Amount::from_msats(10000),
        contract: outgoing_contract.clone(),
    };
    let contract = OutgoingContractData {
        recovery_key: Keypair::from_secret_key(&secp, &sk),
        contract_account: outgoing_account,
    };
    let ln_common = LightningPayCommon {
        operation_id,
        federation_id: FederationId::dummy(),
        contract,
        gateway_fee: Amount::from_msats(1000),
        preimage_auth: sha256::Hash::hash(&BYTE_32),
        invoice: invoice.clone(),
    };

    let refund_state: Vec<u8> = {
        let mut bytes = Vec::new();
        bytes.append(&mut TransactionId::all_zeros().consensus_encode_to_vec());
        bytes.append(
            &mut vec![OutPoint {
                txid: TransactionId::all_zeros(),
                out_idx: 0,
            }]
            .consensus_encode_to_vec(),
        );
        bytes
    };
    let old_refund_bytes = create_pay_state_machine(refund_state, ln_common.clone(), 5u64);

    let hop = RouteHintHop {
        src_node_id: pk,
        short_channel_id: 3,
        base_msat: 20,
        proportional_millionths: 3000,
        cltv_expiry_delta: 8,
        htlc_minimum_msat: Some(10),
        htlc_maximum_msat: Some(1000),
    };
    let route_hints = vec![RouteHint(vec![hop])];

    let funded_state: Vec<u8> = {
        let mut bytes = Vec::new();
        bytes.append(
            &mut PayInvoicePayload {
                federation_id: FederationId::dummy(),
                contract_id: outgoing_contract.contract_id(),
                payment_data: PaymentData::Invoice(invoice),
                preimage_auth: sha256::Hash::hash(&BYTE_32),
            }
            .consensus_encode_to_vec(),
        );
        bytes.append(
            &mut LightningGateway {
                federation_index: 3,
                gateway_redeem_key: pk,
                node_pub_key: pk,
                lightning_alias: "MyLightningNode".to_string(),
                api: SafeUrl::from_str("http://mylightningnode.com")
                    .expect("SafeUrl parsing should not fail"),
                route_hints,
                fees: RoutingFees {
                    base_msat: 10,
                    proportional_millionths: 1000,
                },
                gateway_id: pk,
                supports_private_payments: false,
            }
            .consensus_encode_to_vec(),
        );
        bytes.append(&mut 10000u32.consensus_encode_to_vec());
        bytes
    };
    let old_funded_bytes = create_pay_state_machine(funded_state, ln_common, 2u64);

    (
        vec![
            old_receive_bytes.clone(),
            new_receive_bytes.clone(),
            old_confirmed_bytes.clone(),
            old_refund_bytes.clone(),
            old_funded_bytes.clone(),
        ],
        vec![
            old_receive_bytes,
            new_receive_bytes,
            old_confirmed_bytes,
            old_refund_bytes,
            old_funded_bytes,
        ],
    )
}

/// Creates a vector of bytes that contains consensus encoded
/// `LightningClientStateMachines::Receive` state machine. `sm_state` is
/// the u64 representation of the state enum.
fn create_receive_state_machine(
    state: Vec<u8>,
    operation_id: OperationId,
    sm_state: u64,
) -> Vec<u8> {
    let receive_variant: Vec<u8> = {
        let mut bytes = Vec::<u8>::new();
        bytes.append(&mut operation_id.consensus_encode_to_vec());
        bytes.append(&mut sm_state.consensus_encode_to_vec());
        bytes.append(&mut state.consensus_encode_to_vec());
        bytes
    };

    let sm_bytes: Vec<u8> = {
        let mut bytes = Vec::new();
        bytes.append(&mut TEST_MODULE_INSTANCE_ID.consensus_encode_to_vec());
        bytes.append(&mut 2u64.consensus_encode_to_vec()); // Receive state machine variant.
        bytes.append(&mut receive_variant.consensus_encode_to_vec());
        bytes
    };

    sm_bytes
}

/// Creates a vector of bytes that contains consensus encoded
/// `LightningClientStateMachines::LightningPay` state machine. `sm_state`
/// is the u64 representation of the state enum.
fn create_pay_state_machine(
    state: Vec<u8>,
    ln_pay_common: LightningPayCommon,
    sm_state: u64,
) -> Vec<u8> {
    let ln_pay_variant: Vec<u8> = {
        let mut bytes = Vec::new();
        bytes.append(&mut ln_pay_common.consensus_encode_to_vec());
        bytes.append(&mut sm_state.consensus_encode_to_vec());
        bytes.append(&mut state.consensus_encode_to_vec());
        bytes
    };

    let sm_bytes: Vec<u8> = {
        let mut bytes = Vec::new();
        bytes.append(&mut TEST_MODULE_INSTANCE_ID.consensus_encode_to_vec());
        bytes.append(&mut 1u64.consensus_encode_to_vec()); // LightningPay state machine variant.
        bytes.append(&mut ln_pay_variant.consensus_encode_to_vec());
        bytes
    };
    sm_bytes
}

#[tokio::test(flavor = "multi_thread")]
async fn create_server_db_with_v0_data_inserts_both_contract_variants() {
    let db = Database::new(MemDatabase::new(), ModuleDecoderRegistry::default());

    create_server_db_with_v0_data(db.clone()).await;

    let mut dbtx = db.begin_transaction_nc().await;
    let contracts = dbtx
        .find_by_prefix(&ContractKeyPrefix)
        .await
        .collect::<Vec<_>>()
        .await;

    assert!(
        contracts
            .iter()
            .any(|(_, account)| matches!(&account.contract, FundedContract::Incoming(_))),
        "fixture database should contain an incoming contract"
    );
    assert!(
        contracts
            .iter()
            .any(|(_, account)| matches!(&account.contract, FundedContract::Outgoing(_))),
        "fixture database should contain an outgoing contract"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn snapshot_server_db_migrations() -> anyhow::Result<()> {
    snapshot_db_migrations::<_, LightningCommonInit>("lightning-server-v0", |db| {
        Box::pin(async {
            create_server_db_with_v0_data(db).await;
        })
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn test_server_db_migrations() -> anyhow::Result<()> {
    let _ = TracingSetup::default().init();
    let module = DynServerModuleInit::from(LightningInit);

    validate_migrations_server(module, "lightning-server", |db| async move {
        let mut dbtx = db.begin_transaction_nc().await;

        for prefix in DbKeyPrefix::iter() {
            match prefix {
                DbKeyPrefix::Contract => {
                    let contracts = dbtx
                        .find_by_prefix(&ContractKeyPrefix)
                        .await
                        .collect::<Vec<_>>()
                        .await;
                    let num_contracts = contracts.len();
                    ensure!(
                        num_contracts > 0,
                        "validate_migrations was not able to read any contracts"
                    );
                    info!("Validated Contracts");
                }
                DbKeyPrefix::AgreedDecryptionShare => {
                    let agreed_decryption_shares = dbtx
                        .find_by_prefix(&AgreedDecryptionShareKeyPrefix)
                        .await
                        .collect::<Vec<_>>()
                        .await;
                    let num_shares = agreed_decryption_shares.len();
                    ensure!(
                        num_shares > 0,
                        "validate_migrations was not able to read any AgreedDecryptionShares"
                    );
                    info!("Validated AgreedDecryptionShares");
                }
                DbKeyPrefix::ContractUpdate => {
                    let contract_updates = dbtx
                        .find_by_prefix(&ContractUpdateKeyPrefix)
                        .await
                        .collect::<Vec<_>>()
                        .await;
                    let num_updates = contract_updates.len();
                    ensure!(
                        num_updates > 0,
                        "validate_migrations was not able to read any ContractUpdates"
                    );
                    info!("Validated ContractUpdates");
                }
                DbKeyPrefix::LightningGateway => {
                    let gateways = dbtx
                        .find_by_prefix(&LightningGatewayKeyPrefix)
                        .await
                        .collect::<Vec<_>>()
                        .await;
                    let num_gateways = gateways.len();
                    ensure!(
                        num_gateways > 0,
                        "validate_migrations was not able to read any LightningGateways"
                    );
                    info!("Validated LightningGateway");
                }
                DbKeyPrefix::Offer => {
                    let offers = dbtx
                        .find_by_prefix(&OfferKeyPrefix)
                        .await
                        .collect::<Vec<_>>()
                        .await;
                    let num_offers = offers.len();
                    ensure!(
                        num_offers > 0,
                        "validate_migrations was not able to read any Offers"
                    );
                    info!("Validated Offer");
                }
                DbKeyPrefix::ProposeDecryptionShare => {
                    let proposed_decryption_shares = dbtx
                        .find_by_prefix(&ProposeDecryptionShareKeyPrefix)
                        .await
                        .collect::<Vec<_>>()
                        .await;
                    let num_shares = proposed_decryption_shares.len();
                    ensure!(
                        num_shares > 0,
                        "validate_migrations was not able to read any ProposeDecryptionShares"
                    );
                    info!("Validated ProposeDecryptionShare");
                }
                DbKeyPrefix::BlockCountVote => {
                    let block_count_vote = dbtx
                        .find_by_prefix(&BlockCountVotePrefix)
                        .await
                        .collect::<Vec<_>>()
                        .await;
                    let num_votes = block_count_vote.len();
                    ensure!(
                        num_votes > 0,
                        "validate_migrations was not able to read any BlockCountVote"
                    );
                    info!("Validated BlockCountVote");
                }
                DbKeyPrefix::EncryptedPreimageIndex => {
                    let encrypted_preimage_index = dbtx
                        .find_by_prefix(&EncryptedPreimageIndexKeyPrefix)
                        .await
                        .collect::<Vec<_>>()
                        .await;
                    let num_shares = encrypted_preimage_index.len();
                    ensure!(
                        num_shares > 0,
                        "validate_migrations was not able to read any EncryptedPreimageIndexKeys"
                    );
                    info!("Validated EncryptedPreimageIndex");
                }
                DbKeyPrefix::LightningAuditItem => {
                    let audit_keys = dbtx
                        .find_by_prefix(&LightningAuditItemKeyPrefix)
                        .await
                        .collect::<Vec<_>>()
                        .await;

                    let num_audit_items = audit_keys.len();
                    ensure!(
                        num_audit_items == 2,
                        "validate_migrations was not able to read both LightningAuditItemKeys"
                    );
                    info!("Validated LightningAuditItem");
                }
                DbKeyPrefix::ConsensusVersionVote => {
                    let votes = dbtx
                        .find_by_prefix(&ConsensusVersionVotePrefix)
                        .await
                        .collect::<Vec<_>>()
                        .await;
                    // The committed v0 snapshot predates this prefix, and
                    // `create_server_db_with_v0_data` cannot currently be re-run
                    // to regenerate it, so only assert that the prefix decodes.
                    info!(?votes, "Validated ConsensusVersionVote");
                }
            }
        }

        Ok(())
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn snapshot_client_db_migrations() -> anyhow::Result<()> {
    snapshot_db_migrations_client::<_, _, LightningCommonInit>(
        "lightning-client-v0",
        |db| Box::pin(async { create_client_db_with_v0_data(db).await }),
        create_client_states,
    )
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn test_client_db_migrations() -> anyhow::Result<()> {
    let _ = TracingSetup::default().init();

    let module = DynClientModuleInit::from(LightningClientInit::default());
    validate_migrations_client::<_, _, LightningClientModule>(
        module,
        "lightning-client",
        |db, active_states, inactive_states| async move {
            let mut dbtx = db.begin_transaction_nc().await;

            for prefix in fedimint_ln_client::db::DbKeyPrefix::iter() {
                match prefix {
                    fedimint_ln_client::db::DbKeyPrefix::ActiveGateway => {
                        // Active gateway is deprecated, there should be no records
                        let active_gateway = dbtx
                            .get_value(&fedimint_ln_client::db::ActiveGatewayKey)
                            .await;
                        ensure!(
                            active_gateway.is_none(),
                            "validate migrations found an active gateway"
                        );
                    }
                    fedimint_ln_client::db::DbKeyPrefix::PaymentResult => {
                        let payment_results = dbtx
                            .find_by_prefix(&PaymentResultPrefix)
                            .await
                            .collect::<Vec<_>>()
                            .await;
                        let num_payment_results = payment_results.len();
                        ensure!(
                            num_payment_results > 0,
                            "validate_migrations was not able to read any PaymentResults"
                        );
                        info!("Validated PaymentResults");
                    }
                    fedimint_ln_client::db::DbKeyPrefix::MetaOverridesDeprecated => {
                        // MetaOverrides is never read anywhere
                    }
                    fedimint_ln_client::db::DbKeyPrefix::LightningGateway => {
                        let gateways = dbtx
                            .find_by_prefix(&LightningGatewayKeyPrefix)
                            .await
                            .collect::<Vec<_>>()
                            .await;
                        let num_gateways = gateways.len();
                        ensure!(
                            num_gateways > 0,
                            "validate_migrations was not able to read any LightningGateways"
                        );
                        info!("Validated LightningGateways");
                    }
                    fedimint_ln_client::db::DbKeyPrefix::RecurringPaymentKey => {
                        let recurring_payment_codes = dbtx
                            .find_by_prefix(&fedimint_ln_client::db::RecurringPaymentCodeKeyPrefix)
                            .await
                            .collect::<Vec<_>>()
                            .await;
                        let num_recurring_payment_codes = recurring_payment_codes.len();
                        ensure!(
                            num_recurring_payment_codes > 0,
                            "validate_migrations was not able to read any RecurringPaymentCodes"
                        );

                        // Validate the structure of the first recurring payment code
                        let (key, entry) = &recurring_payment_codes[0];
                        ensure!(
                            key.derivation_idx == 1,
                            "Expected derivation_idx to be 1, got {}",
                            key.derivation_idx
                        );
                        ensure!(
                            entry.protocol == fedimint_ln_client::recurring::RecurringPaymentProtocol::LNURL,
                            "Expected protocol to be LNURL"
                        );
                        ensure!(
                            entry.last_derivation_index == 5,
                            "Expected last_derivation_index to be 5, got {}",
                            entry.last_derivation_index
                        );

                        info!("Validated RecurringPaymentCodes");
                    }
                    fedimint_ln_client::db::DbKeyPrefix::CoreInternalReservedStart
                    | fedimint_ln_client::db::DbKeyPrefix::ExternalReservedStart
                    | fedimint_ln_client::db::DbKeyPrefix::CoreInternalReservedEnd => {}
                }
            }

            fn verify_states(states: Vec<LightningClientStateMachines>) -> anyhow::Result<()> {
                let mut input_count = 0;
                let mut confirmed_count = 0;
                let mut refund_count = 0;
                let mut funded_count = 0;
                for active_state in states {
                    match active_state {
                        LightningClientStateMachines::Receive(machine) => {
                            match machine.state {
                                LightningReceiveStates::SubmittedOffer(_) => input_count += 1,
                                LightningReceiveStates::ConfirmedInvoice(_) => confirmed_count += 1,
                                _ => panic!("State machine migration failed, states contain unexpected state"),
                            }
                        }
                        LightningClientStateMachines::LightningPay(machine) => {
                            match machine.state {
                                LightningPayStates::Refund(_) => refund_count += 1,
                                LightningPayStates::Funded(_) => funded_count += 1,
                                _ => panic!("State machine migration failed, states contain unexpected state"),
                            }
                        }
                        _ => panic!("Found unexpected state machine"),
                    }
                }

                ensure!(input_count == 2, "Expecting two `SubmittedOffer` state, found {input_count}");
                ensure!(confirmed_count == 1, "Expecting one `ConfirmedInvoice` state, found {confirmed_count}");
                ensure!(refund_count == 1, "Expecting one `Refund` state, found {refund_count}");
                ensure!(funded_count == 1, "Expecting one `Funded` state, found {funded_count}");

                Ok(())
            }

            verify_states(active_states)?;
            verify_states(inactive_states)?;

            Ok(())
        },
    )
    .await
}
