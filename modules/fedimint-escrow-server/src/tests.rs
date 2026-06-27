use assert_matches::assert_matches;
use fedimint_core::config::FederationId;
use fedimint_core::db::mem_impl::MemDatabase;
use fedimint_core::db::{Database, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::module::Amounts;
use fedimint_core::module::registry::ModuleRegistry;
use fedimint_core::secp256k1::schnorr::Signature;
use fedimint_core::secp256k1::{Keypair, Message, Secp256k1};
use fedimint_core::{Amount, BitcoinHash, InPoint, OutPoint, TransactionId};
use fedimint_escrow_common::config::{EscrowConfig, EscrowConfigConsensus, EscrowConfigPrivate};
use fedimint_escrow_common::{
    ContractHash, EscrowContract, EscrowId, EscrowInput, EscrowInputError, EscrowMessage,
    EscrowOutput, EscrowOutputError, EscrowStatus, Outcome, PendingArbiterFee, Resolution,
    compute_contract_hash, compute_escrow_message,
};
use fedimint_server_core::ServerModule;
use rand::rngs::OsRng;

use crate::Escrow;
use crate::db::{EscrowContractKey, EscrowOutputOutcomeKey, PendingArbiterFeeKey};

fn make_escrow() -> Escrow {
    Escrow::new(EscrowConfig {
        private: EscrowConfigPrivate,
        consensus: EscrowConfigConsensus,
    })
}

fn make_keypair() -> Keypair {
    Keypair::new(&Secp256k1::new(), &mut OsRng)
}

fn dummy_federation_id() -> FederationId {
    FederationId(fedimint_core::bitcoin::hashes::sha256::Hash::all_zeros())
}

fn make_contract(
    buyer_kp: &Keypair,
    seller_kp: &Keypair,
    arbiter_kp: &Keypair,
    amount: Amount,
    arbiter_fee: Amount,
    timeout: u64,
) -> EscrowContract {
    let buyer_key = buyer_kp.public_key();
    let seller_key = seller_kp.public_key();
    let arbiter_key = arbiter_kp.public_key();
    let federation_id = dummy_federation_id();

    let contract_hash = compute_contract_hash(
        &buyer_key,
        &seller_key,
        &arbiter_key,
        &amount,
        &timeout,
        &federation_id,
    );

    let escrow_id = EscrowId(contract_hash.0);

    EscrowContract {
        escrow_id,
        buyer_key,
        seller_key,
        arbiter_key,
        amount,
        arbiter_fee,
        contract_hash,
        timeout,
        federation_id,
        status: EscrowStatus::Active,
    }
}

fn future_timeout() -> u64 {
    fedimint_core::time::duration_since_epoch().as_secs() + 9999
}

fn past_timeout() -> u64 {
    fedimint_core::time::duration_since_epoch().as_secs() - 1
}

fn sign_release(buyer_kp: &Keypair, contract: &EscrowContract) -> Signature {
    let msg_bytes = compute_escrow_message(&contract.resolution_message(Outcome::Release));
    Secp256k1::new().sign_schnorr(&Message::from_digest(msg_bytes), buyer_kp)
}

fn sign_arbiter(arbiter_kp: &Keypair, contract: &EscrowContract, outcome: Outcome) -> Signature {
    let msg_bytes = compute_escrow_message(&contract.resolution_message(outcome));
    Secp256k1::new().sign_schnorr(&Message::from_digest(msg_bytes), arbiter_kp)
}

fn sign_fee_claim(arbiter_kp: &Keypair, escrow_id: EscrowId, fee: Amount) -> Signature {
    let msg_bytes = compute_escrow_message(&EscrowMessage::ArbiterFeeClaim {
        escrow_id,
        fee_amount: fee,
    });
    Secp256k1::new().sign_schnorr(&Message::from_digest(msg_bytes), arbiter_kp)
}

fn dummy_in_point() -> InPoint {
    InPoint {
        txid: TransactionId::all_zeros(),
        in_idx: 0,
    }
}

fn dummy_out_point() -> OutPoint {
    OutPoint {
        txid: TransactionId::all_zeros(),
        out_idx: 0,
    }
}

#[test_log::test(tokio::test)]
async fn test_process_output_valid_contract_stored() {
    let escrow = make_escrow();
    let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
    let buyer_kp = make_keypair();
    let seller_kp = make_keypair();
    let arbiter_kp = make_keypair();
    let contract = make_contract(
        &buyer_kp,
        &seller_kp,
        &arbiter_kp,
        Amount::from_sats(1000),
        Amount::from_sats(20),
        future_timeout(),
    );
    let output = EscrowOutput {
        contract: contract.clone(),
    };
    let out_point = dummy_out_point();

    let mut dbtx = db.begin_transaction_nc().await;
    let result = escrow
        .process_output(
            &mut dbtx.to_ref_with_prefix_module_id(42).0.into_nc(),
            &output,
            out_point,
        )
        .await;

    assert!(result.is_ok());
    let amounts = result.unwrap();
    assert_eq!(amounts.amounts, Amounts::new_bitcoin(contract.amount));

    // verify it was stored
    let stored = dbtx
        .to_ref_with_prefix_module_id(42)
        .0
        .into_nc()
        .get_value(&EscrowContractKey(contract.escrow_id))
        .await;
    assert!(stored.is_some());
    assert_eq!(stored.unwrap().status, EscrowStatus::Active);

    let outcome = dbtx
        .to_ref_with_prefix_module_id(42)
        .0
        .into_nc()
        .get_value(&EscrowOutputOutcomeKey(out_point))
        .await;

    assert!(outcome.is_some());
}

#[test_log::test(tokio::test)]
async fn test_process_output_duplicate_rejected() {
    let escrow = make_escrow();
    let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
    let buyer_kp = make_keypair();
    let seller_kp = make_keypair();
    let arbiter_kp = make_keypair();
    let contract = make_contract(
        &buyer_kp,
        &seller_kp,
        &arbiter_kp,
        Amount::from_sats(1000),
        Amount::from_sats(20),
        future_timeout(),
    );
    let output = EscrowOutput { contract };

    let mut dbtx = db.begin_transaction_nc().await;
    escrow
        .process_output(
            &mut dbtx.to_ref_with_prefix_module_id(42).0.into_nc(),
            &output,
            dummy_out_point(),
        )
        .await
        .unwrap();

    let second = escrow
        .process_output(
            &mut dbtx.to_ref_with_prefix_module_id(42).0.into_nc(),
            &output,
            OutPoint {
                txid: TransactionId::all_zeros(),
                out_idx: 1,
            },
        )
        .await;

    assert_matches!(second, Err(EscrowOutputError::AlreadyExists));
}

#[test_log::test(tokio::test)]
async fn test_process_output_arbiter_fee_equals_amount_rejected() {
    let escrow = make_escrow();
    let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
    let buyer_kp = make_keypair();
    let seller_kp = make_keypair();
    let arbiter_kp = make_keypair();
    let contract = make_contract(
        &buyer_kp,
        &seller_kp,
        &arbiter_kp,
        Amount::from_sats(100),
        Amount::from_sats(100),
        future_timeout(),
    );
    let output = EscrowOutput { contract };

    let mut dbtx = db.begin_transaction_nc().await;
    let result = escrow
        .process_output(
            &mut dbtx.to_ref_with_prefix_module_id(42).0.into_nc(),
            &output,
            dummy_out_point(),
        )
        .await;

    assert_matches!(result, Err(EscrowOutputError::InvalidInputs));
}

#[test_log::test(tokio::test)]
async fn test_process_output_expired_timeout_rejected() {
    let escrow = make_escrow();
    let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
    let buyer_kp = make_keypair();
    let seller_kp = make_keypair();
    let arbiter_kp = make_keypair();
    let contract = make_contract(
        &buyer_kp,
        &seller_kp,
        &arbiter_kp,
        Amount::from_sats(1000),
        Amount::from_sats(20),
        past_timeout(),
    );
    let output = EscrowOutput { contract };

    let mut dbtx = db.begin_transaction_nc().await;
    let result = escrow
        .process_output(
            &mut dbtx.to_ref_with_prefix_module_id(42).0.into_nc(),
            &output,
            dummy_out_point(),
        )
        .await;

    assert_matches!(result, Err(EscrowOutputError::InvalidInputs));
}

#[test_log::test(tokio::test)]
async fn test_process_output_duplicate_keys_rejected() {
    let escrow = make_escrow();
    let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
    let buyer_kp = make_keypair();
    let seller_kp = make_keypair();

    let contract = make_contract(
        &buyer_kp,
        &seller_kp,
        &buyer_kp,
        Amount::from_sats(1000),
        Amount::from_sats(20),
        future_timeout(),
    );
    let output = EscrowOutput { contract };

    let mut dbtx = db.begin_transaction_nc().await;
    let result = escrow
        .process_output(
            &mut dbtx.to_ref_with_prefix_module_id(42).0.into_nc(),
            &output,
            dummy_out_point(),
        )
        .await;

    assert_matches!(result, Err(EscrowOutputError::InvalidInputs));
}

#[test_log::test(tokio::test)]
async fn test_process_output_tampered_contract_hash_rejected() {
    let escrow = make_escrow();
    let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
    let buyer_kp = make_keypair();
    let seller_kp = make_keypair();
    let arbiter_kp = make_keypair();
    let mut contract = make_contract(
        &buyer_kp,
        &seller_kp,
        &arbiter_kp,
        Amount::from_sats(1000),
        Amount::from_sats(20),
        future_timeout(),
    );
    contract.contract_hash = ContractHash([0xff; 32]);
    let output = EscrowOutput { contract };

    let mut dbtx = db.begin_transaction_nc().await;
    let result = escrow
        .process_output(
            &mut dbtx.to_ref_with_prefix_module_id(42).0.into_nc(),
            &output,
            dummy_out_point(),
        )
        .await;

    assert_matches!(result, Err(EscrowOutputError::ContractHashMismatch));
}

#[test_log::test(tokio::test)]
async fn test_buyer_release_valid() {
    let escrow = make_escrow();
    let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
    let buyer_kp = make_keypair();
    let seller_kp = make_keypair();
    let arbiter_kp = make_keypair();
    let contract = make_contract(
        &buyer_kp,
        &seller_kp,
        &arbiter_kp,
        Amount::from_sats(1000),
        Amount::from_sats(20),
        future_timeout(),
    );

    let mut dbtx = db.begin_transaction_nc().await;
    let mut module_dbtx = dbtx.to_ref_with_prefix_module_id(42).0.into_nc();
    module_dbtx
        .insert_entry(&EscrowContractKey(contract.escrow_id), &contract)
        .await;

    let sig = sign_release(&buyer_kp, &contract);
    let input = EscrowInput {
        escrow_id: contract.escrow_id,
        resolution: Resolution::BuyerRelease {
            buyer_signature: sig,
        },
    };

    let result = escrow
        .process_input(&mut module_dbtx, &input, dummy_in_point())
        .await;

    assert!(result.is_ok());
    let meta = result.unwrap();
    // seller is the recipient of the full amount
    assert_eq!(meta.pub_key, contract.seller_key);
    assert_eq!(meta.amount.amounts, Amounts::new_bitcoin(contract.amount));

    // status updated to Released
    let stored = module_dbtx
        .get_value(&EscrowContractKey(contract.escrow_id))
        .await
        .unwrap();
    assert_eq!(stored.status, EscrowStatus::Released);
}

#[test_log::test(tokio::test)]
async fn test_buyer_release_wrong_signature_rejected() {
    let escrow = make_escrow();
    let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
    let buyer_kp = make_keypair();
    let seller_kp = make_keypair();
    let arbiter_kp = make_keypair();
    let contract = make_contract(
        &buyer_kp,
        &seller_kp,
        &arbiter_kp,
        Amount::from_sats(1000),
        Amount::from_sats(20),
        future_timeout(),
    );

    let mut dbtx = db.begin_transaction_nc().await;
    let mut module_dbtx = dbtx.to_ref_with_prefix_module_id(42).0.into_nc();
    module_dbtx
        .insert_entry(&EscrowContractKey(contract.escrow_id), &contract)
        .await;
    // seller signing instead of buyer
    let sig = sign_release(&seller_kp, &contract);
    let input = EscrowInput {
        escrow_id: contract.escrow_id,
        resolution: Resolution::BuyerRelease {
            buyer_signature: sig,
        },
    };

    let result = escrow
        .process_input(&mut module_dbtx, &input, dummy_in_point())
        .await;

    assert_matches!(result, Err(EscrowInputError::InvalidBuyerSignature));
}

#[test_log::test(tokio::test)]
async fn test_buyer_release_signs_refund_outcome_rejected() {
    let escrow = make_escrow();
    let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
    let buyer_kp = make_keypair();
    let seller_kp = make_keypair();
    let arbiter_kp = make_keypair();
    let contract = make_contract(
        &buyer_kp,
        &seller_kp,
        &arbiter_kp,
        Amount::from_sats(1000),
        Amount::from_sats(20),
        future_timeout(),
    );

    let mut dbtx = db.begin_transaction_nc().await;
    let mut module_dbtx = dbtx.to_ref_with_prefix_module_id(42).0.into_nc();
    module_dbtx
        .insert_entry(&EscrowContractKey(contract.escrow_id), &contract)
        .await;

    // buyer signs Refund outcome which should fail
    let sig = sign_arbiter(&buyer_kp, &contract, Outcome::Refund);
    let input = EscrowInput {
        escrow_id: contract.escrow_id,
        resolution: Resolution::BuyerRelease {
            buyer_signature: sig,
        },
    };

    let result = escrow
        .process_input(&mut module_dbtx, &input, dummy_in_point())
        .await;

    assert_matches!(result, Err(EscrowInputError::InvalidBuyerSignature));
}

#[test_log::test(tokio::test)]
async fn test_buyer_release_already_released_rejected() {
    let escrow = make_escrow();
    let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
    let buyer_kp = make_keypair();
    let seller_kp = make_keypair();
    let arbiter_kp = make_keypair();
    let mut contract = make_contract(
        &buyer_kp,
        &seller_kp,
        &arbiter_kp,
        Amount::from_sats(1000),
        Amount::from_sats(20),
        future_timeout(),
    );
    contract.status = EscrowStatus::Released;

    let mut dbtx = db.begin_transaction_nc().await;
    let mut module_dbtx = dbtx.to_ref_with_prefix_module_id(42).0.into_nc();
    module_dbtx
        .insert_entry(&EscrowContractKey(contract.escrow_id), &contract)
        .await;

    let sig = sign_release(&buyer_kp, &contract);
    let input = EscrowInput {
        escrow_id: contract.escrow_id,
        resolution: Resolution::BuyerRelease {
            buyer_signature: sig,
        },
    };

    let result = escrow
        .process_input(&mut module_dbtx, &input, dummy_in_point())
        .await;

    assert_matches!(result, Err(EscrowInputError::InvalidStateTransition));
}

#[test_log::test(tokio::test)]
async fn test_arbiter_release_after_timeout_valid() {
    let escrow = make_escrow();
    let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
    let buyer_kp = make_keypair();
    let seller_kp = make_keypair();
    let arbiter_kp = make_keypair();
    let contract = make_contract(
        &buyer_kp,
        &seller_kp,
        &arbiter_kp,
        Amount::from_sats(1000),
        Amount::from_sats(20),
        past_timeout(),
    );

    let mut dbtx = db.begin_transaction_nc().await;
    let mut module_dbtx = dbtx.to_ref_with_prefix_module_id(42).0.into_nc();
    module_dbtx
        .insert_entry(&EscrowContractKey(contract.escrow_id), &contract)
        .await;

    let sig = sign_arbiter(&arbiter_kp, &contract, Outcome::Release);
    let input = EscrowInput {
        escrow_id: contract.escrow_id,
        resolution: Resolution::ArbiterOutcome {
            arbiter_signature: sig,
            outcome: Outcome::Release,
        },
    };

    let result = escrow
        .process_input(&mut module_dbtx, &input, dummy_in_point())
        .await;

    assert!(result.is_ok());
    let meta = result.unwrap();
    assert_eq!(meta.pub_key, contract.seller_key);
    assert_eq!(
        meta.amount.amounts,
        Amounts::new_bitcoin(contract.amount - contract.arbiter_fee)
    );

    let pending = module_dbtx
        .get_value(&PendingArbiterFeeKey(contract.escrow_id))
        .await;
    assert!(pending.is_some());
    assert_eq!(pending.unwrap().fee_amount, contract.arbiter_fee);

    // Contract status updated
    let stored = module_dbtx
        .get_value(&EscrowContractKey(contract.escrow_id))
        .await
        .unwrap();
    assert_eq!(stored.status, EscrowStatus::Released);
}

#[test_log::test(tokio::test)]
async fn test_arbiter_refund_after_timeout_valid() {
    let escrow = make_escrow();
    let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
    let buyer_kp = make_keypair();
    let seller_kp = make_keypair();
    let arbiter_kp = make_keypair();
    let contract = make_contract(
        &buyer_kp,
        &seller_kp,
        &arbiter_kp,
        Amount::from_sats(1000),
        Amount::from_sats(20),
        past_timeout(),
    );

    let mut dbtx = db.begin_transaction_nc().await;
    let mut module_dbtx = dbtx.to_ref_with_prefix_module_id(42).0.into_nc();
    module_dbtx
        .insert_entry(&EscrowContractKey(contract.escrow_id), &contract)
        .await;

    let sig = sign_arbiter(&arbiter_kp, &contract, Outcome::Refund);
    let input = EscrowInput {
        escrow_id: contract.escrow_id,
        resolution: Resolution::ArbiterOutcome {
            arbiter_signature: sig,
            outcome: Outcome::Refund,
        },
    };

    let result = escrow
        .process_input(&mut module_dbtx, &input, dummy_in_point())
        .await;

    assert!(result.is_ok());
    // Refund → buyer receives payout
    assert_eq!(result.unwrap().pub_key, contract.buyer_key);

    let stored = module_dbtx
        .get_value(&EscrowContractKey(contract.escrow_id))
        .await
        .unwrap();
    assert_eq!(stored.status, EscrowStatus::Refunded);
}

#[test_log::test(tokio::test)]
async fn test_arbiter_wrong_signature_rejected() {
    let escrow = make_escrow();
    let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
    let buyer_kp = make_keypair();
    let seller_kp = make_keypair();
    let arbiter_kp = make_keypair();
    let contract = make_contract(
        &buyer_kp,
        &seller_kp,
        &arbiter_kp,
        Amount::from_sats(1000),
        Amount::from_sats(20),
        past_timeout(),
    );

    let mut dbtx = db.begin_transaction_nc().await;
    let mut module_dbtx = dbtx.to_ref_with_prefix_module_id(42).0.into_nc();
    module_dbtx
        .insert_entry(&EscrowContractKey(contract.escrow_id), &contract)
        .await;

    // buyer signing instead of arbiter
    let sig = sign_arbiter(&buyer_kp, &contract, Outcome::Release);
    let input = EscrowInput {
        escrow_id: contract.escrow_id,
        resolution: Resolution::ArbiterOutcome {
            arbiter_signature: sig,
            outcome: Outcome::Release,
        },
    };

    let result = escrow
        .process_input(&mut module_dbtx, &input, dummy_in_point())
        .await;

    assert_matches!(result, Err(EscrowInputError::InvalidArbiterSignature));
}

#[test_log::test(tokio::test)]
async fn test_arbiter_outcome_mismatch_rejected() {
    // Arbiter signs Release but declares Refund in the input
    let escrow = make_escrow();
    let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
    let buyer_kp = make_keypair();
    let seller_kp = make_keypair();
    let arbiter_kp = make_keypair();
    let contract = make_contract(
        &buyer_kp,
        &seller_kp,
        &arbiter_kp,
        Amount::from_sats(1000),
        Amount::from_sats(20),
        past_timeout(),
    );

    let mut dbtx = db.begin_transaction_nc().await;
    let mut module_dbtx = dbtx.to_ref_with_prefix_module_id(42).0.into_nc();
    module_dbtx
        .insert_entry(&EscrowContractKey(contract.escrow_id), &contract)
        .await;

    let sig = sign_arbiter(&arbiter_kp, &contract, Outcome::Release);
    let input = EscrowInput {
        escrow_id: contract.escrow_id,
        resolution: Resolution::ArbiterOutcome {
            arbiter_signature: sig,
            outcome: Outcome::Refund,
        },
    };

    let result = escrow
        .process_input(&mut module_dbtx, &input, dummy_in_point())
        .await;

    assert_matches!(result, Err(EscrowInputError::InvalidArbiterSignature));
}

#[test_log::test(tokio::test)]
async fn test_fee_claim_valid() {
    let escrow = make_escrow();
    let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
    let buyer_kp = make_keypair();
    let seller_kp = make_keypair();
    let arbiter_kp = make_keypair();
    let contract = make_contract(
        &buyer_kp,
        &seller_kp,
        &arbiter_kp,
        Amount::from_sats(1000),
        Amount::from_sats(20),
        past_timeout(),
    );

    let mut dbtx = db.begin_transaction_nc().await;
    let mut module_dbtx = dbtx.to_ref_with_prefix_module_id(42).0.into_nc();

    module_dbtx
        .insert_entry(
            &PendingArbiterFeeKey(contract.escrow_id),
            &PendingArbiterFee {
                escrow_id: contract.escrow_id,
                arbiter_key: arbiter_kp.public_key(),
                fee_amount: contract.arbiter_fee,
            },
        )
        .await;

    let sig = sign_fee_claim(&arbiter_kp, contract.escrow_id, contract.arbiter_fee);
    let input = EscrowInput {
        escrow_id: contract.escrow_id,
        resolution: Resolution::ArbiterFeeClaim {
            arbiter_signature: sig,
        },
    };

    let result = escrow
        .process_input(&mut module_dbtx, &input, dummy_in_point())
        .await;

    assert!(result.is_ok());
    let meta = result.unwrap();
    assert_eq!(meta.pub_key, arbiter_kp.public_key());
    assert_eq!(
        meta.amount.amounts,
        Amounts::new_bitcoin(contract.arbiter_fee)
    );

    let pending = module_dbtx
        .get_value(&PendingArbiterFeeKey(contract.escrow_id))
        .await;

    assert!(pending.is_none());
}

#[test_log::test(tokio::test)]
async fn test_fee_claim_wrong_signature_rejected() {
    let escrow = make_escrow();
    let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
    let buyer_kp = make_keypair();
    let seller_kp = make_keypair();
    let arbiter_kp = make_keypair();
    let contract = make_contract(
        &buyer_kp,
        &seller_kp,
        &arbiter_kp,
        Amount::from_sats(1000),
        Amount::from_sats(20),
        past_timeout(),
    );

    let mut dbtx = db.begin_transaction_nc().await;
    let mut module_dbtx = dbtx.to_ref_with_prefix_module_id(42).0.into_nc();
    module_dbtx
        .insert_entry(
            &PendingArbiterFeeKey(contract.escrow_id),
            &PendingArbiterFee {
                escrow_id: contract.escrow_id,
                arbiter_key: arbiter_kp.public_key(),
                fee_amount: contract.arbiter_fee,
            },
        )
        .await;

    // buyer signing the fee claim instead of arbiter
    let sig = sign_fee_claim(&buyer_kp, contract.escrow_id, contract.arbiter_fee);
    let input = EscrowInput {
        escrow_id: contract.escrow_id,
        resolution: Resolution::ArbiterFeeClaim {
            arbiter_signature: sig,
        },
    };

    let result = escrow
        .process_input(&mut module_dbtx, &input, dummy_in_point())
        .await;

    assert_matches!(result, Err(EscrowInputError::InvalidArbiterSignature));
}

#[test_log::test(tokio::test)]
async fn test_fee_claim_wrong_amount_signature_rejected() {
    let escrow = make_escrow();
    let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
    let buyer_kp = make_keypair();
    let seller_kp = make_keypair();
    let arbiter_kp = make_keypair();
    let contract = make_contract(
        &buyer_kp,
        &seller_kp,
        &arbiter_kp,
        Amount::from_sats(1000),
        Amount::from_sats(20),
        past_timeout(),
    );

    let mut dbtx = db.begin_transaction_nc().await;
    let mut module_dbtx = dbtx.to_ref_with_prefix_module_id(42).0.into_nc();
    module_dbtx
        .insert_entry(
            &PendingArbiterFeeKey(contract.escrow_id),
            &PendingArbiterFee {
                escrow_id: contract.escrow_id,
                arbiter_key: arbiter_kp.public_key(),
                fee_amount: contract.arbiter_fee,
            },
        )
        .await;

    let sig = sign_fee_claim(&arbiter_kp, contract.escrow_id, Amount::from_sats(999));
    let input = EscrowInput {
        escrow_id: contract.escrow_id,
        resolution: Resolution::ArbiterFeeClaim {
            arbiter_signature: sig,
        },
    };

    let result = escrow
        .process_input(&mut module_dbtx, &input, dummy_in_point())
        .await;

    assert_matches!(result, Err(EscrowInputError::InvalidArbiterSignature));
}

#[test_log::test]
fn test_contract_transition_active_to_released() {
    let buyer_kp = make_keypair();
    let seller_kp = make_keypair();
    let arbiter_kp = make_keypair();
    let mut contract = make_contract(
        &buyer_kp,
        &seller_kp,
        &arbiter_kp,
        Amount::from_sats(100),
        Amount::from_sats(5),
        future_timeout(),
    );
    assert!(contract.transition(EscrowStatus::Released).is_ok());
    assert_eq!(contract.status, EscrowStatus::Released);
}

#[test_log::test]
fn test_contract_transition_active_to_refunded() {
    let buyer_kp = make_keypair();
    let seller_kp = make_keypair();
    let arbiter_kp = make_keypair();
    let mut contract = make_contract(
        &buyer_kp,
        &seller_kp,
        &arbiter_kp,
        Amount::from_sats(100),
        Amount::from_sats(5),
        future_timeout(),
    );
    assert!(contract.transition(EscrowStatus::Refunded).is_ok());
    assert_eq!(contract.status, EscrowStatus::Refunded);
}

#[test_log::test]
fn test_contract_transition_released_to_released_rejected() {
    let buyer_kp = make_keypair();
    let seller_kp = make_keypair();
    let arbiter_kp = make_keypair();
    let mut contract = make_contract(
        &buyer_kp,
        &seller_kp,
        &arbiter_kp,
        Amount::from_sats(100),
        Amount::from_sats(5),
        future_timeout(),
    );
    contract.status = EscrowStatus::Released;
    assert_matches!(
        contract.transition(EscrowStatus::Released),
        Err(EscrowInputError::InvalidStateTransition)
    );
}

#[test_log::test]
fn test_contract_transition_refunded_to_released_rejected() {
    let buyer_kp = make_keypair();
    let seller_kp = make_keypair();
    let arbiter_kp = make_keypair();
    let mut contract = make_contract(
        &buyer_kp,
        &seller_kp,
        &arbiter_kp,
        Amount::from_sats(100),
        Amount::from_sats(5),
        future_timeout(),
    );
    contract.status = EscrowStatus::Refunded;
    assert_matches!(
        contract.transition(EscrowStatus::Released),
        Err(EscrowInputError::InvalidStateTransition)
    );
}
