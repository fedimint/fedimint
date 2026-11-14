use assert_matches::assert_matches;
use fedimint_core::config::FederationId;
use fedimint_core::db::mem_impl::MemDatabase;
use fedimint_core::db::{Database, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::module::Amounts;
use fedimint_core::module::registry::ModuleRegistry;
use fedimint_core::secp256k1::schnorr::Signature;
use fedimint_core::secp256k1::{Keypair, Message, Parity, PublicKey, Secp256k1};
use fedimint_core::{Amount, BitcoinHash, InPoint, NumPeers, OutPoint, PeerId, TransactionId};
use fedimint_escrow_common::config::{EscrowConfig, EscrowConfigConsensus, EscrowConfigPrivate};
use fedimint_escrow_common::{
    ClaimPool, ContractHash, EscrowConsensusItem, EscrowContract, EscrowContractValidationError,
    EscrowId, EscrowInput, EscrowInputError, EscrowOutput, EscrowOutputError, EscrowStatus,
    FallbackPolicy, Outcome, Resolution, compute_contract_hash, compute_escrow_message,
};
use fedimint_server_core::ServerModule;
use rand::rngs::OsRng;

use crate::Escrow;
use crate::db::{ClaimPoolKey, EscrowContractKey, EscrowOutputOutcomeKey, UnixTimeVoteKey};

fn make_escrow() -> Escrow {
    Escrow {
        cfg: EscrowConfig {
            private: EscrowConfigPrivate,
            consensus: EscrowConfigConsensus,
        },
        num_peers: NumPeers::from(1usize),
    }
}

fn make_keypair() -> Keypair {
    Keypair::new(&Secp256k1::new(), &mut OsRng)
}

fn dummy_federation_id() -> FederationId {
    FederationId(fedimint_core::bitcoin::hashes::sha256::Hash::all_zeros())
}

#[allow(clippy::too_many_arguments)]
fn make_contract(
    funder_kp: &Keypair,
    recipient_kp: &Keypair,
    arbiter_kp: &Keypair,
    fee_kp: &Keypair,
    amount: Amount,
    arbiter_fee: Amount,
    timeout: u64,
    resolution_period: u64,
    default_fallback: FallbackPolicy,
) -> EscrowContract {
    let funder_key = funder_kp.public_key();
    let recipient_key = recipient_kp.public_key();
    let arbiter_key = arbiter_kp.public_key();
    let arbiter_fee_key = vec![fee_kp.public_key()];
    let federation_id = dummy_federation_id();

    let contract_hash = compute_contract_hash(
        &funder_key,
        &recipient_key,
        &arbiter_key,
        &arbiter_fee,
        &amount,
        &timeout,
        &federation_id,
        &resolution_period,
        &arbiter_fee_key,
        &default_fallback,
    );

    let escrow_id = EscrowId(contract_hash.0);

    EscrowContract {
        escrow_id,
        funder_key,
        recipient_key,
        arbiter_key,
        arbiter_fee_key,
        amount,
        arbiter_fee,
        contract_hash,
        timeout,
        federation_id,
        status: EscrowStatus::Active,
        resolution_period,
        default_fallback,
    }
}

fn sign_release(funder_kp: &Keypair, contract: &EscrowContract) -> Signature {
    let msg_bytes = compute_escrow_message(&contract.resolution_message(Outcome::Release));
    Secp256k1::new().sign_schnorr(&Message::from_digest(msg_bytes), funder_kp)
}

fn sign_arbiter(arbiter_kp: &Keypair, contract: &EscrowContract, outcome: Outcome) -> Signature {
    let msg_bytes = compute_escrow_message(&contract.resolution_message(outcome));
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
    let funder_kp = make_keypair();
    let recipient_kp = make_keypair();
    let arbiter_kp = make_keypair();
    let fee_kp = make_keypair();
    let contract = make_contract(
        &funder_kp,
        &recipient_kp,
        &arbiter_kp,
        &fee_kp,
        Amount::from_sats(1000),
        Amount::from_sats(20),
        10_000,
        3_600,
        FallbackPolicy::Refund,
    );
    let output = EscrowOutput::new_v0(contract.clone());
    let out_point = dummy_out_point();

    let mut dbtx = db.begin_transaction_nc().await;
    let result = escrow
        .process_output(
            &mut dbtx.to_ref_with_prefix_module_id(42).0.into_nc(),
            &output,
            out_point,
        )
        .await;

    let amounts = result.unwrap();
    assert_eq!(amounts.amounts, Amounts::new_bitcoin(contract.amount));
    assert_eq!(amounts.fees, Amounts::ZERO);

    // the contract is stored unchanged and still active
    let stored = dbtx
        .to_ref_with_prefix_module_id(42)
        .0
        .into_nc()
        .get_value(&EscrowContractKey(contract.escrow_id))
        .await;
    assert_eq!(stored, Some(contract.clone()));

    let outcome = dbtx
        .to_ref_with_prefix_module_id(42)
        .0
        .into_nc()
        .get_value(&EscrowOutputOutcomeKey(out_point))
        .await;
    assert!(outcome.is_some());
}

#[test_log::test(tokio::test)]
async fn test_process_output_swap_arbiter_contract_stored() {
    let escrow = make_escrow();
    let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
    let funder_kp = make_keypair();
    let recipient_kp = make_keypair();
    let arbiter_kp = make_keypair();
    let fee_kp = make_keypair();
    let swap_arbiter_kp = make_keypair();
    let swap_fee_kp = make_keypair();
    let contract = make_contract(
        &funder_kp,
        &recipient_kp,
        &arbiter_kp,
        &fee_kp,
        Amount::from_sats(1000),
        Amount::from_sats(20),
        10_000,
        3_600,
        FallbackPolicy::SwapArbiter {
            arbiter_key: swap_arbiter_kp.public_key(),
            arbiter_fee_key: vec![swap_fee_kp.public_key()],
            arbiter_fee: Amount::from_sats(30),
        },
    );

    let output = EscrowOutput::new_v0(contract.clone());
    let mut dbtx = db.begin_transaction_nc().await;
    let result = escrow
        .process_output(
            &mut dbtx.to_ref_with_prefix_module_id(42).0.into_nc(),
            &output,
            dummy_out_point(),
        )
        .await;

    assert!(result.is_ok());
    let stored = dbtx
        .to_ref_with_prefix_module_id(42)
        .0
        .into_nc()
        .get_value(&EscrowContractKey(contract.escrow_id))
        .await;
    assert_eq!(stored, Some(contract));
}

#[test_log::test(tokio::test)]
async fn test_process_output_duplicate_rejected() {
    let escrow = make_escrow();
    let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
    let funder_kp = make_keypair();
    let recipient_kp = make_keypair();
    let arbiter_kp = make_keypair();
    let fee_kp = make_keypair();
    let contract = make_contract(
        &funder_kp,
        &recipient_kp,
        &arbiter_kp,
        &fee_kp,
        Amount::from_sats(1000),
        Amount::from_sats(20),
        10_000,
        3_600,
        FallbackPolicy::Refund,
    );
    let output = EscrowOutput::new_v0(contract);

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
    let funder_kp = make_keypair();
    let recipient_kp = make_keypair();
    let arbiter_kp = make_keypair();
    let fee_kp = make_keypair();
    let contract = make_contract(
        &funder_kp,
        &recipient_kp,
        &arbiter_kp,
        &fee_kp,
        Amount::from_sats(100),
        Amount::from_sats(100),
        10_000,
        3_600,
        FallbackPolicy::Refund,
    );
    let output = EscrowOutput::new_v0(contract);

    let mut dbtx = db.begin_transaction_nc().await;
    let result = escrow
        .process_output(
            &mut dbtx.to_ref_with_prefix_module_id(42).0.into_nc(),
            &output,
            dummy_out_point(),
        )
        .await;

    assert_matches!(
        result,
        Err(EscrowOutputError::InvalidInputs(
            EscrowContractValidationError::InvalidArbiterFee
        ))
    );
}

#[test_log::test(tokio::test)]
async fn test_process_output_timeout_not_in_future_rejected() {
    let escrow = make_escrow();
    let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
    let funder_kp = make_keypair();
    let recipient_kp = make_keypair();
    let arbiter_kp = make_keypair();
    let fee_kp = make_keypair();

    let contract = make_contract(
        &funder_kp,
        &recipient_kp,
        &arbiter_kp,
        &fee_kp,
        Amount::from_sats(1000),
        Amount::from_sats(20),
        5_000,
        3_600,
        FallbackPolicy::Refund,
    );
    let output = EscrowOutput::new_v0(contract);

    let mut dbtx = db.begin_transaction_nc().await;
    let mut module_dbtx = dbtx.to_ref_with_prefix_module_id(42).0.into_nc();
    module_dbtx
        .insert_entry(&UnixTimeVoteKey(PeerId::from(0u16)), &5_000)
        .await;

    let result = escrow
        .process_output(&mut module_dbtx, &output, dummy_out_point())
        .await;

    assert_matches!(
        result,
        Err(EscrowOutputError::InvalidInputs(
            EscrowContractValidationError::InvalidTimeout
        ))
    );
}

#[test_log::test(tokio::test)]
async fn test_process_output_duplicate_keys_rejected() {
    let escrow = make_escrow();
    let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
    let funder_kp = make_keypair();
    let recipient_kp = make_keypair();
    let fee_kp = make_keypair();
    // the funder is also the arbiter
    let contract = make_contract(
        &funder_kp,
        &recipient_kp,
        &funder_kp,
        &fee_kp,
        Amount::from_sats(1000),
        Amount::from_sats(20),
        10_000,
        3_600,
        FallbackPolicy::Refund,
    );
    let output = EscrowOutput::new_v0(contract);

    let mut dbtx = db.begin_transaction_nc().await;
    let result = escrow
        .process_output(
            &mut dbtx.to_ref_with_prefix_module_id(42).0.into_nc(),
            &output,
            dummy_out_point(),
        )
        .await;

    assert_matches!(
        result,
        Err(EscrowOutputError::InvalidInputs(
            EscrowContractValidationError::DuplicateKeys
        ))
    );
}

#[test_log::test(tokio::test)]
async fn test_process_output_swap_key_reusing_contract_key_rejected() {
    let escrow = make_escrow();
    let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
    let funder_kp = make_keypair();
    let recipient_kp = make_keypair();
    let arbiter_kp = make_keypair();
    let fee_kp = make_keypair();
    let swap_fee_kp = make_keypair();
    // adding replacement arbiter as the same key as the first arbiter
    let contract = make_contract(
        &funder_kp,
        &recipient_kp,
        &arbiter_kp,
        &fee_kp,
        Amount::from_sats(1000),
        Amount::from_sats(20),
        10_000,
        3_600,
        FallbackPolicy::SwapArbiter {
            arbiter_key: arbiter_kp.public_key(),
            arbiter_fee_key: vec![swap_fee_kp.public_key()],
            arbiter_fee: Amount::from_sats(30),
        },
    );
    let output = EscrowOutput::new_v0(contract);

    let mut dbtx = db.begin_transaction_nc().await;
    let result = escrow
        .process_output(
            &mut dbtx.to_ref_with_prefix_module_id(42).0.into_nc(),
            &output,
            dummy_out_point(),
        )
        .await;

    assert_matches!(
        result,
        Err(EscrowOutputError::InvalidInputs(
            EscrowContractValidationError::DuplicateKeys
        ))
    );
}

#[test_log::test(tokio::test)]
async fn test_process_output_missing_fee_keys_rejected() {
    let escrow = make_escrow();
    let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
    let funder_kp = make_keypair();
    let recipient_kp = make_keypair();
    let arbiter_kp = make_keypair();
    let fee_kp = make_keypair();
    let mut contract = make_contract(
        &funder_kp,
        &recipient_kp,
        &arbiter_kp,
        &fee_kp,
        Amount::from_sats(1000),
        Amount::from_sats(20),
        10_000,
        3_600,
        FallbackPolicy::Refund,
    );
    // a fee is given but not the claiming keys
    contract.arbiter_fee_key = vec![];
    let output = EscrowOutput::new_v0(contract);

    let mut dbtx = db.begin_transaction_nc().await;
    let result = escrow
        .process_output(
            &mut dbtx.to_ref_with_prefix_module_id(42).0.into_nc(),
            &output,
            dummy_out_point(),
        )
        .await;

    assert_matches!(
        result,
        Err(EscrowOutputError::InvalidInputs(
            EscrowContractValidationError::MissingArbiterFeeKeys
        ))
    );
}

#[test_log::test(tokio::test)]
async fn test_process_output_short_resolution_period_rejected() {
    let escrow = make_escrow();
    let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
    let funder_kp = make_keypair();
    let recipient_kp = make_keypair();
    let arbiter_kp = make_keypair();
    let fee_kp = make_keypair();

    let contract = make_contract(
        &funder_kp,
        &recipient_kp,
        &arbiter_kp,
        &fee_kp,
        Amount::from_sats(1000),
        Amount::from_sats(20),
        10_000,
        599,
        FallbackPolicy::Refund,
    );
    let output = EscrowOutput::new_v0(contract);

    let mut dbtx = db.begin_transaction_nc().await;
    let result = escrow
        .process_output(
            &mut dbtx.to_ref_with_prefix_module_id(42).0.into_nc(),
            &output,
            dummy_out_point(),
        )
        .await;

    assert_matches!(
        result,
        Err(EscrowOutputError::InvalidInputs(
            EscrowContractValidationError::InvalidResolutionTimeout
        ))
    );
}

#[test_log::test(tokio::test)]
async fn test_process_output_invalid_fallback_split_rejected() {
    let escrow = make_escrow();
    let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
    let funder_kp = make_keypair();
    let recipient_kp = make_keypair();
    let arbiter_kp = make_keypair();
    let fee_kp = make_keypair();

    let contract = make_contract(
        &funder_kp,
        &recipient_kp,
        &arbiter_kp,
        &fee_kp,
        Amount::from_sats(1000),
        Amount::from_sats(20),
        10_000,
        3_600,
        FallbackPolicy::Split {
            funder_split_bps: 6_000,
            recipient_split_bps: 3_000,
        },
    );
    let output = EscrowOutput::new_v0(contract);

    let mut dbtx = db.begin_transaction_nc().await;
    let result = escrow
        .process_output(
            &mut dbtx.to_ref_with_prefix_module_id(42).0.into_nc(),
            &output,
            dummy_out_point(),
        )
        .await;

    assert_matches!(
        result,
        Err(EscrowOutputError::InvalidInputs(
            EscrowContractValidationError::InvalidSplitRatio
        ))
    );
}

#[test_log::test(tokio::test)]
async fn test_process_output_tampered_contract_hash_rejected() {
    let escrow = make_escrow();
    let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
    let funder_kp = make_keypair();
    let recipient_kp = make_keypair();
    let arbiter_kp = make_keypair();
    let fee_kp = make_keypair();

    let mut contract = make_contract(
        &funder_kp,
        &recipient_kp,
        &arbiter_kp,
        &fee_kp,
        Amount::from_sats(1000),
        Amount::from_sats(20),
        10_000,
        3_600,
        FallbackPolicy::Refund,
    );
    contract.contract_hash = ContractHash([0xff; 32]);
    let output = EscrowOutput::new_v0(contract);

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
async fn test_funder_release_valid() {
    let escrow = make_escrow();
    let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
    let funder_kp = make_keypair();
    let recipient_kp = make_keypair();
    let arbiter_kp = make_keypair();
    let fee_kp = make_keypair();
    let contract = make_contract(
        &funder_kp,
        &recipient_kp,
        &arbiter_kp,
        &fee_kp,
        Amount::from_sats(1000),
        Amount::from_sats(20),
        10_000,
        3_600,
        FallbackPolicy::Refund,
    );

    let mut dbtx = db.begin_transaction_nc().await;
    let mut module_dbtx = dbtx.to_ref_with_prefix_module_id(42).0.into_nc();
    module_dbtx
        .insert_entry(&EscrowContractKey(contract.escrow_id), &contract)
        .await;

    let input = EscrowInput::new_v0(
        contract.escrow_id,
        Resolution::FunderRelease {
            funder_signature: sign_release(&funder_kp, &contract),
        },
    );
    let meta = escrow
        .process_input(&mut module_dbtx, &input, dummy_in_point())
        .await
        .unwrap();

    // the recipient is paid the full amount, no arbiter fee
    assert_eq!(meta.pub_key, contract.recipient_key);
    assert_eq!(meta.amount.amounts, Amounts::new_bitcoin(contract.amount));

    let stored = module_dbtx
        .get_value(&EscrowContractKey(contract.escrow_id))
        .await
        .unwrap();
    assert_eq!(stored.status, EscrowStatus::Released);

    // a funder release should never creates a claim pool
    let pool = module_dbtx
        .get_value(&ClaimPoolKey(contract.escrow_id))
        .await;
    assert!(pool.is_none());
}

#[test_log::test(tokio::test)]
async fn test_funder_release_wrong_signature_rejected() {
    let escrow = make_escrow();
    let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
    let funder_kp = make_keypair();
    let recipient_kp = make_keypair();
    let arbiter_kp = make_keypair();
    let fee_kp = make_keypair();
    let contract = make_contract(
        &funder_kp,
        &recipient_kp,
        &arbiter_kp,
        &fee_kp,
        Amount::from_sats(1000),
        Amount::from_sats(20),
        10_000,
        3_600,
        FallbackPolicy::Refund,
    );

    let mut dbtx = db.begin_transaction_nc().await;
    let mut module_dbtx = dbtx.to_ref_with_prefix_module_id(42).0.into_nc();
    module_dbtx
        .insert_entry(&EscrowContractKey(contract.escrow_id), &contract)
        .await;

    // recipient signing instead of funder
    let input = EscrowInput::new_v0(
        contract.escrow_id,
        Resolution::FunderRelease {
            funder_signature: sign_release(&funder_kp, &contract),
        },
    );

    let result = escrow
        .process_input(&mut module_dbtx, &input, dummy_in_point())
        .await;

    assert_matches!(result, Err(EscrowInputError::InvalidSignature));

    let stored = module_dbtx
        .get_value(&EscrowContractKey(contract.escrow_id))
        .await
        .unwrap();
    assert_eq!(stored.status, EscrowStatus::Active);
}

#[test_log::test(tokio::test)]
async fn test_funder_release_signs_refund_outcome_rejected() {
    let escrow = make_escrow();
    let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
    let funder_kp = make_keypair();
    let recipient_kp = make_keypair();
    let arbiter_kp = make_keypair();
    let fee_kp = make_keypair();
    let contract = make_contract(
        &funder_kp,
        &recipient_kp,
        &arbiter_kp,
        &fee_kp,
        Amount::from_sats(1000),
        Amount::from_sats(20),
        10_000,
        3_600,
        FallbackPolicy::Refund,
    );

    let mut dbtx = db.begin_transaction_nc().await;
    let mut module_dbtx = dbtx.to_ref_with_prefix_module_id(42).0.into_nc();
    module_dbtx
        .insert_entry(&EscrowContractKey(contract.escrow_id), &contract)
        .await;

    // funder signs the Refund outcome, which is invalid for happy path
    let input = EscrowInput::new_v0(
        contract.escrow_id,
        Resolution::FunderRelease {
            funder_signature: sign_arbiter(&arbiter_kp, &contract, Outcome::Refund),
        },
    );
    let result = escrow
        .process_input(&mut module_dbtx, &input, dummy_in_point())
        .await;

    assert_matches!(result, Err(EscrowInputError::InvalidSignature));
}

#[test_log::test(tokio::test)]
async fn test_funder_release_already_released_rejected() {
    let escrow = make_escrow();
    let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
    let funder_kp = make_keypair();
    let recipient_kp = make_keypair();
    let arbiter_kp = make_keypair();
    let fee_kp = make_keypair();
    let mut contract = make_contract(
        &funder_kp,
        &recipient_kp,
        &arbiter_kp,
        &fee_kp,
        Amount::from_sats(1000),
        Amount::from_sats(20),
        10_000,
        3_600,
        FallbackPolicy::Refund,
    );
    contract.status = EscrowStatus::Released;

    let mut dbtx = db.begin_transaction_nc().await;
    let mut module_dbtx = dbtx.to_ref_with_prefix_module_id(42).0.into_nc();
    module_dbtx
        .insert_entry(&EscrowContractKey(contract.escrow_id), &contract)
        .await;

    let input = EscrowInput::new_v0(
        contract.escrow_id,
        Resolution::FunderRelease {
            funder_signature: sign_release(&funder_kp, &contract),
        },
    );
    let result = escrow
        .process_input(&mut module_dbtx, &input, dummy_in_point())
        .await;

    assert_matches!(result, Err(EscrowInputError::ContractAlreadyResolved));
}

#[test_log::test(tokio::test)]
async fn test_funder_release_after_dispute_rejected() {
    let escrow = make_escrow();
    let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
    let funder_kp = make_keypair();
    let recipient_kp = make_keypair();
    let arbiter_kp = make_keypair();
    let fee_kp = make_keypair();
    let mut contract = make_contract(
        &funder_kp,
        &recipient_kp,
        &arbiter_kp,
        &fee_kp,
        Amount::from_sats(1000),
        Amount::from_sats(20),
        10_000,
        3_600,
        FallbackPolicy::Refund,
    );
    contract.status = EscrowStatus::Disputed {
        resolve_by: 5_000,
        swapped: false,
    };

    let mut dbtx = db.begin_transaction_nc().await;
    let mut module_dbtx = dbtx.to_ref_with_prefix_module_id(42).0.into_nc();
    module_dbtx
        .insert_entry(&EscrowContractKey(contract.escrow_id), &contract)
        .await;

    // a perfectly valid release signature is useless once the arbiter is engaged
    let input = EscrowInput::new_v0(
        contract.escrow_id,
        Resolution::FunderRelease {
            funder_signature: sign_release(&funder_kp, &contract),
        },
    );
    let result = escrow
        .process_input(&mut module_dbtx, &input, dummy_in_point())
        .await;

    assert_matches!(result, Err(EscrowInputError::ContractDisputed));
}

#[test_log::test(tokio::test)]
async fn test_input_for_unknown_contract_rejected() {
    let escrow = make_escrow();
    let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
    let funder_kp = make_keypair();
    let recipient_kp = make_keypair();
    let arbiter_kp = make_keypair();
    let fee_kp = make_keypair();
    // the contract is never stored
    let contract = make_contract(
        &funder_kp,
        &recipient_kp,
        &arbiter_kp,
        &fee_kp,
        Amount::from_sats(1000),
        Amount::from_sats(20),
        10_000,
        3_600,
        FallbackPolicy::Refund,
    );

    let mut dbtx = db.begin_transaction_nc().await;
    let mut module_dbtx = dbtx.to_ref_with_prefix_module_id(42).0.into_nc();

    let input = EscrowInput::new_v0(
        contract.escrow_id,
        Resolution::FunderRelease {
            funder_signature: sign_release(&funder_kp, &contract),
        },
    );
    let result = escrow
        .process_input(&mut module_dbtx, &input, dummy_in_point())
        .await;

    assert_matches!(result, Err(EscrowInputError::ContractNotFound));
}

#[test_log::test(tokio::test)]
async fn test_engage_arbiter_valid_at_exact_timeout() {
    let escrow = make_escrow();
    let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
    let funder_kp = make_keypair();
    let recipient_kp = make_keypair();
    let arbiter_kp = make_keypair();
    let fee_kp = make_keypair();
    let contract = make_contract(
        &funder_kp,
        &recipient_kp,
        &arbiter_kp,
        &fee_kp,
        Amount::from_sats(1000),
        Amount::from_sats(20),
        1_000,
        3_600,
        FallbackPolicy::Refund,
    );

    let mut dbtx = db.begin_transaction_nc().await;
    let mut module_dbtx = dbtx.to_ref_with_prefix_module_id(42).0.into_nc();
    module_dbtx
        .insert_entry(&EscrowContractKey(contract.escrow_id), &contract)
        .await;
    // federation time equals the timeout
    module_dbtx
        .insert_entry(&UnixTimeVoteKey(PeerId::from(0u16)), &1_000)
        .await;

    let msg_bytes = compute_escrow_message(&contract.engage_message());
    let sig = Secp256k1::new().sign_schnorr(&Message::from_digest(msg_bytes), &funder_kp);
    let input = EscrowInput::new_v0(
        contract.escrow_id,
        Resolution::ArbiterEngaged {
            disputant_pubkey: funder_kp.public_key(),
            disputant_signature: sig,
        },
    );
    let meta = escrow
        .process_input(&mut module_dbtx, &input, dummy_in_point())
        .await
        .unwrap();

    // no fund moves
    assert_eq!(meta.pub_key, contract.funder_key);
    assert_eq!(meta.amount.amounts, Amounts::ZERO);

    // the arbiter has resolution_period seconds from now to rule
    let stored = module_dbtx
        .get_value(&EscrowContractKey(contract.escrow_id))
        .await
        .unwrap();
    assert_eq!(
        stored.status,
        EscrowStatus::Disputed {
            resolve_by: 4_600,
            swapped: false
        }
    );
}

#[test_log::test(tokio::test)]
async fn test_engage_arbiter_before_timeout_rejected() {
    let escrow = make_escrow();
    let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
    let funder_kp = make_keypair();
    let recipient_kp = make_keypair();
    let arbiter_kp = make_keypair();
    let fee_kp = make_keypair();
    let contract = make_contract(
        &funder_kp,
        &recipient_kp,
        &arbiter_kp,
        &fee_kp,
        Amount::from_sats(1000),
        Amount::from_sats(20),
        1_000,
        3_600,
        FallbackPolicy::Refund,
    );

    let mut dbtx = db.begin_transaction_nc().await;
    let mut module_dbtx = dbtx.to_ref_with_prefix_module_id(42).0.into_nc();
    module_dbtx
        .insert_entry(&EscrowContractKey(contract.escrow_id), &contract)
        .await;
    // one second before the timeout
    module_dbtx
        .insert_entry(&UnixTimeVoteKey(PeerId::from(0u16)), &999)
        .await;

    let msg_bytes = compute_escrow_message(&contract.engage_message());
    let sig = Secp256k1::new().sign_schnorr(&Message::from_digest(msg_bytes), &funder_kp);
    let input = EscrowInput::new_v0(
        contract.escrow_id,
        Resolution::ArbiterEngaged {
            disputant_pubkey: funder_kp.public_key(),
            disputant_signature: sig,
        },
    );
    let result = escrow
        .process_input(&mut module_dbtx, &input, dummy_in_point())
        .await;

    assert_matches!(result, Err(EscrowInputError::TimeoutNotReached));

    let stored = module_dbtx
        .get_value(&EscrowContractKey(contract.escrow_id))
        .await
        .unwrap();
    assert_eq!(stored.status, EscrowStatus::Active);
}

#[test_log::test(tokio::test)]
async fn test_engage_arbiter_by_arbiter_rejected() {
    let escrow = make_escrow();
    let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
    let funder_kp = make_keypair();
    let recipient_kp = make_keypair();
    let arbiter_kp = make_keypair();
    let fee_kp = make_keypair();
    let contract = make_contract(
        &funder_kp,
        &recipient_kp,
        &arbiter_kp,
        &fee_kp,
        Amount::from_sats(1000),
        Amount::from_sats(20),
        1_000,
        3_600,
        FallbackPolicy::Refund,
    );

    let mut dbtx = db.begin_transaction_nc().await;
    let mut module_dbtx = dbtx.to_ref_with_prefix_module_id(42).0.into_nc();
    module_dbtx
        .insert_entry(&EscrowContractKey(contract.escrow_id), &contract)
        .await;
    module_dbtx
        .insert_entry(&UnixTimeVoteKey(PeerId::from(0u16)), &2_000)
        .await;

    // only the funder and the recipient can bring in the arbiter
    let msg_bytes = compute_escrow_message(&contract.engage_message());
    let sig = Secp256k1::new().sign_schnorr(&Message::from_digest(msg_bytes), &arbiter_kp);
    let input = EscrowInput::new_v0(
        contract.escrow_id,
        Resolution::ArbiterEngaged {
            disputant_pubkey: arbiter_kp.public_key(),
            disputant_signature: sig,
        },
    );
    let result = escrow
        .process_input(&mut module_dbtx, &input, dummy_in_point())
        .await;

    assert_matches!(result, Err(EscrowInputError::NotAParticipant));
}

#[test_log::test(tokio::test)]
async fn test_engage_arbiter_wrong_signature_rejected() {
    let escrow = make_escrow();
    let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
    let funder_kp = make_keypair();
    let recipient_kp = make_keypair();
    let arbiter_kp = make_keypair();
    let fee_kp = make_keypair();
    let contract = make_contract(
        &funder_kp,
        &recipient_kp,
        &arbiter_kp,
        &fee_kp,
        Amount::from_sats(1000),
        Amount::from_sats(20),
        1_000,
        3_600,
        FallbackPolicy::Refund,
    );

    let mut dbtx = db.begin_transaction_nc().await;
    let mut module_dbtx = dbtx.to_ref_with_prefix_module_id(42).0.into_nc();
    module_dbtx
        .insert_entry(&EscrowContractKey(contract.escrow_id), &contract)
        .await;
    module_dbtx
        .insert_entry(&UnixTimeVoteKey(PeerId::from(0u16)), &2_000)
        .await;

    // the input says funder, but the recipient signed
    let msg_bytes = compute_escrow_message(&contract.engage_message());
    let sig = Secp256k1::new().sign_schnorr(&Message::from_digest(msg_bytes), &recipient_kp);
    let input = EscrowInput::new_v0(
        contract.escrow_id,
        Resolution::ArbiterEngaged {
            disputant_pubkey: funder_kp.public_key(),
            disputant_signature: sig,
        },
    );
    let result = escrow
        .process_input(&mut module_dbtx, &input, dummy_in_point())
        .await;

    assert_matches!(result, Err(EscrowInputError::InvalidSignature));

    let stored = module_dbtx
        .get_value(&EscrowContractKey(contract.escrow_id))
        .await
        .unwrap();
    assert_eq!(stored.status, EscrowStatus::Active);
}

#[test_log::test(tokio::test)]
async fn test_engage_arbiter_twice_rejected() {
    let escrow = make_escrow();
    let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
    let funder_kp = make_keypair();
    let recipient_kp = make_keypair();
    let arbiter_kp = make_keypair();
    let fee_kp = make_keypair();
    let contract = make_contract(
        &funder_kp,
        &recipient_kp,
        &arbiter_kp,
        &fee_kp,
        Amount::from_sats(1000),
        Amount::from_sats(20),
        1_000,
        3_600,
        FallbackPolicy::Refund,
    );

    let mut dbtx = db.begin_transaction_nc().await;
    let mut module_dbtx = dbtx.to_ref_with_prefix_module_id(42).0.into_nc();
    module_dbtx
        .insert_entry(&EscrowContractKey(contract.escrow_id), &contract)
        .await;
    module_dbtx
        .insert_entry(&UnixTimeVoteKey(PeerId::from(0u16)), &2_000)
        .await;

    let msg_bytes = compute_escrow_message(&contract.engage_message());
    let sig = Secp256k1::new().sign_schnorr(&Message::from_digest(msg_bytes), &funder_kp);
    let input = EscrowInput::new_v0(
        contract.escrow_id,
        Resolution::ArbiterEngaged {
            disputant_pubkey: funder_kp.public_key(),
            disputant_signature: sig,
        },
    );
    escrow
        .process_input(&mut module_dbtx, &input, dummy_in_point())
        .await
        .unwrap();
    let second = escrow
        .process_input(&mut module_dbtx, &input, dummy_in_point())
        .await;

    assert_matches!(second, Err(EscrowInputError::ContractDisputed));
}

#[test_log::test(tokio::test)]
async fn test_arbiter_release_valid() {
    let escrow = make_escrow();
    let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
    let funder_kp = make_keypair();
    let recipient_kp = make_keypair();
    let arbiter_kp = make_keypair();
    let fee_kp = make_keypair();
    let mut contract = make_contract(
        &funder_kp,
        &recipient_kp,
        &arbiter_kp,
        &fee_kp,
        Amount::from_sats(1000),
        Amount::from_sats(20),
        1_000,
        3_600,
        FallbackPolicy::Refund,
    );
    contract.status = EscrowStatus::Disputed {
        resolve_by: 5_000,
        swapped: false,
    };

    let mut dbtx = db.begin_transaction_nc().await;
    let mut module_dbtx = dbtx.to_ref_with_prefix_module_id(42).0.into_nc();
    module_dbtx
        .insert_entry(&EscrowContractKey(contract.escrow_id), &contract)
        .await;
    module_dbtx
        .insert_entry(&UnixTimeVoteKey(PeerId::from(0u16)), &4_000)
        .await;

    let input = EscrowInput::new_v0(
        contract.escrow_id,
        Resolution::ArbiterOutcome {
            arbiter_signature: sign_arbiter(&arbiter_kp, &contract, Outcome::Release),
            outcome: Outcome::Release,
            submitter_pubkey: recipient_kp.public_key(),
        },
    );
    let meta = escrow
        .process_input(&mut module_dbtx, &input, dummy_in_point())
        .await
        .unwrap();

    // nobody is paid in this transaction, the submitter only authorizes it
    assert_eq!(meta.pub_key, recipient_kp.public_key());
    assert_eq!(meta.amount.amounts, Amounts::ZERO);

    let stored = module_dbtx
        .get_value(&EscrowContractKey(contract.escrow_id))
        .await
        .unwrap();
    assert_eq!(stored.status, EscrowStatus::Released);

    // recipient gets amount - fee, the fee key gets the fee
    let pool = module_dbtx
        .get_value(&ClaimPoolKey(contract.escrow_id))
        .await
        .unwrap();
    assert_eq!(
        pool,
        ClaimPool {
            escrow_id: contract.escrow_id,
            claimer: vec![
                (recipient_kp.public_key(), Amount::from_sats(980)),
                (fee_kp.public_key(), Amount::from_sats(20)),
            ],
        }
    );
}

#[test_log::test(tokio::test)]
async fn test_arbiter_refund_valid() {
    let escrow = make_escrow();
    let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
    let funder_kp = make_keypair();
    let recipient_kp = make_keypair();
    let arbiter_kp = make_keypair();
    let fee_kp = make_keypair();
    let mut contract = make_contract(
        &funder_kp,
        &recipient_kp,
        &arbiter_kp,
        &fee_kp,
        Amount::from_sats(1000),
        Amount::from_sats(20),
        1_000,
        3_600,
        FallbackPolicy::Refund,
    );
    contract.status = EscrowStatus::Disputed {
        resolve_by: 5_000,
        swapped: false,
    };

    let mut dbtx = db.begin_transaction_nc().await;
    let mut module_dbtx = dbtx.to_ref_with_prefix_module_id(42).0.into_nc();
    module_dbtx
        .insert_entry(&EscrowContractKey(contract.escrow_id), &contract)
        .await;
    module_dbtx
        .insert_entry(&UnixTimeVoteKey(PeerId::from(0u16)), &4_000)
        .await;

    let input = EscrowInput::new_v0(
        contract.escrow_id,
        Resolution::ArbiterOutcome {
            arbiter_signature: sign_arbiter(&arbiter_kp, &contract, Outcome::Refund),
            outcome: Outcome::Refund,
            submitter_pubkey: funder_kp.public_key(),
        },
    );
    let meta = escrow
        .process_input(&mut module_dbtx, &input, dummy_in_point())
        .await
        .unwrap();

    assert_eq!(meta.pub_key, funder_kp.public_key());
    assert_eq!(meta.amount.amounts, Amounts::ZERO);

    let stored = module_dbtx
        .get_value(&EscrowContractKey(contract.escrow_id))
        .await
        .unwrap();
    assert_eq!(stored.status, EscrowStatus::Refunded);

    let pool = module_dbtx
        .get_value(&ClaimPoolKey(contract.escrow_id))
        .await
        .unwrap();
    assert_eq!(
        pool.claimer,
        vec![
            (funder_kp.public_key(), Amount::from_sats(980)),
            (fee_kp.public_key(), Amount::from_sats(20)),
        ]
    );
}

#[test_log::test(tokio::test)]
async fn test_arbiter_split_valid() {
    let escrow = make_escrow();
    let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
    let funder_kp = make_keypair();
    let recipient_kp = make_keypair();
    let arbiter_kp = make_keypair();
    let fee_kp = make_keypair();
    let mut contract = make_contract(
        &funder_kp,
        &recipient_kp,
        &arbiter_kp,
        &fee_kp,
        Amount::from_sats(1000),
        Amount::from_sats(20),
        1_000,
        3_600,
        FallbackPolicy::Refund,
    );
    contract.status = EscrowStatus::Disputed {
        resolve_by: 5_000,
        swapped: false,
    };

    let mut dbtx = db.begin_transaction_nc().await;
    let mut module_dbtx = dbtx.to_ref_with_prefix_module_id(42).0.into_nc();
    module_dbtx
        .insert_entry(&EscrowContractKey(contract.escrow_id), &contract)
        .await;
    module_dbtx
        .insert_entry(&UnixTimeVoteKey(PeerId::from(0u16)), &4_000)
        .await;

    let outcome = Outcome::Split {
        funder_split_bps: 2_500,
        recipient_split_bps: 7_500,
    };
    let input = EscrowInput::new_v0(
        contract.escrow_id,
        Resolution::ArbiterOutcome {
            arbiter_signature: sign_arbiter(&arbiter_kp, &contract, outcome),
            outcome,
            submitter_pubkey: recipient_kp.public_key(),
        },
    );
    escrow
        .process_input(&mut module_dbtx, &input, dummy_in_point())
        .await
        .unwrap();

    let stored = module_dbtx
        .get_value(&EscrowContractKey(contract.escrow_id))
        .await
        .unwrap();
    assert_eq!(stored.status, EscrowStatus::Split);

    let pool = module_dbtx
        .get_value(&ClaimPoolKey(contract.escrow_id))
        .await
        .unwrap();
    assert_eq!(
        pool.claimer,
        vec![
            (funder_kp.public_key(), Amount::from_sats(245)),
            (recipient_kp.public_key(), Amount::from_sats(735)),
            (fee_kp.public_key(), Amount::from_sats(20)),
        ]
    );
}

#[test_log::test(tokio::test)]
async fn test_arbiter_ruling_at_resolve_by_valid() {
    let escrow = make_escrow();
    let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
    let funder_kp = make_keypair();
    let recipient_kp = make_keypair();
    let arbiter_kp = make_keypair();
    let fee_kp = make_keypair();
    let mut contract = make_contract(
        &funder_kp,
        &recipient_kp,
        &arbiter_kp,
        &fee_kp,
        Amount::from_sats(1000),
        Amount::from_sats(20),
        1_000,
        3_600,
        FallbackPolicy::Refund,
    );
    contract.status = EscrowStatus::Disputed {
        resolve_by: 5_000,
        swapped: false,
    };

    let mut dbtx = db.begin_transaction_nc().await;
    let mut module_dbtx = dbtx.to_ref_with_prefix_module_id(42).0.into_nc();
    module_dbtx
        .insert_entry(&EscrowContractKey(contract.escrow_id), &contract)
        .await;
    // federation time equals resolve_by: the arbiter still has time
    module_dbtx
        .insert_entry(&UnixTimeVoteKey(PeerId::from(0u16)), &5_000)
        .await;

    let input = EscrowInput::new_v0(
        contract.escrow_id,
        Resolution::ArbiterOutcome {
            arbiter_signature: sign_arbiter(&arbiter_kp, &contract, Outcome::Refund),
            outcome: Outcome::Refund,
            submitter_pubkey: funder_kp.public_key(),
        },
    );
    let result = escrow
        .process_input(&mut module_dbtx, &input, dummy_in_point())
        .await;

    assert!(result.is_ok());
}

#[test_log::test(tokio::test)]
async fn test_arbiter_ruling_after_resolve_by_rejected() {
    let escrow = make_escrow();
    let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
    let funder_kp = make_keypair();
    let recipient_kp = make_keypair();
    let arbiter_kp = make_keypair();
    let fee_kp = make_keypair();
    let mut contract = make_contract(
        &funder_kp,
        &recipient_kp,
        &arbiter_kp,
        &fee_kp,
        Amount::from_sats(1000),
        Amount::from_sats(20),
        1_000,
        3_600,
        FallbackPolicy::Refund,
    );
    contract.status = EscrowStatus::Disputed {
        resolve_by: 5_000,
        swapped: false,
    };

    let mut dbtx = db.begin_transaction_nc().await;
    let mut module_dbtx = dbtx.to_ref_with_prefix_module_id(42).0.into_nc();
    module_dbtx
        .insert_entry(&EscrowContractKey(contract.escrow_id), &contract)
        .await;
    // one second after resolve_by
    module_dbtx
        .insert_entry(&UnixTimeVoteKey(PeerId::from(0u16)), &5_001)
        .await;

    let input = EscrowInput::new_v0(
        contract.escrow_id,
        Resolution::ArbiterOutcome {
            arbiter_signature: sign_arbiter(&arbiter_kp, &contract, Outcome::Refund),
            outcome: Outcome::Refund,
            submitter_pubkey: funder_kp.public_key(),
        },
    );
    let result = escrow
        .process_input(&mut module_dbtx, &input, dummy_in_point())
        .await;

    assert_matches!(result, Err(EscrowInputError::ResolutionDeadlinePassed));
}

#[test_log::test(tokio::test)]
async fn test_arbiter_wrong_signature_rejected() {
    let escrow = make_escrow();
    let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
    let funder_kp = make_keypair();
    let recipient_kp = make_keypair();
    let arbiter_kp = make_keypair();
    let fee_kp = make_keypair();
    let mut contract = make_contract(
        &funder_kp,
        &recipient_kp,
        &arbiter_kp,
        &fee_kp,
        Amount::from_sats(1000),
        Amount::from_sats(20),
        1_000,
        3_600,
        FallbackPolicy::Refund,
    );
    contract.status = EscrowStatus::Disputed {
        resolve_by: 5_000,
        swapped: false,
    };

    let mut dbtx = db.begin_transaction_nc().await;
    let mut module_dbtx = dbtx.to_ref_with_prefix_module_id(42).0.into_nc();
    module_dbtx
        .insert_entry(&EscrowContractKey(contract.escrow_id), &contract)
        .await;
    module_dbtx
        .insert_entry(&UnixTimeVoteKey(PeerId::from(0u16)), &4_000)
        .await;

    // funder signing instead of the arbiter
    let input = EscrowInput::new_v0(
        contract.escrow_id,
        Resolution::ArbiterOutcome {
            arbiter_signature: sign_arbiter(&funder_kp, &contract, Outcome::Refund),
            outcome: Outcome::Refund,
            submitter_pubkey: funder_kp.public_key(),
        },
    );
    let result = escrow
        .process_input(&mut module_dbtx, &input, dummy_in_point())
        .await;

    assert_matches!(result, Err(EscrowInputError::InvalidSignature));

    // nothing was written
    let stored = module_dbtx
        .get_value(&EscrowContractKey(contract.escrow_id))
        .await
        .unwrap();
    assert_eq!(
        stored.status,
        EscrowStatus::Disputed {
            resolve_by: 5_000,
            swapped: false
        }
    );
    let pool = module_dbtx
        .get_value(&ClaimPoolKey(contract.escrow_id))
        .await;
    assert!(pool.is_none());
}

#[test_log::test(tokio::test)]
async fn test_arbiter_outcome_mismatch_rejected() {
    // Arbiter signs Release but the input declares Refund
    let escrow = make_escrow();
    let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
    let funder_kp = make_keypair();
    let recipient_kp = make_keypair();
    let arbiter_kp = make_keypair();
    let fee_kp = make_keypair();
    let mut contract = make_contract(
        &funder_kp,
        &recipient_kp,
        &arbiter_kp,
        &fee_kp,
        Amount::from_sats(1000),
        Amount::from_sats(20),
        1_000,
        3_600,
        FallbackPolicy::Refund,
    );
    contract.status = EscrowStatus::Disputed {
        resolve_by: 5_000,
        swapped: false,
    };

    let mut dbtx = db.begin_transaction_nc().await;
    let mut module_dbtx = dbtx.to_ref_with_prefix_module_id(42).0.into_nc();
    module_dbtx
        .insert_entry(&EscrowContractKey(contract.escrow_id), &contract)
        .await;
    module_dbtx
        .insert_entry(&UnixTimeVoteKey(PeerId::from(0u16)), &4_000)
        .await;

    let input = EscrowInput::new_v0(
        contract.escrow_id,
        Resolution::ArbiterOutcome {
            arbiter_signature: sign_arbiter(&arbiter_kp, &contract, Outcome::Release),
            outcome: Outcome::Refund,
            submitter_pubkey: funder_kp.public_key(),
        },
    );
    let result = escrow
        .process_input(&mut module_dbtx, &input, dummy_in_point())
        .await;

    assert_matches!(result, Err(EscrowInputError::InvalidSignature));
}

#[test_log::test(tokio::test)]
async fn test_arbiter_ruling_on_active_contract_rejected() {
    let escrow = make_escrow();
    let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
    let funder_kp = make_keypair();
    let recipient_kp = make_keypair();
    let arbiter_kp = make_keypair();
    let fee_kp = make_keypair();

    // the arbiter was never engaged
    let contract = make_contract(
        &funder_kp,
        &recipient_kp,
        &arbiter_kp,
        &fee_kp,
        Amount::from_sats(1000),
        Amount::from_sats(20),
        1_000,
        3_600,
        FallbackPolicy::Refund,
    );

    let mut dbtx = db.begin_transaction_nc().await;
    let mut module_dbtx = dbtx.to_ref_with_prefix_module_id(42).0.into_nc();
    module_dbtx
        .insert_entry(&EscrowContractKey(contract.escrow_id), &contract)
        .await;
    module_dbtx
        .insert_entry(&UnixTimeVoteKey(PeerId::from(0u16)), &2_000)
        .await;

    let input = EscrowInput::new_v0(
        contract.escrow_id,
        Resolution::ArbiterOutcome {
            arbiter_signature: sign_arbiter(&arbiter_kp, &contract, Outcome::Refund),
            outcome: Outcome::Refund,
            submitter_pubkey: funder_kp.public_key(),
        },
    );
    let result = escrow
        .process_input(&mut module_dbtx, &input, dummy_in_point())
        .await;

    assert_matches!(result, Err(EscrowInputError::ContractNotDisputed));
}

#[test_log::test(tokio::test)]
async fn test_arbiter_ruling_twice_rejected() {
    let escrow = make_escrow();
    let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
    let funder_kp = make_keypair();
    let recipient_kp = make_keypair();
    let arbiter_kp = make_keypair();
    let fee_kp = make_keypair();

    let mut contract = make_contract(
        &funder_kp,
        &recipient_kp,
        &arbiter_kp,
        &fee_kp,
        Amount::from_sats(1000),
        Amount::from_sats(20),
        1_000,
        3_600,
        FallbackPolicy::Refund,
    );
    contract.status = EscrowStatus::Disputed {
        resolve_by: 5_000,
        swapped: false,
    };

    let mut dbtx = db.begin_transaction_nc().await;
    let mut module_dbtx = dbtx.to_ref_with_prefix_module_id(42).0.into_nc();
    module_dbtx
        .insert_entry(&EscrowContractKey(contract.escrow_id), &contract)
        .await;
    module_dbtx
        .insert_entry(&UnixTimeVoteKey(PeerId::from(0u16)), &4_000)
        .await;

    let input = EscrowInput::new_v0(
        contract.escrow_id,
        Resolution::ArbiterOutcome {
            arbiter_signature: sign_arbiter(&arbiter_kp, &contract, Outcome::Release),
            outcome: Outcome::Release,
            submitter_pubkey: recipient_kp.public_key(),
        },
    );
    escrow
        .process_input(&mut module_dbtx, &input, dummy_in_point())
        .await
        .unwrap();
    // replaying the same signed ruling must not pay out twice
    let second = escrow
        .process_input(&mut module_dbtx, &input, dummy_in_point())
        .await;

    assert_matches!(second, Err(EscrowInputError::ContractAlreadyResolved));

    let pool = module_dbtx
        .get_value(&ClaimPoolKey(contract.escrow_id))
        .await
        .unwrap();
    assert_eq!(pool.claimer.len(), 2);
}

#[test_log::test(tokio::test)]
async fn test_arbiter_ruling_by_stranger_rejected() {
    let escrow = make_escrow();
    let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
    let funder_kp = make_keypair();
    let recipient_kp = make_keypair();
    let arbiter_kp = make_keypair();
    let fee_kp = make_keypair();
    let stranger_kp = make_keypair();
    let mut contract = make_contract(
        &funder_kp,
        &recipient_kp,
        &arbiter_kp,
        &fee_kp,
        Amount::from_sats(1000),
        Amount::from_sats(20),
        1_000,
        3_600,
        FallbackPolicy::Refund,
    );
    contract.status = EscrowStatus::Disputed {
        resolve_by: 5_000,
        swapped: false,
    };

    let mut dbtx = db.begin_transaction_nc().await;
    let mut module_dbtx = dbtx.to_ref_with_prefix_module_id(42).0.into_nc();
    module_dbtx
        .insert_entry(&EscrowContractKey(contract.escrow_id), &contract)
        .await;
    module_dbtx
        .insert_entry(&UnixTimeVoteKey(PeerId::from(0u16)), &4_000)
        .await;

    // the signature is valid, but the submitter is not part of the contract
    let input = EscrowInput::new_v0(
        contract.escrow_id,
        Resolution::ArbiterOutcome {
            arbiter_signature: sign_arbiter(&arbiter_kp, &contract, Outcome::Refund),
            outcome: Outcome::Refund,
            submitter_pubkey: stranger_kp.public_key(),
        },
    );
    let result = escrow
        .process_input(&mut module_dbtx, &input, dummy_in_point())
        .await;

    assert_matches!(result, Err(EscrowInputError::NotAParticipant));
}

#[test_log::test(tokio::test)]
async fn test_arbiter_ruling_with_existing_claim_pool_rejected() {
    let escrow = make_escrow();
    let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
    let funder_kp = make_keypair();
    let recipient_kp = make_keypair();
    let arbiter_kp = make_keypair();
    let fee_kp = make_keypair();
    let mut contract = make_contract(
        &funder_kp,
        &recipient_kp,
        &arbiter_kp,
        &fee_kp,
        Amount::from_sats(1000),
        Amount::from_sats(20),
        1_000,
        3_600,
        FallbackPolicy::Refund,
    );
    contract.status = EscrowStatus::Disputed {
        resolve_by: 5_000,
        swapped: false,
    };
    // a pool that should never exist for an unresolved contract
    let existing_pool = ClaimPool {
        escrow_id: contract.escrow_id,
        claimer: vec![(funder_kp.public_key(), Amount::from_sats(1))],
    };

    let mut dbtx = db.begin_transaction_nc().await;
    let mut module_dbtx = dbtx.to_ref_with_prefix_module_id(42).0.into_nc();
    module_dbtx
        .insert_entry(&EscrowContractKey(contract.escrow_id), &contract)
        .await;
    module_dbtx
        .insert_entry(&ClaimPoolKey(contract.escrow_id), &existing_pool)
        .await;
    module_dbtx
        .insert_entry(&UnixTimeVoteKey(PeerId::from(0u16)), &4_000)
        .await;

    let input = EscrowInput::new_v0(
        contract.escrow_id,
        Resolution::ArbiterOutcome {
            arbiter_signature: sign_arbiter(&arbiter_kp, &contract, Outcome::Refund),
            outcome: Outcome::Refund,
            submitter_pubkey: funder_kp.public_key(),
        },
    );
    let result = escrow
        .process_input(&mut module_dbtx, &input, dummy_in_point())
        .await;

    assert_matches!(result, Err(EscrowInputError::InvalidStateTransition));

    // neither the contract nor the existing pool was touched
    let stored = module_dbtx
        .get_value(&EscrowContractKey(contract.escrow_id))
        .await
        .unwrap();
    assert_eq!(
        stored.status,
        EscrowStatus::Disputed {
            resolve_by: 5_000,
            swapped: false
        }
    );
    let pool = module_dbtx
        .get_value(&ClaimPoolKey(contract.escrow_id))
        .await
        .unwrap();
    assert_eq!(pool, existing_pool);
}

#[test_log::test(tokio::test)]
async fn test_fallback_refund_valid() {
    let escrow = make_escrow();
    let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
    let funder_kp = make_keypair();
    let recipient_kp = make_keypair();
    let arbiter_kp = make_keypair();
    let fee_kp = make_keypair();
    let mut contract = make_contract(
        &funder_kp,
        &recipient_kp,
        &arbiter_kp,
        &fee_kp,
        Amount::from_sats(1000),
        Amount::from_sats(20),
        1_000,
        3_600,
        FallbackPolicy::Refund,
    );
    contract.status = EscrowStatus::Disputed {
        resolve_by: 5_000,
        swapped: false,
    };

    let mut dbtx = db.begin_transaction_nc().await;
    let mut module_dbtx = dbtx.to_ref_with_prefix_module_id(42).0.into_nc();
    module_dbtx
        .insert_entry(&EscrowContractKey(contract.escrow_id), &contract)
        .await;
    module_dbtx
        .insert_entry(&UnixTimeVoteKey(PeerId::from(0u16)), &5_001)
        .await;

    let input = EscrowInput::new_v0(
        contract.escrow_id,
        Resolution::ResolveFallbackPolicy {
            claimer_pubkey: recipient_kp.public_key(),
            fallback: FallbackPolicy::Refund,
        },
    );
    let meta = escrow
        .process_input(&mut module_dbtx, &input, dummy_in_point())
        .await
        .unwrap();

    assert_eq!(meta.pub_key, recipient_kp.public_key());
    assert_eq!(meta.amount.amounts, Amounts::ZERO);

    let stored = module_dbtx
        .get_value(&EscrowContractKey(contract.escrow_id))
        .await
        .unwrap();
    assert_eq!(stored.status, EscrowStatus::Refunded);

    // the arbiter did no work, so the funder gets the whole amount
    let pool = module_dbtx
        .get_value(&ClaimPoolKey(contract.escrow_id))
        .await
        .unwrap();
    assert_eq!(
        pool.claimer,
        vec![(funder_kp.public_key(), Amount::from_sats(1000))]
    );
}

#[test_log::test(tokio::test)]
async fn test_fallback_before_resolve_by_rejected() {
    let escrow = make_escrow();
    let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
    let funder_kp = make_keypair();
    let recipient_kp = make_keypair();
    let arbiter_kp = make_keypair();
    let fee_kp = make_keypair();
    let mut contract = make_contract(
        &funder_kp,
        &recipient_kp,
        &arbiter_kp,
        &fee_kp,
        Amount::from_sats(1000),
        Amount::from_sats(20),
        1_000,
        3_600,
        FallbackPolicy::Refund,
    );
    contract.status = EscrowStatus::Disputed {
        resolve_by: 5_000,
        swapped: false,
    };

    let mut dbtx = db.begin_transaction_nc().await;
    let mut module_dbtx = dbtx.to_ref_with_prefix_module_id(42).0.into_nc();
    module_dbtx
        .insert_entry(&EscrowContractKey(contract.escrow_id), &contract)
        .await;
    // the arbiter can still rule at exactly resolve_by
    module_dbtx
        .insert_entry(&UnixTimeVoteKey(PeerId::from(0u16)), &5_000)
        .await;

    let input = EscrowInput::new_v0(
        contract.escrow_id,
        Resolution::ResolveFallbackPolicy {
            claimer_pubkey: funder_kp.public_key(),
            fallback: FallbackPolicy::Refund,
        },
    );
    let result = escrow
        .process_input(&mut module_dbtx, &input, dummy_in_point())
        .await;

    assert_matches!(result, Err(EscrowInputError::FallbackNotAvailable));
}

#[test_log::test(tokio::test)]
async fn test_fallback_by_arbiter_rejected() {
    let escrow = make_escrow();
    let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
    let funder_kp = make_keypair();
    let recipient_kp = make_keypair();
    let arbiter_kp = make_keypair();
    let fee_kp = make_keypair();
    let mut contract = make_contract(
        &funder_kp,
        &recipient_kp,
        &arbiter_kp,
        &fee_kp,
        Amount::from_sats(1000),
        Amount::from_sats(20),
        1_000,
        3_600,
        FallbackPolicy::Refund,
    );
    contract.status = EscrowStatus::Disputed {
        resolve_by: 5_000,
        swapped: false,
    };

    let mut dbtx = db.begin_transaction_nc().await;
    let mut module_dbtx = dbtx.to_ref_with_prefix_module_id(42).0.into_nc();
    module_dbtx
        .insert_entry(&EscrowContractKey(contract.escrow_id), &contract)
        .await;
    module_dbtx
        .insert_entry(&UnixTimeVoteKey(PeerId::from(0u16)), &5_001)
        .await;

    let input = EscrowInput::new_v0(
        contract.escrow_id,
        Resolution::ResolveFallbackPolicy {
            claimer_pubkey: arbiter_kp.public_key(),
            fallback: FallbackPolicy::Refund,
        },
    );
    let result = escrow
        .process_input(&mut module_dbtx, &input, dummy_in_point())
        .await;

    assert_matches!(result, Err(EscrowInputError::NotAParticipant));
}

#[test_log::test(tokio::test)]
async fn test_fallback_on_active_contract_rejected() {
    let escrow = make_escrow();
    let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
    let funder_kp = make_keypair();
    let recipient_kp = make_keypair();
    let arbiter_kp = make_keypair();
    let fee_kp = make_keypair();
    let contract = make_contract(
        &funder_kp,
        &recipient_kp,
        &arbiter_kp,
        &fee_kp,
        Amount::from_sats(1000),
        Amount::from_sats(20),
        1_000,
        3_600,
        FallbackPolicy::Refund,
    );

    let mut dbtx = db.begin_transaction_nc().await;
    let mut module_dbtx = dbtx.to_ref_with_prefix_module_id(42).0.into_nc();
    module_dbtx
        .insert_entry(&EscrowContractKey(contract.escrow_id), &contract)
        .await;
    module_dbtx
        .insert_entry(&UnixTimeVoteKey(PeerId::from(0u16)), &9_000)
        .await;

    let input = EscrowInput::new_v0(
        contract.escrow_id,
        Resolution::ResolveFallbackPolicy {
            claimer_pubkey: funder_kp.public_key(),
            fallback: FallbackPolicy::Refund,
        },
    );
    let result = escrow
        .process_input(&mut module_dbtx, &input, dummy_in_point())
        .await;

    assert_matches!(result, Err(EscrowInputError::ContractNotDisputed));
}

#[test_log::test(tokio::test)]
async fn test_fallback_ignores_policy_sent_in_input() {
    let escrow = make_escrow();
    let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
    let funder_kp = make_keypair();
    let recipient_kp = make_keypair();
    let arbiter_kp = make_keypair();
    let fee_kp = make_keypair();

    // the contract says Refund
    let mut contract = make_contract(
        &funder_kp,
        &recipient_kp,
        &arbiter_kp,
        &fee_kp,
        Amount::from_sats(1000),
        Amount::from_sats(20),
        1_000,
        3_600,
        FallbackPolicy::Refund,
    );
    contract.status = EscrowStatus::Disputed {
        resolve_by: 5_000,
        swapped: false,
    };

    let mut dbtx = db.begin_transaction_nc().await;
    let mut module_dbtx = dbtx.to_ref_with_prefix_module_id(42).0.into_nc();
    module_dbtx
        .insert_entry(&EscrowContractKey(contract.escrow_id), &contract)
        .await;
    module_dbtx
        .insert_entry(&UnixTimeVoteKey(PeerId::from(0u16)), &5_001)
        .await;

    // the input claims an even split
    let input = EscrowInput::new_v0(
        contract.escrow_id,
        Resolution::ResolveFallbackPolicy {
            claimer_pubkey: funder_kp.public_key(),
            fallback: FallbackPolicy::Split {
                funder_split_bps: 5_000,
                recipient_split_bps: 5_000,
            },
        },
    );
    escrow
        .process_input(&mut module_dbtx, &input, dummy_in_point())
        .await
        .unwrap();

    let stored = module_dbtx
        .get_value(&EscrowContractKey(contract.escrow_id))
        .await
        .unwrap();
    assert_eq!(stored.status, EscrowStatus::Refunded);
    let pool = module_dbtx
        .get_value(&ClaimPoolKey(contract.escrow_id))
        .await
        .unwrap();
    assert_eq!(
        pool.claimer,
        vec![(funder_kp.public_key(), Amount::from_sats(1000))]
    );
}

#[test_log::test(tokio::test)]
async fn test_fallback_swaps_arbiter() {
    let escrow = make_escrow();
    let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
    let funder_kp = make_keypair();
    let recipient_kp = make_keypair();
    let arbiter_kp = make_keypair();
    let fee_kp = make_keypair();
    let swap_arbiter_kp = make_keypair();
    let swap_fee_kp = make_keypair();
    let mut contract = make_contract(
        &funder_kp,
        &recipient_kp,
        &arbiter_kp,
        &fee_kp,
        Amount::from_sats(1000),
        Amount::from_sats(20),
        1_000,
        3_600,
        FallbackPolicy::SwapArbiter {
            arbiter_key: swap_arbiter_kp.public_key(),
            arbiter_fee_key: vec![swap_fee_kp.public_key()],
            arbiter_fee: Amount::from_sats(30),
        },
    );
    contract.status = EscrowStatus::Disputed {
        resolve_by: 5_000,
        swapped: false,
    };

    let mut dbtx = db.begin_transaction_nc().await;
    let mut module_dbtx = dbtx.to_ref_with_prefix_module_id(42).0.into_nc();
    module_dbtx
        .insert_entry(&EscrowContractKey(contract.escrow_id), &contract)
        .await;
    module_dbtx
        .insert_entry(&UnixTimeVoteKey(PeerId::from(0u16)), &5_001)
        .await;

    let input = EscrowInput::new_v0(
        contract.escrow_id,
        Resolution::ResolveFallbackPolicy {
            claimer_pubkey: funder_kp.public_key(),
            fallback: contract.default_fallback.clone(),
        },
    );
    let meta = escrow
        .process_input(&mut module_dbtx, &input, dummy_in_point())
        .await
        .unwrap();

    // no funds move, the replacement arbiter gets a fresh window
    assert_eq!(meta.pub_key, funder_kp.public_key());
    assert_eq!(meta.amount.amounts, Amounts::ZERO);

    let stored = module_dbtx
        .get_value(&EscrowContractKey(contract.escrow_id))
        .await
        .unwrap();
    assert_eq!(
        stored.status,
        EscrowStatus::Disputed {
            resolve_by: 8_601,
            swapped: true
        }
    );
    let pool = module_dbtx
        .get_value(&ClaimPoolKey(contract.escrow_id))
        .await;
    assert!(pool.is_none());
}

#[test_log::test(tokio::test)]
async fn test_swapped_arbiter_replaces_old_arbiter() {
    let escrow = make_escrow();
    let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
    let funder_kp = make_keypair();
    let recipient_kp = make_keypair();
    let arbiter_kp = make_keypair();
    let fee_kp = make_keypair();
    let swap_arbiter_kp = make_keypair();
    let swap_fee_kp = make_keypair();
    let mut contract = make_contract(
        &funder_kp,
        &recipient_kp,
        &arbiter_kp,
        &fee_kp,
        Amount::from_sats(1000),
        Amount::from_sats(20),
        1_000,
        3_600,
        FallbackPolicy::SwapArbiter {
            arbiter_key: swap_arbiter_kp.public_key(),
            arbiter_fee_key: vec![swap_fee_kp.public_key()],
            arbiter_fee: Amount::from_sats(30),
        },
    );
    contract.status = EscrowStatus::Disputed {
        resolve_by: 5_000,
        swapped: false,
    };

    let mut dbtx = db.begin_transaction_nc().await;
    let mut module_dbtx = dbtx.to_ref_with_prefix_module_id(42).0.into_nc();
    module_dbtx
        .insert_entry(&EscrowContractKey(contract.escrow_id), &contract)
        .await;
    module_dbtx
        .insert_entry(&UnixTimeVoteKey(PeerId::from(0u16)), &5_001)
        .await;

    // first arbiter missed the deadline: swap
    let swap_input = EscrowInput::new_v0(
        contract.escrow_id,
        Resolution::ResolveFallbackPolicy {
            claimer_pubkey: funder_kp.public_key(),
            fallback: contract.default_fallback.clone(),
        },
    );
    escrow
        .process_input(&mut module_dbtx, &swap_input, dummy_in_point())
        .await
        .unwrap();

    // the old arbiter's ruling no longer works
    let old_input = EscrowInput::new_v0(
        contract.escrow_id,
        Resolution::ArbiterOutcome {
            arbiter_signature: sign_arbiter(&arbiter_kp, &contract, Outcome::Release),
            outcome: Outcome::Release,
            submitter_pubkey: recipient_kp.public_key(),
        },
    );
    let old_result = escrow
        .process_input(&mut module_dbtx, &old_input, dummy_in_point())
        .await;
    assert_matches!(old_result, Err(EscrowInputError::InvalidSignature));

    // the replacement arbiter's ruling works, with its own fee and fee key
    let new_input = EscrowInput::new_v0(
        contract.escrow_id,
        Resolution::ArbiterOutcome {
            arbiter_signature: sign_arbiter(&swap_arbiter_kp, &contract, Outcome::Release),
            outcome: Outcome::Release,
            submitter_pubkey: recipient_kp.public_key(),
        },
    );
    escrow
        .process_input(&mut module_dbtx, &new_input, dummy_in_point())
        .await
        .unwrap();

    let stored = module_dbtx
        .get_value(&EscrowContractKey(contract.escrow_id))
        .await
        .unwrap();
    assert_eq!(stored.status, EscrowStatus::Released);
    let pool = module_dbtx
        .get_value(&ClaimPoolKey(contract.escrow_id))
        .await
        .unwrap();
    assert_eq!(
        pool.claimer,
        vec![
            (recipient_kp.public_key(), Amount::from_sats(970)),
            (swap_fee_kp.public_key(), Amount::from_sats(30)),
        ]
    );
}

#[test_log::test(tokio::test)]
async fn test_second_fallback_after_swap_refunds() {
    let escrow = make_escrow();
    let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
    let funder_kp = make_keypair();
    let recipient_kp = make_keypair();
    let arbiter_kp = make_keypair();
    let fee_kp = make_keypair();
    let swap_arbiter_kp = make_keypair();
    let swap_fee_kp = make_keypair();
    let mut contract = make_contract(
        &funder_kp,
        &recipient_kp,
        &arbiter_kp,
        &fee_kp,
        Amount::from_sats(1000),
        Amount::from_sats(20),
        1_000,
        3_600,
        FallbackPolicy::SwapArbiter {
            arbiter_key: swap_arbiter_kp.public_key(),
            arbiter_fee_key: vec![swap_fee_kp.public_key()],
            arbiter_fee: Amount::from_sats(30),
        },
    );
    contract.status = EscrowStatus::Disputed {
        resolve_by: 5_000,
        swapped: false,
    };

    let mut dbtx = db.begin_transaction_nc().await;
    let mut module_dbtx = dbtx.to_ref_with_prefix_module_id(42).0.into_nc();
    module_dbtx
        .insert_entry(&EscrowContractKey(contract.escrow_id), &contract)
        .await;
    module_dbtx
        .insert_entry(&UnixTimeVoteKey(PeerId::from(0u16)), &5_001)
        .await;

    let input = EscrowInput::new_v0(
        contract.escrow_id,
        Resolution::ResolveFallbackPolicy {
            claimer_pubkey: funder_kp.public_key(),
            fallback: contract.default_fallback.clone(),
        },
    );
    // first trigger swaps the arbiter, the new window ends at 8_601
    escrow
        .process_input(&mut module_dbtx, &input, dummy_in_point())
        .await
        .unwrap();

    // the replacement arbiter is silent too
    module_dbtx
        .insert_entry(&UnixTimeVoteKey(PeerId::from(0u16)), &8_602)
        .await;
    escrow
        .process_input(&mut module_dbtx, &input, dummy_in_point())
        .await
        .unwrap();

    // no second swap: the funder is refunded the whole amount, no fee
    let stored = module_dbtx
        .get_value(&EscrowContractKey(contract.escrow_id))
        .await
        .unwrap();
    assert_eq!(stored.status, EscrowStatus::Refunded);
    let pool = module_dbtx
        .get_value(&ClaimPoolKey(contract.escrow_id))
        .await
        .unwrap();
    assert_eq!(
        pool.claimer,
        vec![(funder_kp.public_key(), Amount::from_sats(1000))]
    );
}

#[test_log::test(tokio::test)]
async fn test_claim_payout_valid() {
    let escrow = make_escrow();
    let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
    let funder_kp = make_keypair();
    let recipient_kp = make_keypair();
    let arbiter_kp = make_keypair();
    let fee_kp = make_keypair();
    let mut contract = make_contract(
        &funder_kp,
        &recipient_kp,
        &arbiter_kp,
        &fee_kp,
        Amount::from_sats(1000),
        Amount::from_sats(20),
        1_000,
        3_600,
        FallbackPolicy::Refund,
    );
    contract.status = EscrowStatus::Released;
    let pool = ClaimPool {
        escrow_id: contract.escrow_id,
        claimer: vec![
            (recipient_kp.public_key(), Amount::from_sats(980)),
            (fee_kp.public_key(), Amount::from_sats(20)),
        ],
    };

    let mut dbtx = db.begin_transaction_nc().await;
    let mut module_dbtx = dbtx.to_ref_with_prefix_module_id(42).0.into_nc();
    module_dbtx
        .insert_entry(&EscrowContractKey(contract.escrow_id), &contract)
        .await;
    module_dbtx
        .insert_entry(&ClaimPoolKey(contract.escrow_id), &pool)
        .await;

    // the recipient claims first
    let recipient_input = EscrowInput::new_v0(
        contract.escrow_id,
        Resolution::ClaimPayout {
            claimer_pubkey: recipient_kp.public_key(),
        },
    );
    let meta = escrow
        .process_input(&mut module_dbtx, &recipient_input, dummy_in_point())
        .await
        .unwrap();

    assert_eq!(meta.pub_key, recipient_kp.public_key());
    assert_eq!(
        meta.amount.amounts,
        Amounts::new_bitcoin(Amount::from_sats(980))
    );
    let remaining = module_dbtx
        .get_value(&ClaimPoolKey(contract.escrow_id))
        .await
        .unwrap();
    assert_eq!(
        remaining.claimer,
        vec![(fee_kp.public_key(), Amount::from_sats(20))]
    );

    // the fee key claims the last entry, which removes the pool
    let fee_input = EscrowInput::new_v0(
        contract.escrow_id,
        Resolution::ClaimPayout {
            claimer_pubkey: fee_kp.public_key(),
        },
    );
    let meta = escrow
        .process_input(&mut module_dbtx, &fee_input, dummy_in_point())
        .await
        .unwrap();

    assert_eq!(meta.pub_key, fee_kp.public_key());
    assert_eq!(
        meta.amount.amounts,
        Amounts::new_bitcoin(Amount::from_sats(20))
    );
    let remaining = module_dbtx
        .get_value(&ClaimPoolKey(contract.escrow_id))
        .await;
    assert!(remaining.is_none());
}

#[test_log::test(tokio::test)]
async fn test_claim_payout_twice_rejected() {
    let escrow = make_escrow();
    let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
    let funder_kp = make_keypair();
    let recipient_kp = make_keypair();
    let arbiter_kp = make_keypair();
    let fee_kp = make_keypair();
    let mut contract = make_contract(
        &funder_kp,
        &recipient_kp,
        &arbiter_kp,
        &fee_kp,
        Amount::from_sats(1000),
        Amount::from_sats(20),
        1_000,
        3_600,
        FallbackPolicy::Refund,
    );
    contract.status = EscrowStatus::Released;
    let pool = ClaimPool {
        escrow_id: contract.escrow_id,
        claimer: vec![
            (recipient_kp.public_key(), Amount::from_sats(980)),
            (fee_kp.public_key(), Amount::from_sats(20)),
        ],
    };

    let mut dbtx = db.begin_transaction_nc().await;
    let mut module_dbtx = dbtx.to_ref_with_prefix_module_id(42).0.into_nc();
    module_dbtx
        .insert_entry(&EscrowContractKey(contract.escrow_id), &contract)
        .await;
    module_dbtx
        .insert_entry(&ClaimPoolKey(contract.escrow_id), &pool)
        .await;

    let input = EscrowInput::new_v0(
        contract.escrow_id,
        Resolution::ClaimPayout {
            claimer_pubkey: recipient_kp.public_key(),
        },
    );
    escrow
        .process_input(&mut module_dbtx, &input, dummy_in_point())
        .await
        .unwrap();

    // the fee entry keeps the pool alive, the recipient's own entry is gone
    let second = escrow
        .process_input(&mut module_dbtx, &input, dummy_in_point())
        .await;

    assert_matches!(second, Err(EscrowInputError::NoPendingClaim));
}

#[test_log::test(tokio::test)]
async fn test_claim_payout_by_party_not_in_pool_rejected() {
    let escrow = make_escrow();
    let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
    let funder_kp = make_keypair();
    let recipient_kp = make_keypair();
    let arbiter_kp = make_keypair();
    let fee_kp = make_keypair();
    let mut contract = make_contract(
        &funder_kp,
        &recipient_kp,
        &arbiter_kp,
        &fee_kp,
        Amount::from_sats(1000),
        Amount::from_sats(20),
        1_000,
        3_600,
        FallbackPolicy::Refund,
    );
    contract.status = EscrowStatus::Released;
    // the recipient won, the funder has nothing to claim
    let pool = ClaimPool {
        escrow_id: contract.escrow_id,
        claimer: vec![
            (recipient_kp.public_key(), Amount::from_sats(980)),
            (fee_kp.public_key(), Amount::from_sats(20)),
        ],
    };

    let mut dbtx = db.begin_transaction_nc().await;
    let mut module_dbtx = dbtx.to_ref_with_prefix_module_id(42).0.into_nc();
    module_dbtx
        .insert_entry(&EscrowContractKey(contract.escrow_id), &contract)
        .await;
    module_dbtx
        .insert_entry(&ClaimPoolKey(contract.escrow_id), &pool)
        .await;

    let input = EscrowInput::new_v0(
        contract.escrow_id,
        Resolution::ClaimPayout {
            claimer_pubkey: funder_kp.public_key(),
        },
    );
    let result = escrow
        .process_input(&mut module_dbtx, &input, dummy_in_point())
        .await;

    assert_matches!(result, Err(EscrowInputError::NoPendingClaim));

    // the pool is unchanged
    let stored_pool = module_dbtx
        .get_value(&ClaimPoolKey(contract.escrow_id))
        .await
        .unwrap();
    assert_eq!(stored_pool, pool);
}

#[test_log::test(tokio::test)]
async fn test_claim_payout_by_third_party_rejected() {
    let escrow = make_escrow();
    let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
    let funder_kp = make_keypair();
    let recipient_kp = make_keypair();
    let arbiter_kp = make_keypair();
    let fee_kp = make_keypair();
    let stranger_kp = make_keypair();
    let mut contract = make_contract(
        &funder_kp,
        &recipient_kp,
        &arbiter_kp,
        &fee_kp,
        Amount::from_sats(1000),
        Amount::from_sats(20),
        1_000,
        3_600,
        FallbackPolicy::Refund,
    );
    contract.status = EscrowStatus::Released;
    let pool = ClaimPool {
        escrow_id: contract.escrow_id,
        claimer: vec![(recipient_kp.public_key(), Amount::from_sats(1000))],
    };

    let mut dbtx = db.begin_transaction_nc().await;
    let mut module_dbtx = dbtx.to_ref_with_prefix_module_id(42).0.into_nc();
    module_dbtx
        .insert_entry(&EscrowContractKey(contract.escrow_id), &contract)
        .await;
    module_dbtx
        .insert_entry(&ClaimPoolKey(contract.escrow_id), &pool)
        .await;

    let input = EscrowInput::new_v0(
        contract.escrow_id,
        Resolution::ClaimPayout {
            claimer_pubkey: stranger_kp.public_key(),
        },
    );
    let result = escrow
        .process_input(&mut module_dbtx, &input, dummy_in_point())
        .await;

    assert_matches!(result, Err(EscrowInputError::NotAParticipant));
}

#[test_log::test(tokio::test)]
async fn test_claim_payout_without_pool_rejected() {
    let escrow = make_escrow();
    let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
    let funder_kp = make_keypair();
    let recipient_kp = make_keypair();
    let arbiter_kp = make_keypair();
    let fee_kp = make_keypair();
    // still active: nothing has been resolved, so nothing can be claimed
    let contract = make_contract(
        &funder_kp,
        &recipient_kp,
        &arbiter_kp,
        &fee_kp,
        Amount::from_sats(1000),
        Amount::from_sats(20),
        1_000,
        3_600,
        FallbackPolicy::Refund,
    );

    let mut dbtx = db.begin_transaction_nc().await;
    let mut module_dbtx = dbtx.to_ref_with_prefix_module_id(42).0.into_nc();
    module_dbtx
        .insert_entry(&EscrowContractKey(contract.escrow_id), &contract)
        .await;

    let input = EscrowInput::new_v0(
        contract.escrow_id,
        Resolution::ClaimPayout {
            claimer_pubkey: recipient_kp.public_key(),
        },
    );
    let result = escrow
        .process_input(&mut module_dbtx, &input, dummy_in_point())
        .await;

    assert_matches!(result, Err(EscrowInputError::NoPendingClaim));
}

#[test_log::test(tokio::test)]
async fn test_claim_payout_matches_key_by_x_only() {
    let escrow = make_escrow();
    let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
    let funder_kp = make_keypair();
    let recipient_kp = make_keypair();
    let arbiter_kp = make_keypair();
    let fee_kp = make_keypair();
    let mut contract = make_contract(
        &funder_kp,
        &recipient_kp,
        &arbiter_kp,
        &fee_kp,
        Amount::from_sats(1000),
        Amount::from_sats(20),
        1_000,
        3_600,
        FallbackPolicy::Refund,
    );
    contract.status = EscrowStatus::Released;
    let pool = ClaimPool {
        escrow_id: contract.escrow_id,
        claimer: vec![(recipient_kp.public_key(), Amount::from_sats(1000))],
    };

    // the same key with the opposite parity prefix
    let (xonly, parity) = recipient_kp.public_key().x_only_public_key();
    let flipped_parity = match parity {
        Parity::Even => Parity::Odd,
        Parity::Odd => Parity::Even,
    };
    let flipped_key = PublicKey::from_x_only_public_key(xonly, flipped_parity);
    assert_ne!(flipped_key, recipient_kp.public_key());

    let mut dbtx = db.begin_transaction_nc().await;
    let mut module_dbtx = dbtx.to_ref_with_prefix_module_id(42).0.into_nc();
    module_dbtx
        .insert_entry(&EscrowContractKey(contract.escrow_id), &contract)
        .await;
    module_dbtx
        .insert_entry(&ClaimPoolKey(contract.escrow_id), &pool)
        .await;

    let input = EscrowInput::new_v0(
        contract.escrow_id,
        Resolution::ClaimPayout {
            claimer_pubkey: flipped_key,
        },
    );
    let meta = escrow
        .process_input(&mut module_dbtx, &input, dummy_in_point())
        .await
        .unwrap();

    assert_eq!(meta.pub_key, recipient_kp.public_key());
    assert_eq!(
        meta.amount.amounts,
        Amounts::new_bitcoin(Amount::from_sats(1000))
    );
}

#[test_log::test(tokio::test)]
async fn test_full_dispute_flow_to_claims() {
    let escrow = make_escrow();
    let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
    let funder_kp = make_keypair();
    let recipient_kp = make_keypair();
    let arbiter_kp = make_keypair();
    let fee_kp = make_keypair();
    let contract = make_contract(
        &funder_kp,
        &recipient_kp,
        &arbiter_kp,
        &fee_kp,
        Amount::from_sats(1000),
        Amount::from_sats(20),
        1_000,
        3_600,
        FallbackPolicy::Refund,
    );

    let mut dbtx = db.begin_transaction_nc().await;
    let mut module_dbtx = dbtx.to_ref_with_prefix_module_id(42).0.into_nc();
    module_dbtx
        .insert_entry(&EscrowContractKey(contract.escrow_id), &contract)
        .await;

    // the timeout passes and the funder engages the arbiter
    module_dbtx
        .insert_entry(&UnixTimeVoteKey(PeerId::from(0u16)), &2_000)
        .await;
    let msg_bytes = compute_escrow_message(&contract.engage_message());
    let sig = Secp256k1::new().sign_schnorr(&Message::from_digest(msg_bytes), &funder_kp);
    let engage_input = EscrowInput::new_v0(
        contract.escrow_id,
        Resolution::ArbiterEngaged {
            disputant_pubkey: funder_kp.public_key(),
            disputant_signature: sig,
        },
    );
    escrow
        .process_input(&mut module_dbtx, &engage_input, dummy_in_point())
        .await
        .unwrap();
    let stored = module_dbtx
        .get_value(&EscrowContractKey(contract.escrow_id))
        .await
        .unwrap();
    assert_eq!(
        stored.status,
        EscrowStatus::Disputed {
            resolve_by: 5_600,
            swapped: false
        }
    );

    // the arbiter rules for the funder within the window
    module_dbtx
        .insert_entry(&UnixTimeVoteKey(PeerId::from(0u16)), &3_000)
        .await;
    let ruling_input = EscrowInput::new_v0(
        contract.escrow_id,
        Resolution::ArbiterOutcome {
            arbiter_signature: sign_arbiter(&arbiter_kp, &contract, Outcome::Refund),
            outcome: Outcome::Refund,
            submitter_pubkey: funder_kp.public_key(),
        },
    );
    escrow
        .process_input(&mut module_dbtx, &ruling_input, dummy_in_point())
        .await
        .unwrap();

    // a release signature can no longer move the funds
    let release_input = EscrowInput::new_v0(
        contract.escrow_id,
        Resolution::FunderRelease {
            funder_signature: sign_release(&funder_kp, &contract),
        },
    );
    let release_result = escrow
        .process_input(&mut module_dbtx, &release_input, dummy_in_point())
        .await;
    assert_matches!(
        release_result,
        Err(EscrowInputError::ContractAlreadyResolved)
    );

    let funder_claim = EscrowInput::new_v0(
        contract.escrow_id,
        Resolution::ClaimPayout {
            claimer_pubkey: funder_kp.public_key(),
        },
    );
    let meta = escrow
        .process_input(&mut module_dbtx, &funder_claim, dummy_in_point())
        .await
        .unwrap();
    assert_eq!(
        meta.amount.amounts,
        Amounts::new_bitcoin(Amount::from_sats(980))
    );

    let fee_claim = EscrowInput::new_v0(
        contract.escrow_id,
        Resolution::ClaimPayout {
            claimer_pubkey: fee_kp.public_key(),
        },
    );
    let meta = escrow
        .process_input(&mut module_dbtx, &fee_claim, dummy_in_point())
        .await
        .unwrap();
    assert_eq!(
        meta.amount.amounts,
        Amounts::new_bitcoin(Amount::from_sats(20))
    );

    let pool = module_dbtx
        .get_value(&ClaimPoolKey(contract.escrow_id))
        .await;
    assert!(pool.is_none());
    let stored = module_dbtx
        .get_value(&EscrowContractKey(contract.escrow_id))
        .await
        .unwrap();
    assert_eq!(stored.status, EscrowStatus::Refunded);
}

#[test_log::test(tokio::test)]
async fn test_process_consensus_item_vote_must_increase() {
    let escrow = make_escrow();
    let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
    let peer = PeerId::from(0u16);

    let mut dbtx = db.begin_transaction_nc().await;
    let mut module_dbtx = dbtx.to_ref_with_prefix_module_id(42).0.into_nc();

    let first = escrow
        .process_consensus_item(
            &mut module_dbtx,
            EscrowConsensusItem::UnixTimeVote(100),
            peer,
        )
        .await;
    assert!(first.is_ok());
    assert_eq!(
        module_dbtx.get_value(&UnixTimeVoteKey(peer)).await,
        Some(100)
    );

    // the same vote again is redundant
    let same = escrow
        .process_consensus_item(
            &mut module_dbtx,
            EscrowConsensusItem::UnixTimeVote(100),
            peer,
        )
        .await;
    assert!(same.is_err());

    // time never goes backwards
    let lower = escrow
        .process_consensus_item(
            &mut module_dbtx,
            EscrowConsensusItem::UnixTimeVote(50),
            peer,
        )
        .await;
    assert!(lower.is_err());

    // a later vote is accepted
    let higher = escrow
        .process_consensus_item(
            &mut module_dbtx,
            EscrowConsensusItem::UnixTimeVote(200),
            peer,
        )
        .await;
    assert!(higher.is_ok());
    assert_eq!(
        module_dbtx.get_value(&UnixTimeVoteKey(peer)).await,
        Some(200)
    );
}

#[test_log::test(tokio::test)]
async fn test_process_consensus_item_unknown_variant_rejected() {
    let escrow = make_escrow();
    let db = Database::new(MemDatabase::new(), ModuleRegistry::default());

    let mut dbtx = db.begin_transaction_nc().await;
    let mut module_dbtx = dbtx.to_ref_with_prefix_module_id(42).0.into_nc();

    let result = escrow
        .process_consensus_item(
            &mut module_dbtx,
            EscrowConsensusItem::Default {
                variant: 7,
                bytes: vec![],
            },
            PeerId::from(0u16),
        )
        .await;

    assert!(result.is_err());
}

#[test_log::test(tokio::test)]
async fn test_consensus_time_needs_threshold_of_votes() {
    // 4 guardians: a threshold of 3 must have reached the time
    let mut escrow = make_escrow();
    escrow.num_peers = NumPeers::from(4usize);
    let db = Database::new(MemDatabase::new(), ModuleRegistry::default());

    let mut dbtx = db.begin_transaction_nc().await;
    let mut module_dbtx = dbtx.to_ref_with_prefix_module_id(42).0.into_nc();

    // two votes are not enough
    module_dbtx
        .insert_entry(&UnixTimeVoteKey(PeerId::from(0u16)), &100)
        .await;
    module_dbtx
        .insert_entry(&UnixTimeVoteKey(PeerId::from(1u16)), &200)
        .await;
    assert_eq!(escrow.consensus_unix_time(&mut module_dbtx).await, 0);

    // with three votes the time is the lowest of them
    module_dbtx
        .insert_entry(&UnixTimeVoteKey(PeerId::from(2u16)), &300)
        .await;
    assert_eq!(escrow.consensus_unix_time(&mut module_dbtx).await, 100);

    // the highest vote alone cannot move the time ahead of the threshold
    module_dbtx
        .insert_entry(&UnixTimeVoteKey(PeerId::from(3u16)), &400)
        .await;
    assert_eq!(escrow.consensus_unix_time(&mut module_dbtx).await, 200);
}
