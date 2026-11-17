use std::str::FromStr;

use fedimint_core::config::FederationId;
use fedimint_core::secp256k1::schnorr::Signature;
use fedimint_core::secp256k1::{Keypair, PublicKey, Secp256k1, SecretKey};
use fedimint_core::{Amount, BitcoinHash, secp256k1};

use crate::rules::{AcceptedResolution, Settlement, check_resolution};
use crate::{
    ContractHash, EscrowContract, EscrowContractValidationError, EscrowId, EscrowInputError,
    EscrowMessage, EscrowStatus, EscrowTransition, FallbackPolicy, MAX_SWAPS, Outcome, Resolution,
    SuccessorArbiter, compute_contract_hash, compute_escrow_message, validate_contract_fields,
};

const TIMEOUT: u64 = 1_000;
const PERIOD: u64 = 600;
const RESOLVE_BY: u64 = 2_000;

fn keypair(n: u8) -> Keypair {
    Keypair::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&[n; 32]).unwrap())
}

fn pk(n: u8) -> PublicKey {
    keypair(n).public_key()
}

fn sign(n: u8, message: &EscrowMessage) -> Signature {
    let digest = secp256k1::Message::from_digest(compute_escrow_message(message));
    Secp256k1::new().sign_schnorr(&digest, &keypair(n))
}

fn msats(n: u64) -> Amount {
    Amount::from_msats(n)
}

fn contract() -> EscrowContract {
    EscrowContract {
        escrow_id: EscrowId([1; 32]),
        funder_key: pk(1),
        recipient_key: pk(2),
        arbiter_key: pk(3),
        arbiter_fee_key: vec![pk(4)],
        amount: msats(100_000),
        arbiter_fee: msats(1_000),
        contract_hash: ContractHash([9; 32]),
        timeout: TIMEOUT,
        federation_id: FederationId(fedimint_core::bitcoin::hashes::sha256::Hash::all_zeros()),
        status: EscrowStatus::Active,
        resolution_period: PERIOD,
        default_fallback: FallbackPolicy::Refund,
    }
}

fn successor(arbiter: u8, fee_key: u8, fee_msats: u64) -> SuccessorArbiter {
    SuccessorArbiter {
        arbiter_key: pk(arbiter),
        arbiter_fee_key: vec![pk(fee_key)],
        arbiter_fee: msats(fee_msats),
    }
}

fn with_successors(successors: Vec<SuccessorArbiter>) -> EscrowContract {
    let mut c = contract();
    c.default_fallback = FallbackPolicy::SwapArbiter { successors };
    c
}

// one successor: arbiter 5, fee key 6, fee 2_000
fn swap_contract() -> EscrowContract {
    with_successors(vec![successor(5, 6, 2_000)])
}

// two successors: arbiter 5 (fee key 6, fee 2_000) then arbiter 7 (fee key 9,
// fee 3_000)
fn two_swap_contract() -> EscrowContract {
    with_successors(vec![successor(5, 6, 2_000), successor(7, 9, 3_000)])
}

fn disputed_with_swaps(mut c: EscrowContract, swaps_used: u8) -> EscrowContract {
    c.status = EscrowStatus::Disputed {
        resolve_by: RESOLVE_BY,
        swaps_used,
    };
    c
}

fn disputed(c: EscrowContract, swapped: bool) -> EscrowContract {
    disputed_with_swaps(c, u8::from(swapped))
}

fn release(c: &EscrowContract, signer: u8) -> Resolution {
    Resolution::FunderRelease {
        funder_signature: sign(signer, &c.resolution_message(Outcome::Release)),
    }
}

fn refund(c: &EscrowContract, signer: u8) -> Resolution {
    Resolution::RecipientRefund {
        recipient_signature: sign(signer, &c.resolution_message(Outcome::Refund)),
    }
}

// `disputant` says who is engaging, `signer` who actually signed
fn engage(c: &EscrowContract, disputant: u8, signer: u8) -> Resolution {
    Resolution::ArbiterEngaged {
        disputant_pubkey: pk(disputant),
        disputant_signature: sign(signer, &c.engage_message()),
    }
}

fn ruling_by(c: &EscrowContract, signer: u8, outcome: Outcome, submitter: u8) -> Resolution {
    Resolution::ArbiterOutcome {
        arbiter_signature: sign(signer, &c.resolution_message(outcome)),
        outcome,
        submitter_pubkey: pk(submitter),
    }
}

fn ruling(c: &EscrowContract, signer: u8, outcome: Outcome) -> Resolution {
    ruling_by(c, signer, outcome, 1)
}

fn fallback(c: &EscrowContract, claimer: u8) -> Resolution {
    Resolution::ResolveFallbackPolicy {
        claimer_pubkey: pk(claimer),
        fallback: c.default_fallback.clone(),
    }
}

fn accept(c: &EscrowContract, resolution: &Resolution, now: u64) -> AcceptedResolution {
    let accepted = check_resolution(c, resolution, now).unwrap();
    c.clone().transition(accepted.transition).unwrap();
    accepted
}

// like `accept`, but really changes the contract, the way the federation does
fn apply(c: &mut EscrowContract, resolution: &Resolution, now: u64) -> AcceptedResolution {
    let accepted = check_resolution(c, resolution, now).unwrap();
    c.transition(accepted.transition).unwrap();
    accepted
}

// a fallback that swaps to the next arbiter
fn swap(c: &mut EscrowContract, claimer: u8, now: u64) {
    let resolution = fallback(c, claimer);
    apply(c, &resolution, now);
}

fn claims(accepted: AcceptedResolution) -> Vec<(PublicKey, Amount)> {
    match accepted.settlement {
        Settlement::WriteClaims(claims) => claims,
        other => panic!("expected claims, got {other:?}"),
    }
}

fn validation_error(c: &EscrowContract) -> EscrowContractValidationError {
    validate_contract_fields(c, 0).unwrap_err()
}

fn hash_of(c: &EscrowContract) -> ContractHash {
    compute_contract_hash(
        &c.funder_key,
        &c.recipient_key,
        &c.arbiter_key,
        &c.arbiter_fee,
        &c.amount,
        &c.timeout,
        &c.federation_id,
        &c.resolution_period,
        &c.arbiter_fee_key,
        &c.default_fallback,
    )
}

#[test]
fn funder_release_pays_recipient_while_active() {
    let c = contract();

    let accepted = accept(&c, &release(&c, 1), 0);

    assert_eq!(accepted.transition, EscrowTransition::FunderRelease);
    assert_eq!(accepted.settlement, Settlement::PayRecipient(c.amount));
    assert_eq!(accepted.input_key, c.recipient_key);
}

#[test]
fn funder_release_is_not_time_gated() {
    let c = contract();

    assert!(check_resolution(&c, &release(&c, 1), TIMEOUT + 5_000).is_ok());
}

#[test]
fn funder_release_signed_by_recipient_rejected() {
    let c = contract();

    assert_eq!(
        check_resolution(&c, &release(&c, 2), 0),
        Err(EscrowInputError::InvalidSignature)
    );
}

#[test]
fn funder_release_signing_refund_rejected() {
    let c = contract();
    let resolution = Resolution::FunderRelease {
        funder_signature: sign(1, &c.resolution_message(Outcome::Refund)),
    };

    assert_eq!(
        check_resolution(&c, &resolution, 0),
        Err(EscrowInputError::InvalidSignature)
    );
}

#[test]
fn funder_release_rejected_once_disputed() {
    let c = disputed(contract(), false);

    assert_eq!(
        check_resolution(&c, &release(&c, 1), 0),
        Err(EscrowInputError::ContractDisputed)
    );
}

#[test]
fn funder_release_rejected_once_resolved() {
    for status in [
        EscrowStatus::Released,
        EscrowStatus::Refunded,
        EscrowStatus::Split,
    ] {
        let mut c = contract();
        c.status = status;

        assert_eq!(
            check_resolution(&c, &release(&c, 1), 0),
            Err(EscrowInputError::ContractAlreadyResolved)
        );
    }
}

#[test]
fn recipient_refund_pays_funder_while_active() {
    let c = contract();

    let accepted = accept(&c, &refund(&c, 2), 0);

    assert_eq!(accepted.transition, EscrowTransition::RecipientRefund);
    assert_eq!(accepted.settlement, Settlement::PayFunder(c.amount));
    assert_eq!(accepted.input_key, c.funder_key);
}

#[test]
fn recipient_refund_is_not_time_gated() {
    let c = contract();

    assert!(check_resolution(&c, &refund(&c, 2), TIMEOUT + 5_000).is_ok());
}

#[test]
fn recipient_refund_signed_by_funder_rejected() {
    let c = contract();

    assert_eq!(
        check_resolution(&c, &refund(&c, 1), 0),
        Err(EscrowInputError::InvalidSignature)
    );
}

#[test]
fn recipient_refund_signing_release_rejected() {
    let c = contract();
    let resolution = Resolution::RecipientRefund {
        recipient_signature: sign(2, &c.resolution_message(Outcome::Release)),
    };

    assert_eq!(
        check_resolution(&c, &resolution, 0),
        Err(EscrowInputError::InvalidSignature)
    );
}

#[test]
fn recipient_refund_rejected_once_disputed() {
    let c = disputed(contract(), false);

    assert_eq!(
        check_resolution(&c, &refund(&c, 2), 0),
        Err(EscrowInputError::ContractDisputed)
    );
}

#[test]
fn recipient_refund_rejected_once_resolved() {
    for status in [
        EscrowStatus::Released,
        EscrowStatus::Refunded,
        EscrowStatus::Split,
    ] {
        let mut c = contract();
        c.status = status;

        assert_eq!(
            check_resolution(&c, &refund(&c, 2), 0),
            Err(EscrowInputError::ContractAlreadyResolved)
        );
    }
}

#[test]
fn recipient_refund_marks_refunded_and_blocks_a_release() {
    let mut c = contract();

    let resolution = refund(&c, 2);
    apply(&mut c, &resolution, 0);

    assert_eq!(c.status, EscrowStatus::Refunded);
    assert_eq!(
        check_resolution(&c, &release(&c, 1), 0),
        Err(EscrowInputError::ContractAlreadyResolved)
    );
}

// the refund shares its message with an arbiter's Refund, only the keys differ
#[test]
fn arbiter_refund_signature_is_not_a_recipient_refund() {
    let c = contract();

    assert_eq!(
        check_resolution(&c, &refund(&c, 3), 0),
        Err(EscrowInputError::InvalidSignature)
    );
}

#[test]
fn recipient_refund_signature_is_not_an_arbiter_ruling() {
    let c = disputed(contract(), false);

    assert_eq!(
        check_resolution(&c, &ruling(&c, 2, Outcome::Refund), RESOLVE_BY),
        Err(EscrowInputError::InvalidSignature)
    );
}

#[test]
fn recipient_refund_transition_only_from_active() {
    for status in [
        EscrowStatus::Released,
        EscrowStatus::Refunded,
        EscrowStatus::Split,
        EscrowStatus::Disputed {
            resolve_by: RESOLVE_BY,
            swaps_used: 0,
        },
    ] {
        let mut c = contract();
        c.status = status;

        assert_eq!(
            c.transition(EscrowTransition::RecipientRefund),
            Err(EscrowInputError::InvalidStateTransition)
        );
    }
}

#[test]
fn engage_opens_exactly_at_timeout() {
    let c = contract();

    assert_eq!(
        check_resolution(&c, &engage(&c, 1, 1), TIMEOUT - 1),
        Err(EscrowInputError::TimeoutNotReached)
    );
    let accepted = accept(&c, &engage(&c, 1, 1), TIMEOUT);
    assert_eq!(
        accepted.transition,
        EscrowTransition::ArbiterEngaged {
            resolve_by: TIMEOUT + PERIOD
        }
    );
    assert_eq!(accepted.settlement, Settlement::None);
    assert_eq!(accepted.input_key, c.funder_key);
}

#[test]
fn engage_by_recipient_accepted() {
    let c = contract();

    assert!(check_resolution(&c, &engage(&c, 2, 2), TIMEOUT).is_ok());
}

#[test]
fn engage_by_arbiter_rejected() {
    let c = contract();

    assert_eq!(
        check_resolution(&c, &engage(&c, 3, 3), TIMEOUT),
        Err(EscrowInputError::NotAParticipant)
    );
}

#[test]
fn engage_signed_by_someone_else_rejected() {
    let c = contract();

    // says funder, but the recipient signed
    assert_eq!(
        check_resolution(&c, &engage(&c, 1, 2), TIMEOUT),
        Err(EscrowInputError::InvalidSignature)
    );
}

#[test]
fn engage_twice_rejected() {
    let c = disputed(contract(), false);

    assert_eq!(
        check_resolution(&c, &engage(&c, 1, 1), TIMEOUT),
        Err(EscrowInputError::ContractDisputed)
    );
}

#[test]
fn ruling_split_rounds_funder_down() {
    let mut c = disputed(contract(), false);
    c.amount = msats(100_001);
    let split = Outcome::Split {
        funder_split_bps: 3_333,
        recipient_split_bps: 6_667,
    };

    let accepted = accept(&c, &ruling(&c, 3, split), RESOLVE_BY);

    // 99_001 after the fee: funder gets 32_997 (rounded down), recipient the rest
    assert_eq!(
        claims(accepted),
        vec![
            (pk(1), msats(32_997)),
            (pk(2), msats(66_004)),
            (pk(4), msats(1_000)),
        ]
    );
}

#[test]
fn ruling_fee_remainder_goes_to_first_fee_key() {
    let mut c = disputed(contract(), false);
    c.arbiter_fee_key = vec![pk(4), pk(7)];
    c.arbiter_fee = msats(1_001);

    let accepted = accept(&c, &ruling(&c, 3, Outcome::Release), RESOLVE_BY);

    assert_eq!(
        claims(accepted),
        vec![
            (pk(2), msats(98_999)),
            (pk(4), msats(501)),
            (pk(7), msats(500)),
        ]
    );
}

#[test]
fn ruling_with_zero_fee_has_no_fee_entry() {
    let mut c = disputed(contract(), false);
    c.arbiter_fee = Amount::ZERO;

    let accepted = accept(&c, &ruling(&c, 3, Outcome::Release), RESOLVE_BY);

    assert_eq!(claims(accepted), vec![(pk(2), msats(100_000))]);
}

#[test]
fn ruling_split_not_adding_to_10000_rejected() {
    let c = disputed(contract(), false);
    let bad = Outcome::Split {
        funder_split_bps: 6_000,
        recipient_split_bps: 3_000,
    };

    assert_eq!(
        check_resolution(&c, &ruling(&c, 3, bad), RESOLVE_BY),
        Err(EscrowInputError::InvalidSplitRatio)
    );
}

#[test]
fn ruling_accepted_up_to_resolve_by_only() {
    let c = disputed(contract(), false);
    let resolution = ruling(&c, 3, Outcome::Refund);

    assert!(check_resolution(&c, &resolution, RESOLVE_BY).is_ok());
    assert_eq!(
        check_resolution(&c, &resolution, RESOLVE_BY + 1),
        Err(EscrowInputError::ResolutionDeadlinePassed)
    );
}

#[test]
fn ruling_with_changed_outcome_rejected() {
    let c = disputed(contract(), false);
    // arbiter signed Refund, the input says Release
    let resolution = Resolution::ArbiterOutcome {
        arbiter_signature: sign(3, &c.resolution_message(Outcome::Refund)),
        outcome: Outcome::Release,
        submitter_pubkey: pk(1),
    };

    assert_eq!(
        check_resolution(&c, &resolution, RESOLVE_BY),
        Err(EscrowInputError::InvalidSignature)
    );
}

#[test]
fn ruling_submitted_by_stranger_rejected() {
    let c = disputed(contract(), false);
    let resolution = ruling_by(&c, 3, Outcome::Refund, 8);

    assert_eq!(
        check_resolution(&c, &resolution, RESOLVE_BY),
        Err(EscrowInputError::NotAParticipant)
    );
}

#[test]
fn ruling_can_be_submitted_by_any_key_in_the_contract() {
    let c = disputed(contract(), false);

    for submitter in [1, 2, 3, 4] {
        let resolution = ruling_by(&c, 3, Outcome::Refund, submitter);

        let accepted = accept(&c, &resolution, RESOLVE_BY);

        assert_eq!(accepted.input_key, pk(submitter));
    }
}

#[test]
fn ruling_on_active_contract_rejected() {
    let c = contract();

    assert_eq!(
        check_resolution(&c, &ruling(&c, 3, Outcome::Refund), TIMEOUT),
        Err(EscrowInputError::ContractNotDisputed)
    );
}

#[test]
fn ruling_on_resolved_contract_rejected() {
    let mut c = contract();
    c.status = EscrowStatus::Refunded;

    assert_eq!(
        check_resolution(&c, &ruling(&c, 3, Outcome::Refund), TIMEOUT),
        Err(EscrowInputError::ContractAlreadyResolved)
    );
}

#[test]
fn fallback_available_only_after_resolve_by() {
    let c = disputed(contract(), false);

    assert_eq!(
        check_resolution(&c, &fallback(&c, 1), RESOLVE_BY),
        Err(EscrowInputError::FallbackNotAvailable)
    );
    let accepted = accept(&c, &fallback(&c, 1), RESOLVE_BY + 1);
    assert_eq!(accepted.transition, EscrowTransition::Fallback);
}

#[test]
fn fallback_split_divides_everything_without_fee() {
    let mut c = disputed(contract(), false);
    c.default_fallback = FallbackPolicy::Split {
        funder_split_bps: 2_500,
        recipient_split_bps: 7_500,
    };

    let accepted = accept(&c, &fallback(&c, 1), RESOLVE_BY + 1);

    assert_eq!(
        claims(accepted),
        vec![(pk(1), msats(25_000)), (pk(2), msats(75_000))]
    );
}

#[test]
fn fallback_ignores_the_policy_sent_in_the_input() {
    let c = disputed(contract(), false);
    let resolution = Resolution::ResolveFallbackPolicy {
        claimer_pubkey: pk(1),
        fallback: FallbackPolicy::Split {
            funder_split_bps: 5_000,
            recipient_split_bps: 5_000,
        },
    };

    let accepted = accept(&c, &resolution, RESOLVE_BY + 1);

    assert_eq!(claims(accepted), vec![(pk(1), msats(100_000))]);
}

#[test]
fn fallback_by_arbiter_rejected() {
    let c = disputed(contract(), false);

    assert_eq!(
        check_resolution(&c, &fallback(&c, 3), RESOLVE_BY + 1),
        Err(EscrowInputError::NotAParticipant)
    );
}

#[test]
fn fallback_on_active_contract_rejected() {
    let c = contract();

    assert_eq!(
        check_resolution(&c, &fallback(&c, 1), RESOLVE_BY + 1),
        Err(EscrowInputError::ContractNotDisputed)
    );
}

#[test]
fn first_fallback_swaps_arbiter_and_moves_no_funds() {
    let c = disputed(swap_contract(), false);
    let now = RESOLVE_BY + 1;

    let accepted = accept(&c, &fallback(&c, 1), now);

    assert_eq!(
        accepted.transition,
        EscrowTransition::SwapArbiter {
            resolve_by: now + PERIOD
        }
    );
    assert_eq!(accepted.settlement, Settlement::None);
    assert_eq!(accepted.input_key, c.funder_key);
}

#[test]
fn swapped_arbiter_and_fee_replace_the_old_ones() {
    let mut c = disputed(swap_contract(), false);
    let now = RESOLVE_BY + 1;
    let swap = accept(&c, &fallback(&c, 1), now);
    c.transition(swap.transition).unwrap();
    let new_resolve_by = now + PERIOD;

    assert_eq!(
        check_resolution(&c, &ruling(&c, 3, Outcome::Release), new_resolve_by),
        Err(EscrowInputError::InvalidSignature)
    );
    // the new one does, with its own fee and fee key
    let accepted = accept(&c, &ruling(&c, 5, Outcome::Release), new_resolve_by);
    assert_eq!(
        claims(accepted),
        vec![(pk(2), msats(98_000)), (pk(6), msats(2_000))]
    );
}

#[test]
fn no_second_swap_the_next_fallback_refunds() {
    let mut c = disputed(swap_contract(), false);
    let now = RESOLVE_BY + 1;
    let swap = accept(&c, &fallback(&c, 1), now);
    c.transition(swap.transition).unwrap();

    let accepted = accept(&c, &fallback(&c, 2), now + PERIOD + 1);

    assert_eq!(accepted.transition, EscrowTransition::Fallback);
    assert_eq!(claims(accepted), vec![(pk(1), msats(100_000))]);
}

#[test]
fn each_fallback_swaps_to_the_next_arbiter() {
    let mut c = disputed(two_swap_contract(), false);
    let first = RESOLVE_BY + 1;

    swap(&mut c, 1, first);
    assert_eq!(
        c.status,
        EscrowStatus::Disputed {
            resolve_by: first + PERIOD,
            swaps_used: 1,
        }
    );

    let second = first + PERIOD + 1;
    swap(&mut c, 2, second);
    assert_eq!(
        c.status,
        EscrowStatus::Disputed {
            resolve_by: second + PERIOD,
            swaps_used: 2,
        }
    );
}

#[test]
fn swap_is_available_until_the_list_is_used_up() {
    let mut c = disputed(two_swap_contract(), false);
    assert!(c.can_swap_arbiter());
    assert_eq!(c.swaps_used(), 0);

    swap(&mut c, 1, RESOLVE_BY + 1);
    assert!(c.can_swap_arbiter());
    assert_eq!(c.swaps_used(), 1);

    swap(&mut c, 1, RESOLVE_BY + 1 + PERIOD + 1);
    assert!(!c.can_swap_arbiter());
    assert_eq!(c.swaps_used(), 2);
    assert_eq!(c.effective_fallback(), FallbackPolicy::Refund);
}

#[test]
fn each_swap_activates_its_own_arbiter_and_fee() {
    let mut c = disputed(two_swap_contract(), false);
    let mut now = RESOLVE_BY + 1;
    swap(&mut c, 1, now);

    // first successor rules, with its own fee and fee key
    let accepted = accept(&c, &ruling(&c, 5, Outcome::Release), now + PERIOD);
    assert_eq!(
        claims(accepted),
        vec![(pk(2), msats(98_000)), (pk(6), msats(2_000))]
    );

    now += PERIOD + 1;
    swap(&mut c, 2, now);

    // second successor rules, with its own fee and fee key
    let accepted = accept(&c, &ruling(&c, 7, Outcome::Release), now + PERIOD);
    assert_eq!(
        claims(accepted),
        vec![(pk(2), msats(97_000)), (pk(9), msats(3_000))]
    );
}

#[test]
fn only_the_active_arbiter_can_rule() {
    let mut c = disputed(two_swap_contract(), false);
    let mut now = RESOLVE_BY + 1;

    // the original rules, the successors are not active yet
    for signer in [5, 7] {
        assert_eq!(
            check_resolution(&c, &ruling(&c, signer, Outcome::Refund), RESOLVE_BY),
            Err(EscrowInputError::InvalidSignature)
        );
    }

    swap(&mut c, 1, now);
    let deadline = now + PERIOD;
    for signer in [3, 7] {
        assert_eq!(
            check_resolution(&c, &ruling(&c, signer, Outcome::Refund), deadline),
            Err(EscrowInputError::InvalidSignature)
        );
    }

    now = deadline + 1;
    swap(&mut c, 1, now);
    let deadline = now + PERIOD;
    for signer in [3, 5] {
        assert_eq!(
            check_resolution(&c, &ruling(&c, signer, Outcome::Refund), deadline),
            Err(EscrowInputError::InvalidSignature)
        );
    }
    assert!(check_resolution(&c, &ruling(&c, 7, Outcome::Refund), deadline).is_ok());
}

#[test]
fn fallback_after_the_last_swap_refunds_without_fee() {
    let mut c = disputed(two_swap_contract(), false);
    let mut now = RESOLVE_BY + 1;
    swap(&mut c, 1, now);
    now += PERIOD + 1;
    swap(&mut c, 2, now);
    now += PERIOD + 1;

    let resolution = fallback(&c, 1);
    let accepted = apply(&mut c, &resolution, now);

    assert_eq!(accepted.transition, EscrowTransition::Fallback);
    assert_eq!(claims(accepted), vec![(pk(1), msats(100_000))]);
    assert_eq!(c.status, EscrowStatus::Refunded);
}

#[test]
fn current_arbiter_follows_the_swaps_used() {
    let c0 = disputed_with_swaps(two_swap_contract(), 0);
    assert_eq!(c0.current_arbiter_key(), &pk(3));
    assert_eq!(c0.current_fee_keys(), &[pk(4)]);
    assert_eq!(c0.current_arbiter_fee(), msats(1_000));

    let c1 = disputed_with_swaps(two_swap_contract(), 1);
    assert_eq!(c1.current_arbiter_key(), &pk(5));
    assert_eq!(c1.current_fee_keys(), &[pk(6)]);
    assert_eq!(c1.current_arbiter_fee(), msats(2_000));

    let c2 = disputed_with_swaps(two_swap_contract(), 2);
    assert_eq!(c2.current_arbiter_key(), &pk(7));
    assert_eq!(c2.current_fee_keys(), &[pk(9)]);
    assert_eq!(c2.current_arbiter_fee(), msats(3_000));
}

#[test]
fn all_keys_include_every_successor() {
    let c = two_swap_contract();

    for n in [1, 2, 3, 4, 5, 6, 7, 9] {
        assert!(c.contains_key(&pk(n)));
    }
    assert!(!c.contains_key(&pk(8)));
    assert_eq!(c.all_keys().len(), 8);
}

#[test]
fn contracts_used_in_these_tests_are_valid() {
    assert_eq!(validate_contract_fields(&contract(), 0), Ok(()));
    assert_eq!(validate_contract_fields(&swap_contract(), 0), Ok(()));
    assert_eq!(validate_contract_fields(&two_swap_contract(), 0), Ok(()));
}

#[test]
fn empty_successor_list_rejected() {
    let c = with_successors(vec![]);

    assert_eq!(
        validation_error(&c),
        EscrowContractValidationError::InvalidInput
    );
}

#[test]
fn successor_list_is_capped_at_max_swaps() {
    let list = |n: u8| -> Vec<SuccessorArbiter> {
        (0..n)
            .map(|i| successor(20 + 2 * i, 21 + 2 * i, 1_000))
            .collect()
    };

    assert_eq!(
        validate_contract_fields(&with_successors(list(MAX_SWAPS as u8)), 0),
        Ok(())
    );
    assert_eq!(
        validation_error(&with_successors(list(MAX_SWAPS as u8 + 1))),
        EscrowContractValidationError::InvalidInput
    );
}

#[test]
fn successor_key_used_twice_rejected() {
    let c = with_successors(vec![successor(5, 6, 2_000), successor(5, 9, 3_000)]);

    assert_eq!(
        validation_error(&c),
        EscrowContractValidationError::DuplicateKeys
    );
}

#[test]
fn successor_key_equal_to_a_party_rejected() {
    // 2 is the recipient
    let c = with_successors(vec![successor(2, 6, 2_000)]);

    assert_eq!(
        validation_error(&c),
        EscrowContractValidationError::DuplicateKeys
    );
}

#[test]
fn successor_fee_key_equal_to_the_original_fee_key_rejected() {
    // 4 is the fee key of the original arbiter
    let c = with_successors(vec![successor(5, 4, 2_000)]);

    assert_eq!(
        validation_error(&c),
        EscrowContractValidationError::DuplicateKeys
    );
}

#[test]
fn successor_fee_not_below_amount_rejected() {
    let c = with_successors(vec![successor(5, 6, 100_000)]);

    assert_eq!(
        validation_error(&c),
        EscrowContractValidationError::InvalidArbiterFee
    );
}

#[test]
fn successor_fee_without_fee_key_rejected() {
    let mut s = successor(5, 6, 2_000);
    s.arbiter_fee_key.clear();

    assert_eq!(
        validation_error(&with_successors(vec![s])),
        EscrowContractValidationError::MissingArbiterFeeKeys
    );
}

#[test]
fn deadlines_must_fit_in_u64_for_every_swap_window() {
    // one window fits exactly
    let mut plain = contract();
    plain.timeout = u64::MAX - PERIOD;
    assert_eq!(validate_contract_fields(&plain, 0), Ok(()));

    // two successors need three windows
    let mut swappy = two_swap_contract();
    swappy.timeout = u64::MAX - PERIOD;
    assert_eq!(
        validation_error(&swappy),
        EscrowContractValidationError::InvalidTimeout
    );
}

#[test]
fn contract_hash_covers_the_successor_list_and_its_order() {
    let one = swap_contract();
    let two = two_swap_contract();
    let reordered = with_successors(vec![successor(7, 9, 3_000), successor(5, 6, 2_000)]);

    assert_eq!(hash_of(&two), hash_of(&two_swap_contract()));
    assert_ne!(hash_of(&one), hash_of(&two));
    assert_ne!(hash_of(&two), hash_of(&reordered));
}

// these two need the sats parsing and the `split:` arm from the lib.rs notes
#[test]
fn swap_fallback_string_parses_every_successor() {
    let text = format!("swap:{}:2:{};{}:3:{}", pk(5), pk(6), pk(7), pk(9));

    let policy = FallbackPolicy::from_str(&text).unwrap();

    assert_eq!(
        policy,
        FallbackPolicy::SwapArbiter {
            successors: vec![
                SuccessorArbiter {
                    arbiter_key: pk(5),
                    arbiter_fee_key: vec![pk(6)],
                    arbiter_fee: Amount::from_sats(2),
                },
                SuccessorArbiter {
                    arbiter_key: pk(7),
                    arbiter_fee_key: vec![pk(9)],
                    arbiter_fee: Amount::from_sats(3),
                },
            ]
        }
    );
}

#[test]
fn refund_and_split_fallback_strings_still_parse() {
    assert_eq!(
        FallbackPolicy::from_str("refund").unwrap(),
        FallbackPolicy::Refund
    );
    assert_eq!(
        FallbackPolicy::from_str("split:2500:7500").unwrap(),
        FallbackPolicy::Split {
            funder_split_bps: 2_500,
            recipient_split_bps: 7_500,
        }
    );
    assert!(FallbackPolicy::from_str("split:2500:7000").is_err());
    assert!(FallbackPolicy::from_str("nonsense").is_err());
}

#[test]
fn claim_payout_is_not_a_contract_transition() {
    let c = contract();
    let resolution = Resolution::ClaimPayout {
        claimer_pubkey: pk(1),
    };

    assert_eq!(
        check_resolution(&c, &resolution, 0),
        Err(EscrowInputError::InvalidStateTransition)
    );
}

#[test]
fn dispute_flow_ends_in_a_resolved_contract() {
    let mut c = contract();

    let engaged = accept(&c, &engage(&c, 2, 2), TIMEOUT);
    c.transition(engaged.transition).unwrap();
    assert_eq!(
        c.status,
        EscrowStatus::Disputed {
            resolve_by: TIMEOUT + PERIOD,
            swaps_used: 0,
        }
    );
    // the funder can no longer release
    assert_eq!(
        check_resolution(&c, &release(&c, 1), TIMEOUT),
        Err(EscrowInputError::ContractDisputed)
    );

    let ruled = accept(&c, &ruling(&c, 3, Outcome::Release), TIMEOUT + PERIOD);
    c.transition(ruled.transition).unwrap();
    assert_eq!(c.status, EscrowStatus::Released);

    // nothing else works afterwards
    assert_eq!(
        check_resolution(&c, &ruling(&c, 3, Outcome::Release), TIMEOUT + PERIOD),
        Err(EscrowInputError::ContractAlreadyResolved)
    );
    assert_eq!(
        check_resolution(&c, &fallback(&c, 1), RESOLVE_BY + 1),
        Err(EscrowInputError::ContractNotDisputed)
    );
}

#[test]
fn active_contract_cannot_jump_to_a_ruling() {
    let mut c = contract();

    assert_eq!(
        c.transition(EscrowTransition::ArbiterOutcome(Outcome::Refund)),
        Err(EscrowInputError::InvalidStateTransition)
    );
    assert_eq!(c.status, EscrowStatus::Active);
}

#[test]
fn resolved_contract_cannot_transition_again() {
    for status in [
        EscrowStatus::Released,
        EscrowStatus::Refunded,
        EscrowStatus::Split,
    ] {
        let mut c = contract();
        c.status = status;

        assert_eq!(
            c.transition(EscrowTransition::FunderRelease),
            Err(EscrowInputError::InvalidStateTransition)
        );
        assert_eq!(
            c.transition(EscrowTransition::Fallback),
            Err(EscrowInputError::InvalidStateTransition)
        );
    }
}
