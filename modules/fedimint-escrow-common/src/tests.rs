use fedimint_core::config::FederationId;
use fedimint_core::secp256k1::schnorr::Signature;
use fedimint_core::secp256k1::{Keypair, PublicKey, Secp256k1, SecretKey};
use fedimint_core::{Amount, BitcoinHash, secp256k1};

use crate::rules::{AcceptedResolution, Settlement, check_resolution};
use crate::{
    ContractHash, EscrowContract, EscrowId, EscrowInputError, EscrowMessage, EscrowStatus,
    EscrowTransition, FallbackPolicy, Outcome, Resolution, compute_escrow_message,
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

fn swap_contract() -> EscrowContract {
    let mut c = contract();
    c.default_fallback = FallbackPolicy::SwapArbiter {
        arbiter_key: pk(5),
        arbiter_fee_key: vec![pk(6)],
        arbiter_fee: msats(2_000),
    };
    c
}

fn disputed(mut c: EscrowContract, swapped: bool) -> EscrowContract {
    c.status = EscrowStatus::Disputed {
        resolve_by: RESOLVE_BY,
        swapped,
    };
    c
}

fn release(c: &EscrowContract, signer: u8) -> Resolution {
    Resolution::FunderRelease {
        funder_signature: sign(signer, &c.resolution_message(Outcome::Release)),
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

fn claims(accepted: AcceptedResolution) -> Vec<(PublicKey, Amount)> {
    match accepted.settlement {
        Settlement::WriteClaims(claims) => claims,
        other => panic!("expected claims, got {other:?}"),
    }
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
            swapped: false
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
