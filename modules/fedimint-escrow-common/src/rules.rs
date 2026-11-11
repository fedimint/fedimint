use fedimint_core::secp256k1::PublicKey;
use fedimint_core::secp256k1::schnorr::Signature;
use fedimint_core::{Amount, secp256k1};

use crate::{
    EscrowContract, EscrowInputError, EscrowMessage, EscrowStatus, EscrowTransition, Outcome,
    Resolution, SPLIT_BPS_DENOMINATOR, compute_escrow_message,
};

/// What the federation must do with the funds once a resolution is accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Settlement {
    /// Only the contract status changes.
    None,
    /// Pay the recipient in the same transaction (funder release).
    PayRecipient(Amount),
    /// Write a claim pool; nobody is paid in this transaction.
    WriteClaims(Vec<(PublicKey, Amount)>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedResolution {
    pub transition: EscrowTransition,
    pub settlement: Settlement,
    /// The key that must authorize the transaction input.
    pub input_key: PublicKey,
}

/// Checks `resolution` against `contract` at consensus time `now`.
///
/// `Resolution::ClaimPayout` does not change the contract and is rejected
/// here; use `ClaimPool::take_claim` for it.
pub fn check_resolution(
    contract: &EscrowContract,
    resolution: &Resolution,
    now: u64,
) -> Result<AcceptedResolution, EscrowInputError> {
    match resolution {
        Resolution::FunderRelease { funder_signature } => {
            funder_release(contract, funder_signature)
        }
        Resolution::ArbiterEngaged {
            disputant_pubkey,
            disputant_signature,
        } => engage_arbiter(contract, disputant_pubkey, disputant_signature, now),
        Resolution::ArbiterOutcome {
            arbiter_signature,
            outcome,
            submitter_pubkey,
        } => arbiter_outcome(contract, arbiter_signature, outcome, submitter_pubkey, now),
        Resolution::ResolveFallbackPolicy { claimer_pubkey, .. } => {
            resolve_fallback(contract, claimer_pubkey, now)
        }
        Resolution::ClaimPayout { .. } => Err(EscrowInputError::InvalidStateTransition),
    }
}

fn funder_release(
    contract: &EscrowContract,
    funder_signature: &Signature,
) -> Result<AcceptedResolution, EscrowInputError> {
    contract.ensure_active()?;
    ensure_signed(
        &contract.funder_key,
        &contract.resolution_message(Outcome::Release),
        funder_signature,
    )?;

    Ok(AcceptedResolution {
        transition: EscrowTransition::FunderRelease,
        settlement: Settlement::PayRecipient(contract.amount),
        input_key: contract.recipient_key,
    })
}

fn engage_arbiter(
    contract: &EscrowContract,
    disputant: &PublicKey,
    disputant_signature: &Signature,
    now: u64,
) -> Result<AcceptedResolution, EscrowInputError> {
    contract.ensure_active()?;
    if now < contract.timeout {
        return Err(EscrowInputError::TimeoutNotReached);
    }
    if !contract.is_party(disputant) {
        return Err(EscrowInputError::NotAParticipant);
    }
    if contract.is_terminal() {
        return Err(EscrowInputError::ContractAlreadyResolved);
    }

    ensure_signed(disputant, &contract.engage_message(), disputant_signature)?;

    Ok(AcceptedResolution {
        transition: EscrowTransition::ArbiterEngaged {
            resolve_by: deadline(now, contract.resolution_period)?,
        },
        settlement: Settlement::None,
        input_key: *disputant,
    })
}

fn arbiter_outcome(
    contract: &EscrowContract,
    arbiter_signature: &Signature,
    outcome: &Outcome,
    submitter: &PublicKey,
    now: u64,
) -> Result<AcceptedResolution, EscrowInputError> {
    if !contract.contains_key(submitter) {
        return Err(EscrowInputError::NotAParticipant);
    }
    let EscrowStatus::Disputed { resolve_by, .. } = contract.status else {
        return Err(if contract.is_terminal() {
            EscrowInputError::ContractAlreadyResolved
        } else {
            EscrowInputError::ContractNotDisputed
        });
    };
    if now > resolve_by {
        return Err(EscrowInputError::ResolutionDeadlinePassed);
    }
    ensure_signed(
        contract.current_arbiter_key(),
        &contract.resolution_message(*outcome),
        arbiter_signature,
    )?;

    Ok(AcceptedResolution {
        transition: EscrowTransition::ArbiterOutcome(*outcome),
        settlement: Settlement::WriteClaims(payout_claims(contract, outcome, true)?),
        input_key: *submitter,
    })
}

fn resolve_fallback(
    contract: &EscrowContract,
    claimer: &PublicKey,
    now: u64,
) -> Result<AcceptedResolution, EscrowInputError> {
    if !contract.is_party(claimer) {
        return Err(EscrowInputError::NotAParticipant);
    }

    let EscrowStatus::Disputed { resolve_by, .. } = contract.status else {
        return Err(if contract.is_terminal() {
            EscrowInputError::ContractAlreadyResolved
        } else {
            EscrowInputError::ContractNotDisputed
        });
    };

    if now <= resolve_by {
        return Err(EscrowInputError::FallbackNotAvailable);
    }

    if contract.can_swap_arbiter() {
        return Ok(AcceptedResolution {
            transition: EscrowTransition::SwapArbiter {
                resolve_by: deadline(now, contract.resolution_period)?,
            },
            settlement: Settlement::None,
            input_key: *claimer,
        });
    }

    // No arbiter fee on fallback path
    let outcome = Outcome::from(&contract.default_fallback);
    Ok(AcceptedResolution {
        transition: EscrowTransition::Fallback,
        settlement: Settlement::WriteClaims(payout_claims(contract, &outcome, false)?),
        input_key: *claimer,
    })
}

fn deadline(now: u64, period: u64) -> Result<u64, EscrowInputError> {
    now.checked_add(period)
        .ok_or_else(|| EscrowInputError::InternalError("resolution period overflows".into()))
}

fn ensure_signed(
    key: &PublicKey,
    message: &EscrowMessage,
    signature: &Signature,
) -> Result<(), EscrowInputError> {
    let msg = secp256k1::Message::from_digest(compute_escrow_message(message));

    secp256k1::global::SECP256K1
        .verify_schnorr(signature, &msg, &key.x_only_public_key().0)
        .map_err(|_| EscrowInputError::InvalidSignature)
}

/// Splits the fee equally between the fee keys; the first key takes the
/// remainder.
fn split_fee(keys: &[PublicKey], fee: Amount) -> Vec<(PublicKey, Amount)> {
    if keys.is_empty() || fee == Amount::ZERO {
        return vec![];
    }
    let n = keys.len() as u64;
    let share = fee.msats / n;
    let remainder = fee.msats - share * n;
    keys.iter()
        .enumerate()
        .map(|(i, k)| {
            (
                *k,
                Amount::from_msats(share + if i == 0 { remainder } else { 0 }),
            )
        })
        .collect()
}

/// Claim pool entries for `outcome`. The entries always sum to
/// `contract.amount`; zero entries are dropped.
fn payout_claims(
    contract: &EscrowContract,
    outcome: &Outcome,
    include_fee: bool,
) -> Result<Vec<(PublicKey, Amount)>, EscrowInputError> {
    let fee = if include_fee {
        contract.current_arbiter_fee()
    } else {
        Amount::ZERO
    };
    let payout_amount = contract
        .amount
        .checked_sub(fee)
        .ok_or_else(|| EscrowInputError::InternalError("fee exceeds amount".into()))?;

    let mut claims = match outcome {
        Outcome::Release => vec![(contract.recipient_key, payout_amount)],
        Outcome::Refund => vec![(contract.funder_key, payout_amount)],
        Outcome::Split {
            funder_split_bps, ..
        } => {
            if !outcome.is_valid() {
                return Err(EscrowInputError::InvalidSplitRatio);
            }
            let funder_amount = Amount::from_msats(
                ((payout_amount.msats as u128 * u128::from(*funder_split_bps))
                    / u128::from(SPLIT_BPS_DENOMINATOR)) as u64,
            );
            let recipient_amount = payout_amount
                .checked_sub(funder_amount)
                .ok_or_else(|| EscrowInputError::InternalError("split overflow".into()))?;
            vec![
                (contract.funder_key, funder_amount),
                (contract.recipient_key, recipient_amount),
            ]
        }
    };

    if include_fee {
        claims.extend(split_fee(contract.current_fee_keys(), fee));
    }
    claims.retain(|(_, a)| *a != Amount::ZERO);

    let total: u128 = claims.iter().map(|(_, a)| u128::from(a.msats)).sum();
    if total != u128::from(contract.amount.msats) {
        return Err(EscrowInputError::InternalError(
            "claims do not sum to amount".into(),
        ));
    }
    Ok(claims)
}
