//! Pure classification of gateway state machines into accounting facts.
//!
//! Every `match` here is exhaustive with no wildcard arm on purpose: adding a
//! state without deciding what it means for the balance sheet must fail to
//! compile, not silently misaccount.

use bitcoin::hashes::sha256;
use fedimint_core::core::OperationId;
use fedimint_core::{Amount, OutPoint};
use fedimint_lightning::OutboundCost;
use fedimint_lnv2_common::LightningInvoice;

use crate::GatewayClientStateMachinesV2;
use crate::complete_sm::CompleteSMState;
use crate::receive_sm::ReceiveSMState;
use crate::send_sm::{Cancelled, SendSMState};

/// What an outgoing forward's state says about the gateway's position.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendOutcome {
    /// Outbound leg in progress. Nothing is at risk on the federation side:
    /// an in-flight HTLC is still counted in the node's balance partition,
    /// and a swap's funding is counted by the target federation's receive.
    InFlight,
    /// Outbound leg settled, claim not yet submitted (LNv1 only). The
    /// contract amount is at risk until the claim lands.
    PaidAwaitingClaim { cost: Option<OutboundCost> },
    /// Outbound leg settled and the claim submitted. Realized once every
    /// outpoint's issuance succeeded; the aggregator performs that join.
    Claimed {
        cost: OutboundCost,
        outpoints: Vec<OutPoint>,
    },
    /// Claim submitted before costs were recorded (pre-upgrade history).
    ClaimedUnknownCost { outpoints: Vec<OutPoint> },
    /// The contract was never paid for according to the state machine.
    /// `after_dispatch` is true when the node was asked to pay first, so the
    /// reconciler must confirm the payment really failed.
    Cancelled { after_dispatch: bool },
}

/// What an incoming forward's receive state says about the funded contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiveOutcome {
    /// Contract funded, preimage not yet decrypted: the contract amount is
    /// at risk.
    Funding,
    /// Preimage obtained. Value is realized only when a circuit completes.
    Success,
    /// Funding was rejected or refunded: the ecash never left, or came back.
    NotFunded,
    /// Funded, but the decryption key was invalid: the contract amount is
    /// lost unless refunded out of band.
    Lost,
}

/// Outcome of settling one incoming Lightning circuit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitOutcome {
    Pending,
    Completed,
    Failed,
}

/// One state machine's contribution to the balance sheet, before joins.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForwardFact {
    Send {
        operation_id: OperationId,
        contract_amount: Amount,
        /// Needed to reconcile cancellations against the node. Always
        /// `Some` for LNv2, whose send machine carries the invoice, and
        /// always `None` for LNv1, which never carries it in any state --
        /// only LNv2 cancellations are reconciled.
        payment_hash: Option<sha256::Hash>,
        outcome: SendOutcome,
    },
    Receive {
        operation_id: OperationId,
        /// `None` when the amount was not recorded (LNv1 pre-upgrade).
        contract_amount: Option<Amount>,
        outcome: ReceiveOutcome,
    },
    Circuit {
        completion_operation_id: OperationId,
        receive_operation_id: OperationId,
        outcome: CircuitOutcome,
    },
}

pub fn classify_send(state: &SendSMState) -> SendOutcome {
    match state {
        SendSMState::Sending => SendOutcome::InFlight,
        SendSMState::Claimed(claimed) => SendOutcome::Claimed {
            cost: claimed.cost.clone(),
            outpoints: claimed.outpoints.clone(),
        },
        SendSMState::Claiming(claiming) => SendOutcome::ClaimedUnknownCost {
            outpoints: claiming.outpoints.clone(),
        },
        SendSMState::Cancelled(reason) => SendOutcome::Cancelled {
            after_dispatch: cancelled_after_dispatch(reason),
        },
    }
}

/// Whether the node may have been asked to pay before this cancellation.
/// Swap-rail failures net to zero on the target side and need no
/// reconciliation; only the Lightning rail can lie to the state machine.
fn cancelled_after_dispatch(reason: &Cancelled) -> bool {
    match reason {
        Cancelled::LightningRpcError(_) => true,
        // `DuplicatePayment` is reached only on the *success* branch of
        // `transition_send_payment`: the outbound leg settled, and a sibling
        // state machine had already claimed the payment image, so this one
        // forfeits its contract and the sibling's `Claimed` books the cost of
        // the single payment that was made. The node will report the payment
        // as settled, so reconciling this would find `Succeeded` and fabricate
        // a second `-(A + F)` loss for money that only left once.
        Cancelled::DuplicatePayment
        | Cancelled::InvoiceExpired
        | Cancelled::TimeoutTooClose
        | Cancelled::Underfunded
        | Cancelled::RegistrationError(_)
        | Cancelled::FinalizationError(_)
        | Cancelled::Rejected
        | Cancelled::Refunded
        | Cancelled::Failure => false,
    }
}

pub fn classify_receive(state: &ReceiveSMState) -> ReceiveOutcome {
    match state {
        ReceiveSMState::Funding => ReceiveOutcome::Funding,
        ReceiveSMState::Success(_) => ReceiveOutcome::Success,
        ReceiveSMState::Rejected(_) | ReceiveSMState::Refunding(_) => ReceiveOutcome::NotFunded,
        ReceiveSMState::Failure => ReceiveOutcome::Lost,
    }
}

pub fn classify_completion(state: &CompleteSMState) -> CircuitOutcome {
    match state {
        CompleteSMState::Pending | CompleteSMState::Completing(_) => CircuitOutcome::Pending,
        CompleteSMState::Completed => CircuitOutcome::Completed,
        CompleteSMState::CompletionFailed(_) => CircuitOutcome::Failed,
    }
}

pub fn forward_fact(sm: &GatewayClientStateMachinesV2) -> ForwardFact {
    match sm {
        GatewayClientStateMachinesV2::Send(send) => {
            let LightningInvoice::Bolt11(invoice) = &send.common.invoice;
            ForwardFact::Send {
                operation_id: send.common.operation_id,
                contract_amount: send.common.contract.amount,
                payment_hash: Some(*invoice.payment_hash()),
                outcome: classify_send(&send.state),
            }
        }
        GatewayClientStateMachinesV2::Receive(receive) => ForwardFact::Receive {
            operation_id: receive.common.operation_id,
            contract_amount: Some(receive.common.contract.commitment.amount),
            outcome: classify_receive(&receive.state),
        },
        GatewayClientStateMachinesV2::Complete(complete) => ForwardFact::Circuit {
            completion_operation_id: complete.common.operation_id,
            receive_operation_id: complete.common.operation_id,
            outcome: classify_completion(&complete.state),
        },
        GatewayClientStateMachinesV2::CircuitComplete(complete) => ForwardFact::Circuit {
            completion_operation_id: complete.common.operation_id,
            receive_operation_id: complete.common.receive_operation_id,
            outcome: classify_completion(&complete.state),
        },
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::hashes::{Hash as _, sha256};
    use fedimint_core::core::OperationId;
    use fedimint_core::secp256k1::{Keypair, PublicKey, SECP256K1, SecretKey};
    use fedimint_core::{Amount, TransactionId};
    use fedimint_lnv2_common::contracts::{IncomingContract, OutgoingContract, PaymentImage};
    use lightning_invoice::Bolt11Invoice;
    use tpe::{AggregatePublicKey, G1Affine};

    use super::*;
    use crate::complete_sm::{CompleteSMCommon, CompleteStateMachine};
    use crate::receive_sm::{ReceiveSMCommon, ReceiveStateMachine};
    use crate::send_sm::{Claimed, Claiming, SendSMCommon, SendStateMachine};
    use crate::{
        CircuitCompleteSMCommon, CircuitCompleteStateMachine, FinalReceiveState, IncomingCircuitKey,
    };

    /// A known-good BOLT11 invoice reused from
    /// `fedimint_core::encoding::btc::tests::bolt11_invoice_roundtrip`.
    const SEND_TEST_INVOICE: &str = "lnbc100p1psj9jhxdqud3jxktt5w46x7unfv9kz6mn0v3jsnp4q0d3p2sfluzdx45tqcs\
        h2pu5qc7lgq0xs578ngs6s0s68ua4h7cvspp5q6rmq35js88zp5dvwrv9m459tnk2zunwj5jalqtyxqulh0l\
        5gflssp5nf55ny5gcrfl30xuhzj3nphgj27rstekmr9fw3ny5989s300gyus9qyysgqcqpcrzjqw2sxwe993\
        h5pcm4dxzpvttgza8zhkqxpgffcrf5v25nwpr3cmfg7z54kuqq8rgqqqqqqqq2qqqqq9qq9qrzjqd0ylaqcl\
        j9424x9m8h2vcukcgnm6s56xfgu3j78zyqzhgs4hlpzvznlugqq9vsqqqqqqqlgqqqqqeqq9qrzjqwldmj9d\
        ha74df76zhx6l9we0vjdquygcdt3kssupehe64g6yyp5yz5rhuqqwccqqyqqqqlgqqqqjcqq9qrzjqf9e58a\
        guqr0rcun0ajlvmzq3ek63cw2w282gv3z5uupmuwvgjtq2z55qsqqg6qqqyqqqrtnqqqzq3cqygrzjqvphms\
        ywntrrhqjcraumvc4y6r8v4z5v593trte429v4hredj7ms5z52usqq9ngqqqqqqqlgqqqqqqgq9qrzjq2v0v\
        p62g49p7569ev48cmulecsxe59lvaw3wlxm7r982zxa9zzj7z5l0cqqxusqqyqqqqlgqqqqqzsqygarl9fh3\
        8s0gyuxjjgux34w75dnc6xp2l35j7es3jd4ugt3lu0xzre26yg5m7ke54n2d5sym4xcmxtl8238xxvw5h5h5\
        j5r6drg6k6zcqj0fcwg";

    /// A deterministic, non-zero secret key: valid for building dummy public
    /// keys and keypairs in tests without pulling in an RNG.
    fn dummy_secret_key(seed: u8) -> SecretKey {
        SecretKey::from_slice(&[seed; 32])
            .expect("32 repeated non-zero bytes are a valid secret key")
    }

    fn dummy_public_key(seed: u8) -> PublicKey {
        dummy_secret_key(seed).public_key(SECP256K1)
    }

    fn dummy_keypair(seed: u8) -> Keypair {
        Keypair::from_secret_key(SECP256K1, &dummy_secret_key(seed))
    }

    fn lightning_cost() -> OutboundCost {
        OutboundCost::Lightning {
            amount_sent: Amount::from_msats(1_000),
            fee: Some(Amount::from_msats(1)),
        }
    }

    #[test]
    fn every_send_state_has_a_defined_outcome() {
        assert_eq!(classify_send(&SendSMState::Sending), SendOutcome::InFlight);
        assert_eq!(
            classify_send(&SendSMState::Claimed(Claimed {
                preimage: [0; 32],
                outpoints: vec![],
                cost: lightning_cost(),
            })),
            SendOutcome::Claimed {
                cost: lightning_cost(),
                outpoints: vec![]
            }
        );
        assert_eq!(
            classify_send(&SendSMState::Claiming(Claiming {
                preimage: [0; 32],
                outpoints: vec![],
            })),
            SendOutcome::ClaimedUnknownCost { outpoints: vec![] }
        );
    }

    #[test]
    fn cancellations_after_a_lightning_dispatch_need_reconciliation() {
        let after = [Cancelled::LightningRpcError("x".into())];
        // `DuplicatePayment` belongs here even though the payment did go out:
        // the sibling machine that won the payment image books its cost, so
        // reconciling this one would double-count the loss.
        let before = [
            Cancelled::DuplicatePayment,
            Cancelled::InvoiceExpired,
            Cancelled::TimeoutTooClose,
            Cancelled::Underfunded,
            Cancelled::RegistrationError("x".into()),
            Cancelled::FinalizationError("x".into()),
            Cancelled::Rejected,
            Cancelled::Refunded,
            Cancelled::Failure,
        ];
        for reason in after {
            assert_eq!(
                classify_send(&SendSMState::Cancelled(reason)),
                SendOutcome::Cancelled {
                    after_dispatch: true
                }
            );
        }
        for reason in before {
            assert_eq!(
                classify_send(&SendSMState::Cancelled(reason)),
                SendOutcome::Cancelled {
                    after_dispatch: false
                }
            );
        }
    }

    #[test]
    fn every_receive_state_has_a_defined_outcome() {
        assert_eq!(
            classify_receive(&ReceiveSMState::Funding),
            ReceiveOutcome::Funding
        );
        assert_eq!(
            classify_receive(&ReceiveSMState::Success([0; 32])),
            ReceiveOutcome::Success
        );
        assert_eq!(
            classify_receive(&ReceiveSMState::Rejected("x".into())),
            ReceiveOutcome::NotFunded
        );
        assert_eq!(
            classify_receive(&ReceiveSMState::Refunding(vec![])),
            ReceiveOutcome::NotFunded
        );
        assert_eq!(
            classify_receive(&ReceiveSMState::Failure),
            ReceiveOutcome::Lost
        );
    }

    #[test]
    fn every_completion_state_has_a_defined_outcome() {
        assert_eq!(
            classify_completion(&CompleteSMState::Pending),
            CircuitOutcome::Pending
        );
        assert_eq!(
            classify_completion(&CompleteSMState::Completing(FinalReceiveState::Failure)),
            CircuitOutcome::Pending
        );
        assert_eq!(
            classify_completion(&CompleteSMState::Completed),
            CircuitOutcome::Completed
        );
        assert_eq!(
            classify_completion(&CompleteSMState::CompletionFailed("x".into())),
            CircuitOutcome::Failed
        );
    }

    #[test]
    fn legacy_and_circuit_completions_join_on_the_receive_operation() {
        let receive = OperationId([1; 32]);
        let completion = OperationId([2; 32]);
        let hash = sha256::Hash::hash(b"h");

        let legacy = GatewayClientStateMachinesV2::Complete(CompleteStateMachine {
            common: CompleteSMCommon {
                operation_id: receive,
                payment_hash: hash,
                incoming_chan_id: 1,
                htlc_id: 2,
            },
            state: CompleteSMState::Completed,
        });
        assert_eq!(
            forward_fact(&legacy),
            ForwardFact::Circuit {
                completion_operation_id: receive,
                receive_operation_id: receive,
                outcome: CircuitOutcome::Completed,
            }
        );

        let circuit = GatewayClientStateMachinesV2::CircuitComplete(CircuitCompleteStateMachine {
            common: CircuitCompleteSMCommon {
                operation_id: completion,
                receive_operation_id: receive,
                payment_hash: hash,
                circuit: IncomingCircuitKey {
                    incoming_chan_id: 1,
                    htlc_id: 2,
                },
            },
            state: CompleteSMState::CompletionFailed("x".into()),
        });
        assert_eq!(
            forward_fact(&circuit),
            ForwardFact::Circuit {
                completion_operation_id: completion,
                receive_operation_id: receive,
                outcome: CircuitOutcome::Failed,
            }
        );
    }

    #[test]
    fn send_fact_carries_contract_amount_and_payment_hash() {
        let invoice: Bolt11Invoice = SEND_TEST_INVOICE
            .parse()
            .expect("SEND_TEST_INVOICE is a known-good BOLT11 invoice");
        let contract_amount = Amount::from_msats(5_000);
        let contract = OutgoingContract {
            payment_image: PaymentImage::Hash(sha256::Hash::hash(b"send-test-preimage")),
            amount: contract_amount,
            expiration: u64::MAX,
            claim_pk: dummy_public_key(1),
            refund_pk: dummy_public_key(2),
            ephemeral_pk: dummy_public_key(3),
        };
        let operation_id = OperationId([9; 32]);
        let common = SendSMCommon {
            operation_id,
            outpoint: OutPoint {
                txid: TransactionId::all_zeros(),
                out_idx: 0,
            },
            contract,
            max_delay: 144,
            min_contract_amount: Amount::from_msats(0),
            invoice: LightningInvoice::Bolt11(invoice.clone()),
            claim_keypair: dummy_keypair(4),
        };

        let sending = GatewayClientStateMachinesV2::Send(SendStateMachine {
            common: common.clone(),
            state: SendSMState::Sending,
        });
        assert_eq!(
            forward_fact(&sending),
            ForwardFact::Send {
                operation_id,
                contract_amount,
                payment_hash: Some(*invoice.payment_hash()),
                outcome: SendOutcome::InFlight,
            }
        );

        // Swap the state (not the common) to prove `forward_fact` reads the
        // state for the outcome rather than deriving it from `common` alone.
        let outpoints = vec![OutPoint {
            txid: TransactionId::all_zeros(),
            out_idx: 1,
        }];
        let claimed = GatewayClientStateMachinesV2::Send(SendStateMachine {
            common,
            state: SendSMState::Claimed(Claimed {
                preimage: [0; 32],
                outpoints: outpoints.clone(),
                cost: lightning_cost(),
            }),
        });
        assert_eq!(
            forward_fact(&claimed),
            ForwardFact::Send {
                operation_id,
                contract_amount,
                payment_hash: Some(*invoice.payment_hash()),
                outcome: SendOutcome::Claimed {
                    cost: lightning_cost(),
                    outpoints,
                },
            }
        );
    }

    #[test]
    fn receive_fact_carries_the_funded_contract_amount() {
        let contract_amount = Amount::from_msats(7_000);
        let contract = IncomingContract::new(
            AggregatePublicKey(G1Affine::generator()),
            [11; 32],
            [12; 32],
            PaymentImage::Hash(sha256::Hash::hash(&[12; 32])),
            contract_amount,
            u64::MAX,
            dummy_public_key(5),
            dummy_public_key(6),
            dummy_public_key(7),
        );
        let operation_id = OperationId([10; 32]);
        let common = ReceiveSMCommon {
            operation_id,
            contract: contract.clone(),
            outpoint: OutPoint {
                txid: TransactionId::all_zeros(),
                out_idx: 0,
            },
            refund_keypair: dummy_keypair(8),
        };

        let funding = GatewayClientStateMachinesV2::Receive(ReceiveStateMachine {
            common,
            state: ReceiveSMState::Funding,
        });

        assert_eq!(
            forward_fact(&funding),
            ForwardFact::Receive {
                operation_id,
                contract_amount: Some(contract.commitment.amount),
                outcome: ReceiveOutcome::Funding,
            }
        );
    }
}
