//! LNv1 counterparts of `fedimint_gwv2_client::audit`, producing the same
//! `ForwardFact` so the gateway scores both protocols with one ledger.

use fedimint_core::Amount;
use fedimint_gwv2_client::audit::{CircuitOutcome, ForwardFact, ReceiveOutcome, SendOutcome};
use fedimint_ln_client::incoming::IncomingSmStates;

use crate::GatewayClientStateMachines;
use crate::complete::GatewayCompleteStates;
use crate::db::Lnv1IncomingAmounts;
use crate::pay::{GatewayPayStates, OutgoingPaymentErrorType};

pub fn classify_pay(state: &GatewayPayStates) -> SendOutcome {
    match state {
        GatewayPayStates::PayInvoice(_)
        | GatewayPayStates::WaitForSwapPreimage(_)
        | GatewayPayStates::CancelContract(_) => SendOutcome::InFlight,
        GatewayPayStates::ClaimOutgoingContract(_) => SendOutcome::PaidAwaitingClaim { cost: None },
        GatewayPayStates::ClaimOutgoingContractV2(claim) => SendOutcome::PaidAwaitingClaim {
            cost: Some(claim.cost.clone()),
        },
        GatewayPayStates::Preimage(out_points, _) => SendOutcome::ClaimedUnknownCost {
            outpoints: out_points.clone(),
        },
        GatewayPayStates::Claimed {
            out_points, cost, ..
        } => SendOutcome::Claimed {
            cost: cost.clone(),
            outpoints: out_points.clone(),
        },
        GatewayPayStates::OfferDoesNotExist(_) => SendOutcome::Cancelled {
            after_dispatch: false,
        },
        GatewayPayStates::Canceled { error, .. } => SendOutcome::Cancelled {
            after_dispatch: matches!(
                error.error_type,
                OutgoingPaymentErrorType::LightningPayError { .. }
            ),
        },
        // `Failed` is reached after a cancellation could not be submitted;
        // the node may have been asked to pay, so reconcile.
        GatewayPayStates::Failed { .. } => SendOutcome::Cancelled {
            after_dispatch: true,
        },
    }
}

pub fn classify_incoming(state: &IncomingSmStates) -> ReceiveOutcome {
    match state {
        IncomingSmStates::FundingOffer(_) | IncomingSmStates::DecryptingPreimage(_) => {
            ReceiveOutcome::Funding
        }
        IncomingSmStates::Preimage(_) => ReceiveOutcome::Success,
        IncomingSmStates::RefundSubmitted { .. } | IncomingSmStates::FundingFailed { .. } => {
            ReceiveOutcome::NotFunded
        }
        IncomingSmStates::Failure(_) => ReceiveOutcome::Lost,
    }
}

pub fn classify_complete(state: &GatewayCompleteStates) -> CircuitOutcome {
    match state {
        GatewayCompleteStates::WaitForPreimage(_) | GatewayCompleteStates::CompleteHtlc(_) => {
            CircuitOutcome::Pending
        }
        GatewayCompleteStates::HtlcFinished => CircuitOutcome::Completed,
        GatewayCompleteStates::Failure => CircuitOutcome::Failed,
    }
}

/// `amounts` is the record written at intercept time for receive and
/// complete operations; `None` marks pre-upgrade history.
pub fn forward_fact(
    sm: &GatewayClientStateMachines,
    amounts: Option<&Lnv1IncomingAmounts>,
) -> ForwardFact {
    match sm {
        GatewayClientStateMachines::Pay(pay) => {
            let contract_amount = match &pay.state {
                GatewayPayStates::ClaimOutgoingContract(claim) => claim.contract.amount,
                GatewayPayStates::ClaimOutgoingContractV2(claim) => claim.contract.amount,
                GatewayPayStates::CancelContract(cancel) => cancel.contract.amount,
                GatewayPayStates::Claimed {
                    contract_amount, ..
                } => *contract_amount,
                GatewayPayStates::PayInvoice(_)
                | GatewayPayStates::WaitForSwapPreimage(_)
                | GatewayPayStates::Preimage(..)
                | GatewayPayStates::OfferDoesNotExist(_)
                | GatewayPayStates::Canceled { .. }
                | GatewayPayStates::Failed { .. } => Amount::ZERO,
            };
            ForwardFact::Send {
                operation_id: pay.common.operation_id,
                contract_amount,
                payment_hash: None,
                outcome: classify_pay(&pay.state),
            }
        }
        GatewayClientStateMachines::Receive(receive) => ForwardFact::Receive {
            operation_id: receive.common.operation_id,
            contract_amount: amounts.map(|a| a.contract_amount),
            outcome: classify_incoming(&receive.state),
        },
        GatewayClientStateMachines::Complete(complete) => ForwardFact::Circuit {
            completion_operation_id: complete.common.operation_id,
            receive_operation_id: complete.common.operation_id,
            outcome: classify_complete(&complete.state),
        },
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::hashes::{Hash as _, sha256};
    use fedimint_core::Amount;
    use fedimint_core::config::FederationId;
    use fedimint_core::core::OperationId;
    use fedimint_core::secp256k1::{PublicKey, SECP256K1, SecretKey};
    use fedimint_gwv2_client::audit::{CircuitOutcome, ForwardFact, ReceiveOutcome, SendOutcome};
    use fedimint_ln_client::incoming::{
        FundingOfferState, IncomingSmCommon, IncomingSmError, IncomingSmStates,
        IncomingStateMachine,
    };
    use fedimint_ln_client::pay::{PayInvoicePayload, PaymentData};
    use fedimint_ln_common::contracts::outgoing::{OutgoingContract, OutgoingContractAccount};
    use fedimint_ln_common::contracts::{ContractId, IdentifiableContract, Preimage};
    use lightning_invoice::Bolt11Invoice;

    use super::*;
    use crate::complete::{
        CompleteHtlcState, GatewayCompleteCommon, GatewayCompleteStateMachine,
        GatewayCompleteStates, HtlcOutcome, WaitForPreimageState,
    };
    use crate::pay::tests_support::dummy_error;
    use crate::pay::{
        GatewayPayCancelContract, GatewayPayClaimOutgoingContract,
        GatewayPayClaimOutgoingContractV2, GatewayPayCommon, GatewayPayInvoice,
        GatewayPayStateMachine, GatewayPayStates, GatewayPayWaitForSwapPreimage,
        OutgoingPaymentError, OutgoingPaymentErrorType,
    };

    /// A known-good BOLT11 invoice reused from
    /// `fedimint_gwv2_client::audit::tests::SEND_TEST_INVOICE`.
    const TEST_INVOICE: &str = "lnbc100p1psj9jhxdqud3jxktt5w46x7unfv9kz6mn0v3jsnp4q0d3p2sfluzdx45tqcs\
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
    /// keys in tests without pulling in an RNG.
    fn dummy_public_key(seed: u8) -> PublicKey {
        SecretKey::from_slice(&[seed; 32])
            .expect("32 repeated non-zero bytes are a valid secret key")
            .public_key(SECP256K1)
    }

    fn dummy_outgoing_contract_account(amount: Amount) -> OutgoingContractAccount {
        OutgoingContractAccount {
            amount,
            contract: OutgoingContract {
                hash: sha256::Hash::hash(b"outgoing-preimage"),
                gateway_key: dummy_public_key(1),
                timelock: 100,
                user_key: dummy_public_key(2),
                cancelled: false,
            },
        }
    }

    fn dummy_lightning_cost() -> fedimint_lightning::OutboundCost {
        fedimint_lightning::OutboundCost::Lightning {
            amount_sent: Amount::from_msats(5),
            fee: Some(Amount::ZERO),
        }
    }

    #[test]
    fn terminal_pay_states_map_to_send_outcomes() {
        let contract_id = ContractId::from_raw_hash(sha256::Hash::hash(b"c"));
        assert_eq!(
            classify_pay(&GatewayPayStates::Preimage(vec![], Preimage([0; 32]))),
            SendOutcome::ClaimedUnknownCost { outpoints: vec![] }
        );
        assert_eq!(
            classify_pay(&GatewayPayStates::OfferDoesNotExist(contract_id)),
            SendOutcome::Cancelled {
                after_dispatch: false
            }
        );
        assert_eq!(
            classify_pay(&GatewayPayStates::Failed {
                error: dummy_error(),
                error_message: String::new(),
            }),
            SendOutcome::Cancelled {
                after_dispatch: true
            }
        );
        let cost = fedimint_lightning::OutboundCost::Lightning {
            amount_sent: Amount::from_msats(5),
            fee: Some(Amount::ZERO),
        };
        assert_eq!(
            classify_pay(&GatewayPayStates::Claimed {
                out_points: vec![],
                preimage: Preimage([0; 32]),
                contract_amount: Amount::from_msats(6),
                cost: cost.clone(),
            }),
            SendOutcome::Claimed {
                cost,
                outpoints: vec![]
            }
        );
    }

    #[test]
    fn cancelled_after_a_lightning_error_needs_reconciliation() {
        let contract_id = ContractId::from_raw_hash(sha256::Hash::hash(b"c"));
        let txid = fedimint_core::TransactionId::from_raw_hash(sha256::Hash::hash(b"t"));
        let ln_error = OutgoingPaymentError {
            error_type: OutgoingPaymentErrorType::LightningPayError {
                lightning_error: fedimint_lightning::LightningRpcError::FailedPayment {
                    failure_reason: "no route".into(),
                },
            },
            contract_id,
            contract: None,
        };
        assert_eq!(
            classify_pay(&GatewayPayStates::Canceled {
                txid,
                contract_id,
                error: ln_error
            }),
            SendOutcome::Cancelled {
                after_dispatch: true
            }
        );
        assert_eq!(
            classify_pay(&GatewayPayStates::Canceled {
                txid,
                contract_id,
                error: dummy_error()
            }),
            SendOutcome::Cancelled {
                after_dispatch: false
            }
        );
    }

    #[test]
    fn incoming_and_complete_states_map_to_outcomes() {
        assert_eq!(
            classify_incoming(&IncomingSmStates::Preimage(Preimage([0; 32]))),
            ReceiveOutcome::Success
        );
        assert_eq!(
            classify_incoming(&IncomingSmStates::FundingFailed {
                error: IncomingSmError::TimeoutFetchingOffer {
                    payment_hash: sha256::Hash::hash(b"h"),
                }
            }),
            ReceiveOutcome::NotFunded
        );
        assert_eq!(
            classify_incoming(&IncomingSmStates::Failure("x".into())),
            ReceiveOutcome::Lost
        );
        assert_eq!(
            classify_complete(&GatewayCompleteStates::HtlcFinished),
            CircuitOutcome::Completed
        );
        assert_eq!(
            classify_complete(&GatewayCompleteStates::Failure),
            CircuitOutcome::Failed
        );
    }

    #[test]
    fn pay_forward_fact_takes_contract_amount_from_the_claimed_state() {
        let operation_id = OperationId([7; 32]);
        let cost = fedimint_lightning::OutboundCost::Lightning {
            amount_sent: Amount::from_msats(5),
            fee: Some(Amount::ZERO),
        };
        let pay = GatewayClientStateMachines::Pay(GatewayPayStateMachine {
            common: GatewayPayCommon { operation_id },
            state: GatewayPayStates::Claimed {
                out_points: vec![],
                preimage: Preimage([0; 32]),
                contract_amount: Amount::from_msats(42),
                cost: cost.clone(),
            },
        });

        assert_eq!(
            forward_fact(&pay, None),
            ForwardFact::Send {
                operation_id,
                contract_amount: Amount::from_msats(42),
                payment_hash: None,
                outcome: SendOutcome::Claimed {
                    cost,
                    outpoints: vec![]
                },
            }
        );
    }

    #[test]
    fn complete_forward_fact_joins_on_the_common_operation_id() {
        let operation_id = OperationId([8; 32]);
        let complete = GatewayClientStateMachines::Complete(GatewayCompleteStateMachine {
            common: GatewayCompleteCommon {
                operation_id,
                payment_hash: sha256::Hash::hash(b"complete"),
                incoming_chan_id: 1,
                htlc_id: 2,
            },
            state: GatewayCompleteStates::HtlcFinished,
        });

        assert_eq!(
            forward_fact(&complete, None),
            ForwardFact::Circuit {
                completion_operation_id: operation_id,
                receive_operation_id: operation_id,
                outcome: CircuitOutcome::Completed,
            }
        );
    }

    #[test]
    fn in_flight_pay_states_map_to_send_outcome_in_flight() {
        let invoice: Bolt11Invoice = TEST_INVOICE
            .parse()
            .expect("TEST_INVOICE is a known-good BOLT11 invoice");
        let contract = dummy_outgoing_contract_account(Amount::from_msats(10));

        let pay_invoice = GatewayPayStates::PayInvoice(GatewayPayInvoice {
            pay_invoice_payload: PayInvoicePayload {
                federation_id: FederationId(sha256::Hash::hash(b"federation")),
                contract_id: contract.contract.contract_id(),
                payment_data: PaymentData::Invoice(invoice),
                preimage_auth: sha256::Hash::hash(b"preimage-auth"),
            },
        });
        assert_eq!(classify_pay(&pay_invoice), SendOutcome::InFlight);

        let wait_for_swap_preimage =
            GatewayPayStates::WaitForSwapPreimage(Box::new(GatewayPayWaitForSwapPreimage {
                contract: contract.clone(),
                federation_id: FederationId(sha256::Hash::hash(b"target-federation")),
                operation_id: OperationId([3; 32]),
            }));
        assert_eq!(classify_pay(&wait_for_swap_preimage), SendOutcome::InFlight);

        let cancel_contract =
            GatewayPayStates::CancelContract(Box::new(GatewayPayCancelContract {
                contract,
                error: dummy_error(),
            }));
        assert_eq!(classify_pay(&cancel_contract), SendOutcome::InFlight);
    }

    #[test]
    fn claim_outgoing_contract_states_carry_the_riskiest_cost_distinction() {
        let contract = dummy_outgoing_contract_account(Amount::from_msats(10));
        let preimage = Preimage([0; 32]);

        // Legacy claim: cost was never recorded.
        let legacy =
            GatewayPayStates::ClaimOutgoingContract(Box::new(GatewayPayClaimOutgoingContract {
                contract: contract.clone(),
                preimage: preimage.clone(),
            }));
        assert_eq!(
            classify_pay(&legacy),
            SendOutcome::PaidAwaitingClaim { cost: None }
        );

        // V2 claim: cost is known at the time the claim is submitted.
        let cost = dummy_lightning_cost();
        let v2 = GatewayPayStates::ClaimOutgoingContractV2(Box::new(
            GatewayPayClaimOutgoingContractV2 {
                contract,
                preimage,
                cost: cost.clone(),
            },
        ));
        assert_eq!(
            classify_pay(&v2),
            SendOutcome::PaidAwaitingClaim { cost: Some(cost) }
        );
    }

    #[test]
    fn funding_offer_state_maps_to_receive_outcome_funding() {
        // `DecryptingPreimage` shares this match arm but is not covered here:
        // its `txid` field is private to `fedimint-ln-client` and making it
        // visible would require a non-`pub(crate)` change in a crate outside
        // `fedimint-gw-client`, which is out of scope for this fix.
        let funding_offer = IncomingSmStates::FundingOffer(FundingOfferState {
            txid: fedimint_core::TransactionId::from_raw_hash(sha256::Hash::hash(b"funding-txid")),
        });
        assert_eq!(classify_incoming(&funding_offer), ReceiveOutcome::Funding);
    }

    #[test]
    fn refund_submitted_maps_to_receive_outcome_not_funded() {
        let refund_submitted = IncomingSmStates::RefundSubmitted {
            out_points: vec![],
            error: IncomingSmError::TimeoutFetchingOffer {
                payment_hash: sha256::Hash::hash(b"refund-payment-hash"),
            },
        };
        assert_eq!(
            classify_incoming(&refund_submitted),
            ReceiveOutcome::NotFunded
        );
    }

    #[test]
    fn pending_complete_states_map_to_circuit_outcome_pending() {
        assert_eq!(
            classify_complete(&GatewayCompleteStates::WaitForPreimage(
                WaitForPreimageState
            )),
            CircuitOutcome::Pending
        );
        assert_eq!(
            classify_complete(&GatewayCompleteStates::CompleteHtlc(CompleteHtlcState {
                outcome: HtlcOutcome::Success(Preimage([0; 32])),
            })),
            CircuitOutcome::Pending
        );
    }

    fn receive_state_machine(operation_id: OperationId) -> GatewayClientStateMachines {
        GatewayClientStateMachines::Receive(IncomingStateMachine {
            common: IncomingSmCommon {
                operation_id,
                contract_id: ContractId::from_raw_hash(sha256::Hash::hash(b"receive-contract")),
                payment_hash: sha256::Hash::hash(b"receive-payment-hash"),
            },
            state: IncomingSmStates::FundingOffer(FundingOfferState {
                txid: fedimint_core::TransactionId::from_raw_hash(sha256::Hash::hash(
                    b"receive-funding-txid",
                )),
            }),
        })
    }

    #[test]
    fn receive_forward_fact_carries_the_recorded_contract_amount() {
        let operation_id = OperationId([9; 32]);
        let sm = receive_state_machine(operation_id);
        let amounts = Lnv1IncomingAmounts {
            contract_amount: Amount::from_msats(11),
            incoming_amount: Amount::from_msats(10),
        };

        assert_eq!(
            forward_fact(&sm, Some(&amounts)),
            ForwardFact::Receive {
                operation_id,
                contract_amount: Some(Amount::from_msats(11)),
                outcome: ReceiveOutcome::Funding,
            }
        );
    }

    #[test]
    fn receive_forward_fact_has_no_contract_amount_without_a_recorded_amount() {
        let operation_id = OperationId([10; 32]);
        let sm = receive_state_machine(operation_id);

        assert_eq!(
            forward_fact(&sm, None),
            ForwardFact::Receive {
                operation_id,
                contract_amount: None,
                outcome: ReceiveOutcome::Funding,
            }
        );
    }
}
