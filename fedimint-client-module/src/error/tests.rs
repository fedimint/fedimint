use assert_matches::assert_matches;
use fedimint_core::Amount;
use fedimint_core::core::{ModuleKind, OperationId};
use fedimint_core::util::FmtCompact as _;

use super::{
    ClientModuleError, InsufficientBalanceError, OperationNotFoundError, TransactionSubmitError,
};

#[test]
fn other_keeps_the_error_it_wraps() {
    let operation_id = OperationId::new_random();
    let error = ClientModuleError::other(OperationNotFoundError { operation_id });

    assert_matches!(
        &error,
        ClientModuleError::Other(source)
            if source
                .downcast_ref::<OperationNotFoundError>()
                .is_some_and(|source| source.operation_id == operation_id)
    );
    assert_eq!(
        error.to_string(),
        OperationNotFoundError { operation_id }.to_string()
    );
}

#[test]
fn other_accepts_a_plain_message() {
    let error = ClientModuleError::other("The module gave up");

    assert_matches!(error, ClientModuleError::Other(_));
    assert_eq!(error.to_string(), "The module gave up");
}

#[test]
fn other_keeps_an_anyhow_chain_intact() {
    let error = ClientModuleError::other(anyhow::anyhow!("inner").context("outer"));

    assert_eq!(error.to_string(), "outer");
    assert_eq!(error.fmt_compact().to_string(), "outer: inner");
}

#[test]
fn an_insufficient_balance_fails_the_transaction_as_insufficient_funds() {
    let balance = InsufficientBalanceError {
        requested_amount: Amount::from_sats(2),
        total_amount: Amount::from_sats(1),
    };

    assert_matches!(
        TransactionSubmitError::from(ClientModuleError::from(balance)),
        TransactionSubmitError::InsufficientFunds(found) if found == balance
    );
}

#[test]
fn any_other_module_failure_fails_the_transaction_as_primary_module() {
    assert_matches!(
        TransactionSubmitError::from(ClientModuleError::other("The notes could not be read")),
        TransactionSubmitError::PrimaryModule(ClientModuleError::Other(_))
    );
    assert_matches!(
        TransactionSubmitError::from(ClientModuleError::Unsupported {
            kind: ModuleKind::from_static_str("dummy"),
            operation: "create_final_inputs_and_outputs",
        }),
        TransactionSubmitError::PrimaryModule(ClientModuleError::Unsupported { .. })
    );
}
