use assert_matches::assert_matches;
use fedimint_core::core::OperationId;

use super::{ClientModuleError, OperationNotFoundError};

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
    assert_matches!(
        ClientModuleError::other("The module gave up"),
        ClientModuleError::Other(_)
    );
}
