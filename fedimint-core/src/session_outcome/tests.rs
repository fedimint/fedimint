use std::collections::BTreeMap;

use super::{SessionOutcome, SignedSessionOutcome};

#[test]
fn verify_rejects_empty_public_key_set() {
    let outcome = SignedSessionOutcome {
        session_outcome: SessionOutcome { items: vec![] },
        signatures: BTreeMap::new(),
    };

    assert!(!outcome.verify(&BTreeMap::new(), 0));
}
