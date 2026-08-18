use fedimint_ln_common::gateway_registry::{Lnv1RegistryEvidenceV1, Lnv1RegistryState};

use super::classify_empty_lnv1_states;

#[test]
fn empty_registry_state_requires_uniform_all_peer_evidence() {
    let no = Lnv1RegistryEvidenceV1::no_registrations();
    let expired = Lnv1RegistryEvidenceV1::registrations_expired();

    assert_eq!(
        classify_empty_lnv1_states(&[no.state(), no.state(), no.state(), no.state()])
            .expect("uniform absence is explicit"),
        Lnv1RegistryState::NoRegistrations
    );
    assert_eq!(
        classify_empty_lnv1_states(&[
            expired.state(),
            expired.state(),
            expired.state(),
            expired.state(),
        ])
        .expect("uniform expiry is explicit"),
        Lnv1RegistryState::RegistrationsExpired
    );
    assert!(
        classify_empty_lnv1_states(&[expired.state(), no.state(), no.state(), no.state()]).is_err()
    );
    assert!(
        classify_empty_lnv1_states(&[
            no.state(),
            expired.state(),
            expired.state(),
            expired.state(),
        ])
        .is_err()
    );
    assert!(classify_empty_lnv1_states(&[]).is_err());
}
