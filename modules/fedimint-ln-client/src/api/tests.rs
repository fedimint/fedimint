use fedimint_ln_common::gateway_registry::{Lnv1RegistrySnapshotV1, Lnv1RegistryState};

use super::classify_empty_lnv1_states;

#[test]
fn empty_registry_state_requires_all_guardians_to_agree() {
    let no = Lnv1RegistrySnapshotV1::no_registrations();
    let expired = Lnv1RegistrySnapshotV1::registrations_expired();

    assert_eq!(
        classify_empty_lnv1_states(&[no.state(), no.state(), no.state(), no.state()])
            .expect("all guardians reported no records"),
        Lnv1RegistryState::NoRegistrations
    );
    assert_eq!(
        classify_empty_lnv1_states(&[
            expired.state(),
            expired.state(),
            expired.state(),
            expired.state(),
        ])
        .expect("all guardians reported expired records"),
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
