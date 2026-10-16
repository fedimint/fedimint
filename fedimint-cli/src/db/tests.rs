use fedimint_core::PeerId;

use super::StoredAdminCreds;

#[test]
fn stored_admin_creds_debug_redacts_auth() {
    let auth = "admin-password";
    let creds = StoredAdminCreds {
        peer_id: PeerId::from(1),
        auth: auth.to_owned(),
    };

    let debug = format!("{creds:?}");

    assert!(!debug.contains(auth));
    assert!(debug.contains(&format!("peer_id: {:?}", creds.peer_id)));
    assert!(debug.contains(r#"auth: "<redacted>""#));
}
