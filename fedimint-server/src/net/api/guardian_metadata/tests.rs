use fedimint_core::net::guardian_metadata::GuardianMetadata;

use super::{ensure_iroh_next_remains_available, reconcile_iroh_next_endpoint};

#[test]
fn iroh_next_advertisement_is_forward_only() {
    assert!(ensure_iroh_next_remains_available(None, None).is_ok());
    assert!(ensure_iroh_next_remains_available(None, Some("new")).is_ok());
    assert!(ensure_iroh_next_remains_available(Some("existing"), Some("existing")).is_ok());
    assert!(ensure_iroh_next_remains_available(Some("existing"), Some("new")).is_err());
    assert!(ensure_iroh_next_remains_available(Some("existing"), None).is_err());
}

#[test]
fn reconciliation_preserves_administrator_owned_metadata() {
    let api_urls = vec!["wss://guardian.example".parse().expect("valid URL")];
    let mut metadata = GuardianMetadata::new(api_urls.clone(), "pkarr-id".to_owned(), 42);

    assert!(
        reconcile_iroh_next_endpoint(&mut metadata, Some("iroh-id".to_owned()))
            .expect("first advertisement is allowed")
    );
    assert_eq!(metadata.api_urls, api_urls);
    assert_eq!(metadata.pkarr_id_z32, "pkarr-id");
    assert_eq!(metadata.timestamp_secs, 42);
    assert_eq!(metadata.iroh_next_endpoint.as_deref(), Some("iroh-id"));
    assert!(
        !reconcile_iroh_next_endpoint(&mut metadata, Some("iroh-id".to_owned()))
            .expect("unchanged advertisement is allowed")
    );
}
