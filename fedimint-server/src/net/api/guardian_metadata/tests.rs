use fedimint_core::net::guardian_metadata::GuardianMetadata;

use super::clear_iroh_next_endpoint;

#[test]
fn clearing_the_iroh_next_endpoint_preserves_administrator_owned_metadata() {
    let api_urls = vec!["wss://guardian.example".parse().expect("valid URL")];
    let mut metadata = GuardianMetadata::new(api_urls.clone(), "pkarr-id".to_owned(), 42)
        .with_iroh_next_endpoint("iroh-id".to_owned());

    assert!(clear_iroh_next_endpoint(&mut metadata));
    assert_eq!(metadata.api_urls, api_urls);
    assert_eq!(metadata.pkarr_id_z32, "pkarr-id");
    assert_eq!(metadata.timestamp_secs, 42);
    assert_eq!(metadata.iroh_next_endpoint, None);
    assert!(!clear_iroh_next_endpoint(&mut metadata));
}
