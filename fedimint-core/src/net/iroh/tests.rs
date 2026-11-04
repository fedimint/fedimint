use super::{DEFAULT_IROH_RELAYS, DEFAULT_IROH_V1_RELAYS, Url};

#[test]
fn default_iroh_relays_are_valid_urls() {
    for relay in DEFAULT_IROH_RELAYS
        .into_iter()
        .chain(DEFAULT_IROH_V1_RELAYS)
    {
        Url::parse(relay).expect("default Iroh relay URL is valid");
    }
}

#[test]
fn default_iroh_relay_lists_are_disjoint() {
    for relay in DEFAULT_IROH_V1_RELAYS {
        assert!(
            !DEFAULT_IROH_RELAYS.contains(&relay),
            "{relay} is listed as both an Iroh 0.35 and an Iroh 1.0 relay"
        );
    }
}
