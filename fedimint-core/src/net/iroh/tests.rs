use super::{DEFAULT_IROH_RELAYS, Url};

#[test]
fn default_iroh_relays_are_valid_urls() {
    for relay in DEFAULT_IROH_RELAYS {
        Url::parse(relay).expect("default Iroh relay URL is valid");
    }
}
