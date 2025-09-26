//! We want to provide our own infrastructure to be independent of n0, but for
//! now we don't use the discovery part of it pending figuring out some
//! performance regressions.

/// The Iroh/Pkarr DNS server hosted by Fedimint project
pub const FM_IROH_DNS_FEDIMINT_PROD: [&str; 0] = [
    // "https://dns.irohdns-eu-01.dev.fedimint.org/pkarr",
    // "https://dns.irohdns-us-01.dev.fedimint.org/pkarr",
];

/// The Iroh relays hosted by Fedimint project
pub const FM_IROH_RELAYS_FEDIMINT_PROD: [&str; 2] = [
    "https://irohrelay-eu-01.dev.fedimint.org",
    "https://irohrelay-us-01.dev.fedimint.org",
];
