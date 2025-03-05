use std::collections::BTreeMap;

use fedimint_core::config::{ClientConfig, GlobalClientConfig};

use crate::module::CoreConsensusVersion;

#[test]
fn test_dcode_meta() {
    let config = ClientConfig {
        global: GlobalClientConfig {
            api_endpoints: BTreeMap::new(),
            broadcast_public_keys: None,
            consensus_version: CoreConsensusVersion { major: 0, minor: 0 },
            meta: vec![
                ("foo".to_string(), "bar".to_string()),
                ("baz".to_string(), "\"bam\"".to_string()),
                ("arr".to_string(), "[\"1\", \"2\"]".to_string()),
            ]
            .into_iter()
            .collect(),
        },
        modules: BTreeMap::new(),
    };

    assert_eq!(
        config
            .meta::<String>("foo")
            .expect("parsing legacy string failed"),
        Some("bar".to_string())
    );
    assert_eq!(
        config.meta::<String>("baz").expect("parsing string failed"),
        Some("bam".to_string())
    );
    assert_eq!(
        config
            .meta::<Vec<String>>("arr")
            .expect("parsing array failed"),
        Some(vec!["1".to_string(), "2".to_string()])
    );

    assert!(config.meta::<Vec<String>>("foo").is_err());
    assert!(config.meta::<Vec<String>>("baz").is_err());
    assert_eq!(
        config
            .meta::<String>("arr")
            .expect("parsing via legacy fallback failed"),
        Some("[\"1\", \"2\"]".to_string())
    );
}
