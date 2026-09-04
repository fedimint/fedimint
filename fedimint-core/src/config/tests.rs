use std::collections::BTreeMap;

use fedimint_core::config::{ClientConfig, GlobalClientConfig};

use crate::module::CoreConsensusVersion;

fn test_config() -> ClientConfig {
    ClientConfig {
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
    }
}

#[test]
fn test_dcode_meta() {
    let config = test_config();

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

#[test]
fn module_lookups_return_typed_errors() {
    use fedimint_core::core::ModuleKind;

    use crate::config::ModuleConfigError;

    let config = test_config();

    assert!(matches!(
        config.get_module_cfg(7),
        Err(ModuleConfigError::ModuleNotFound { id: 7 })
    ));
    assert!(matches!(
        config.get_first_module_by_kind_cfg(ModuleKind::from_static_str("nope")),
        Err(ModuleConfigError::KindNotFound { kind }) if kind.as_str() == "nope"
    ));
}

#[test]
fn meta_decode_failure_names_the_key() {
    use crate::config::ModuleConfigError;

    let config = test_config();

    // "foo" holds the legacy unquoted string "bar", which is not a number.
    assert!(matches!(
        config.meta::<u32>("foo"),
        Err(ModuleConfigError::Meta { key, .. }) if key == "foo"
    ));
}

#[test]
fn cast_reports_an_undecoded_config() {
    use fedimint_core::core::ModuleKind;

    use crate::config::{ClientModuleConfig, ModuleConfigError};
    use crate::encoding::DynRawFallback;
    use crate::module::ModuleConsensusVersion;

    let cfg = ClientModuleConfig {
        kind: ModuleKind::from_static_str("test"),
        version: ModuleConsensusVersion::new(0, 0),
        config: DynRawFallback::Raw {
            module_instance_id: 3,
            raw: vec![],
        },
    };

    assert!(matches!(
        cfg.cast::<()>(),
        Err(ModuleConfigError::NotDecoded { id: 3, kind }) if kind.as_str() == "test"
    ));
}

#[test]
fn get_module_reports_an_undecoded_config() {
    use fedimint_core::core::ModuleKind;

    use crate::config::{ClientModuleConfig, ModuleConfigError};
    use crate::encoding::DynRawFallback;
    use crate::module::ModuleConsensusVersion;

    let mut config = test_config();
    config.modules.insert(
        3,
        ClientModuleConfig {
            kind: ModuleKind::from_static_str("test"),
            version: ModuleConsensusVersion::new(0, 0),
            config: DynRawFallback::Raw {
                module_instance_id: 3,
                raw: vec![],
            },
        },
    );

    assert!(matches!(
        config.get_module::<()>(3),
        Err(ModuleConfigError::NotDecoded { id: 3, kind }) if kind.as_str() == "test"
    ));
}

#[test]
fn cast_to_the_wrong_type_names_kind_and_type() {
    use std::fmt;

    use fedimint_core::core::{DynClientConfig, ModuleInstanceId, ModuleKind};
    use serde::{Deserialize, Serialize};

    use crate::config::{ClientModuleConfig, ModuleConfigError};
    use crate::encoding::{Decodable, Encodable};
    use crate::module::ModuleConsensusVersion;

    #[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
    struct TestClientConfig {
        value: u64,
    }

    impl fmt::Display for TestClientConfig {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "TestClientConfig({})", self.value)
        }
    }

    impl fedimint_core::core::ClientConfig for TestClientConfig {
        const KIND: ModuleKind = ModuleKind::from_static_str("test");
    }

    impl fedimint_core::core::IntoDynInstance for TestClientConfig {
        type DynType = DynClientConfig;

        fn into_dyn(self, instance_id: ModuleInstanceId) -> Self::DynType {
            DynClientConfig::from_typed(instance_id, self)
        }
    }

    let cfg = ClientModuleConfig {
        kind: ModuleKind::from_static_str("test"),
        version: ModuleConsensusVersion::new(0, 0),
        config: DynClientConfig::from_typed(3, TestClientConfig { value: 1 }).into(),
    };

    assert!(cfg.cast::<TestClientConfig>().is_ok());

    let err = cfg.cast::<u64>().expect_err("the config is not a u64");

    assert!(matches!(
        &err,
        ModuleConfigError::WrongType { kind, expected }
            if kind.as_str() == "test" && *expected == "u64"
    ));
    assert_eq!(
        err.to_string(),
        "Client module config of kind test is not a u64"
    );
}

#[cfg(unix)]
#[test]
fn load_from_file_reports_a_read_failure_as_io() {
    use crate::config::{ConfigFileError, load_from_file};

    // A directory opens successfully but fails to read with `EISDIR`.
    let dir = tempfile::tempdir().expect("creating a temporary directory failed");

    assert!(matches!(
        load_from_file::<serde_json::Value>(dir.path()),
        Err(ConfigFileError::Io { path, .. }) if path == dir.path()
    ));
}

#[test]
fn load_from_file_reports_invalid_json() {
    use std::io::Write;

    use crate::config::{ConfigFileError, load_from_file};

    let mut file = tempfile::NamedTempFile::new().expect("creating a temporary file failed");
    file.write_all(b"{ not json")
        .expect("writing the temporary file failed");

    assert!(matches!(
        load_from_file::<serde_json::Value>(file.path()),
        Err(ConfigFileError::Json { path, .. }) if path == file.path()
    ));
}

#[test]
fn load_from_file_reads_valid_json() {
    use std::io::Write;

    use crate::config::load_from_file;

    let mut file = tempfile::NamedTempFile::new().expect("creating a temporary file failed");
    file.write_all(br#"{"answer": 42}"#)
        .expect("writing the temporary file failed");

    assert_eq!(
        load_from_file::<serde_json::Value>(file.path()).expect("the file holds valid JSON"),
        serde_json::json!({ "answer": 42 })
    );
}

#[test]
fn dkg_message_deserialize_reports_the_whole_decode_chain() {
    use crate::config::DkgMessageG1;
    use crate::encoding::Decodable;
    use crate::module::registry::ModuleDecoderRegistry;
    use crate::util::FmtCompact as _;

    // Variant 1 (`Commitment`) whose one payload byte announces a one-element
    // vector and then ends, so the reader runs out of input inside the variant
    // rather than on the first byte.
    let hex = "010101";
    let expected = DkgMessageG1::consensus_decode_hex(hex, &ModuleDecoderRegistry::default())
        .expect_err("payload is truncated");
    assert_ne!(
        expected.fmt_compact().to_string(),
        expected.to_string(),
        "the decode error has more than one layer, and the message shows all of them"
    );

    let err = serde_json::from_str::<DkgMessageG1>(&format!("\"{hex}\""))
        .expect_err("payload is truncated");
    assert!(
        err.to_string()
            .starts_with(&expected.fmt_compact().to_string()),
        "{err}"
    );
}
