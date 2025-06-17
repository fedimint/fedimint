use std::sync::LazyLock;

use semver::Version;

pub static VERSION_0_5_0_ALPHA: LazyLock<Version> =
    LazyLock::new(|| Version::parse("0.5.0-alpha").expect("version is parsable"));
pub static VERSION_0_6_0_ALPHA: LazyLock<Version> =
    LazyLock::new(|| Version::parse("0.6.0-alpha").expect("version is parsable"));
pub static VERSION_0_7_0_ALPHA: LazyLock<Version> =
    LazyLock::new(|| Version::parse("0.7.0-alpha").expect("version is parsable"));
pub static VERSION_0_7_2: LazyLock<Version> =
    LazyLock::new(|| Version::parse("0.7.2").expect("version is parsable"));
pub static VERSION_0_8_0_ALPHA: LazyLock<Version> =
    LazyLock::new(|| Version::parse("0.8.0-alpha").expect("version is parsable"));
