use std::sync::LazyLock;

use semver::Version;

pub static VERSION_0_6_0_ALPHA: LazyLock<Version> =
    LazyLock::new(|| Version::parse("0.6.0-alpha").expect("version is parsable"));
pub static VERSION_0_7_0_ALPHA: LazyLock<Version> =
    LazyLock::new(|| Version::parse("0.7.0-alpha").expect("version is parsable"));
