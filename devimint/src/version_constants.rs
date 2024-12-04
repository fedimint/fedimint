use std::sync::LazyLock;

use semver::Version;

pub static VERSION_0_3_0_ALPHA: LazyLock<Version> =
    LazyLock::new(|| Version::parse("0.3.0-alpha").expect("version is parsable"));
pub static VERSION_0_3_0: LazyLock<Version> =
    LazyLock::new(|| Version::parse("0.3.0").expect("version is parsable"));
pub static VERSION_0_4_0_ALPHA: LazyLock<Version> =
    LazyLock::new(|| Version::parse("0.4.0-alpha").expect("version is parsable"));
pub static VERSION_0_4_0: LazyLock<Version> =
    LazyLock::new(|| Version::parse("0.4.0").expect("version is parsable"));
pub static VERSION_0_5_0_ALPHA: LazyLock<Version> =
    LazyLock::new(|| Version::parse("0.5.0-alpha").expect("version is parsable"));
