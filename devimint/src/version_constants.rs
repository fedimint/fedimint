use std::env;
use std::sync::LazyLock;

use semver::{BuildMetadata, Version};

use crate::envs::FM_EXPECTED_FEDIMINTD_VENDOR_ENV;

/// Add the exact expected vendor identity to a fedimintd release version.
pub fn version_with_vendor(mut version: Version, vendor: Option<&str>) -> anyhow::Result<Version> {
    version.build = match vendor {
        Some(vendor) => {
            anyhow::ensure!(!vendor.is_empty(), "Fedimintd vendor must not be empty");
            BuildMetadata::new(vendor)?
        }
        None => BuildMetadata::EMPTY,
    };
    Ok(version)
}

/// Check a reported fedimintd version against this devimint invocation.
pub fn ensure_expected_fedimintd_version(
    reported_version: &str,
    version: Version,
) -> anyhow::Result<()> {
    let expected_vendor = match env::var(FM_EXPECTED_FEDIMINTD_VENDOR_ENV) {
        Ok(vendor) => Some(vendor),
        Err(env::VarError::NotPresent) => None,
        Err(error) => return Err(error.into()),
    };
    let expected_version = version_with_vendor(version, expected_vendor.as_deref())?;
    let reported_version = Version::parse(reported_version)?;

    anyhow::ensure!(
        reported_version == expected_version,
        "Fedimintd reported version {reported_version}, expected {expected_version}"
    );
    Ok(())
}

pub static VERSION_0_10_0_ALPHA: LazyLock<Version> =
    LazyLock::new(|| Version::parse("0.10.0-alpha").expect("version is parsable"));
pub static VERSION_0_11_0_ALPHA: LazyLock<Version> =
    LazyLock::new(|| Version::parse("0.11.0-alpha").expect("version is parsable"));
pub static VERSION_0_12_0_ALPHA: LazyLock<Version> =
    LazyLock::new(|| Version::parse("0.12.0-alpha").expect("version is parsable"));
pub static VERSION_0_13_0_ALPHA: LazyLock<Version> =
    LazyLock::new(|| Version::parse("0.13.0-alpha").expect("version is parsable"));

#[cfg(test)]
mod tests;
