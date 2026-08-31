use semver::{BuildMetadata, Prerelease, Version};
use serde::{Serialize, Serializer};

use crate::encoding::{Decodable, DecodeError, Encodable};
use crate::module::registry::ModuleDecoderRegistry;

/// Get the  cargo package version of `fedimint-core`
pub fn cargo_pkg() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Get the `x.y.z` cargo release version of `fedimint-core`.
pub fn cargo_pkg_release() -> &'static str {
    release_version(cargo_pkg())
}

/// Return only the `x.y.z` release component of a cargo package version.
pub fn release_version(version: &str) -> &str {
    version
        .split(['-', '+'])
        .next()
        .expect("split always returns at least one item")
}

/// A validated Fedimint version projected for DKG compatibility.
///
/// DKG ignores patch and pre-release components, but requires exact equality
/// of the major version, minor version, and optional vendor string. The vendor
/// string is encoded as SemVer build metadata.
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct DkgVersion {
    /// The normalized semantic release version sent in setup codes.
    setup_code_version: Box<Version>,
}

/// The semantic identity used to decide whether two guardians can run DKG.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DkgVersionCompatibility {
    /// The Fedimint major version.
    major: u64,
    /// The Fedimint minor version.
    minor: u64,
    /// The exact optional vendor identity.
    vendor: Option<BuildMetadata>,
}

impl DkgVersion {
    /// Parse a semantic version and derive its setup-code and DKG forms.
    pub fn parse(version: &str) -> Result<Self, semver::Error> {
        let mut setup_code_version = Version::parse(version)?;
        setup_code_version.pre = Prerelease::EMPTY;

        Ok(Self {
            setup_code_version: Box::new(setup_code_version),
        })
    }

    /// Return the normalized release version stored in a setup code.
    pub fn setup_code_version(&self) -> &Version {
        &self.setup_code_version
    }

    /// Return the major.minor and exact optional vendor identity for DKG.
    pub fn compatibility_version(&self) -> DkgVersionCompatibility {
        DkgVersionCompatibility {
            major: self.setup_code_version.major,
            minor: self.setup_code_version.minor,
            vendor: (!self.setup_code_version.build.is_empty())
                .then(|| self.setup_code_version.build.clone()),
        }
    }
}

impl std::fmt::Display for DkgVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.setup_code_version.fmt(f)
    }
}

impl Serialize for DkgVersion {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(self)
    }
}

impl Encodable for DkgVersion {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        self.to_string().consensus_encode(writer)
    }
}

impl Decodable for DkgVersion {
    fn consensus_decode_partial_from_finite_reader<D: std::io::Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let version = String::consensus_decode_partial_from_finite_reader(d, modules)?;
        Self::parse(&version).map_err(DecodeError::from_err)
    }
}

impl std::fmt::Display for DkgVersionCompatibility {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)?;
        if let Some(vendor) = &self.vendor {
            write!(f, "+{vendor}")?;
        }
        Ok(())
    }
}

/// Get the git hash version of `fedimint-core`
///
/// Note, in certain situations this not be accurate (eg. might be all `0`s).
///
/// The return value was injected via `fedimint-build` crate at the compile
/// time.
pub fn git_hash() -> &'static str {
    option_env!("FEDIMINT_BUILD_CODE_VERSION").unwrap_or("0000000000000000000000000000000000000001")
}

/// Returns the version hash if it is meaningful (i.e. not all zeros, which
/// `fedimint-build` substitutes when no git information is available).
pub fn non_zero_version_hash(hash: &str) -> Option<&str> {
    if hash.bytes().all(|b| b == b'0') {
        None
    } else {
        Some(hash)
    }
}

#[cfg(test)]
mod tests;
