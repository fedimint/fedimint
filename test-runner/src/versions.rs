use std::cmp::Ordering;
use std::env;
use std::fmt::{self, Display, Formatter};
use std::str::FromStr;

use devimint::cmd;
use devimint::util::nix_binary_version_env_var_name;
use itertools::{Itertools as _, iproduct};
use tracing::info;

use crate::util::set_env;

/// The version at which LNv2 became stable
pub const LNV2_STABLE_VERSION: semver::Version = semver::Version::new(0, 7, 0);

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Version {
    Tagged(semver::Version),
    Current,
}

impl Display for Version {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Version::Tagged(version) => write!(f, "{version}"),
            Version::Current => write!(f, "current"),
        }
    }
}

impl FromStr for Version {
    type Err = anyhow::Error;

    fn from_str(version: &str) -> Result<Self, Self::Err> {
        if version == "current" {
            return Ok(Version::Current);
        }
        Ok(Version::Tagged(semver::Version::parse(version)?))
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (Version::Current, Version::Current) => Ordering::Equal,
            (Version::Tagged(_), Version::Current) => Ordering::Less,
            (Version::Current, Version::Tagged(_)) => Ordering::Greater,
            (Version::Tagged(v1), Version::Tagged(v2)) => v1.cmp_precedence(v2),
        }
    }
}

#[derive(Clone, Debug)]
/// Version for different commonents
pub struct ComponentVersions {
    pub fed: Version,
    pub client: Version,
    pub gateway: Version,
}

impl ComponentVersions {
    pub fn all_current() -> Self {
        Self {
            fed: Version::Current,
            client: Version::Current,
            gateway: Version::Current,
        }
    }
    pub fn is_all_current(&self) -> bool {
        self.fed == Version::Current
            && self.client == Version::Current
            && self.gateway == Version::Current
    }

    fn is_any_different(&self) -> bool {
        self.fed != self.client || self.fed != self.gateway || self.client != self.gateway
    }

    fn is_only_one_not_current(&self) -> bool {
        let current_count = [&self.fed, &self.client, &self.gateway]
            .into_iter()
            .filter(|v| **v == Version::Current)
            .count();
        current_count == 2
    }

    pub fn supports_lnv2(&self) -> bool {
        let lnv2_version = Version::Tagged(LNV2_STABLE_VERSION);
        lnv2_version <= self.fed && lnv2_version <= self.client && lnv2_version <= self.gateway
    }
}

/// Generate a version matrix from given previous versions
pub fn generate_backward_compat_version_matrix(
    previous_versions: Vec<semver::Version>,
    full: bool,
) -> Vec<ComponentVersions> {
    let mut result = Vec::new();
    let versions = previous_versions
        .into_iter()
        .map(Version::Tagged)
        .chain([Version::Current])
        .collect_vec();

    for (fed, client, gateway) in iproduct!(&versions, &versions, &versions) {
        let vm = ComponentVersions {
            fed: fed.clone(),
            client: client.clone(),
            gateway: gateway.clone(),
        };

        // The following example shows the difference between a full and partial matrix
        // using v0.2.1.
        //
        // Full:
        // v0.2.1  v0.2.1  current
        // v0.2.1  current v0.2.1
        // v0.2.1  current current
        // current v0.2.1  v0.2.1
        // current v0.2.1  current
        // current current v0.2.1
        //
        // Partial:
        // v0.2.1  current current
        // current v0.2.1  current
        // current current v0.2.1
        let include = if full {
            // Generates a matrix of every version combination except for all binaries on
            // the same version. Testing all binaries with the same version is redundant
            // since this was covered for that version's "current" release.

            // Question: should this make sure at least one is current?
            vm.is_any_different()
        } else {
            // Generates a matrix of every version combination where only one binary is not
            // "current".
            //
            // This is the default matrix generated in CI since testing only one binary on a
            // previous version will cover most of the backwards-incompatible
            // changes and materially increase the speed of CI.
            //
            // For additional context, see: https://github.com/fedimint/fedimint/pull/4389
            //
            vm.is_only_one_not_current()
        };

        if include {
            result.push(vm);
        }
    }

    result
}

/// Build binaries for previous version and sets env variables later used by
/// set_binary_version_base_executable
pub async fn build_previous_versions_with_nix(versions: &[semver::Version]) -> anyhow::Result<()> {
    for (binary, version) in iproduct!(
        ["fedimintd", "fedimint-cli", "gatewayd", "gateway-cli"],
        versions,
    ) {
        info!("Building {binary} {version} using nix");
        // TODO: should we run concurrency?
        let path = cmd!(
            "nix",
            "build",
            "github:fedimint/fedimint/v{version}#{binary}",
            "--no-link",
            "--print-out-paths"
        )
        .out_string()
        .await?;

        set_env(
            nix_binary_version_env_var_name(binary, version),
            format!("{path}/bin/{binary}"),
        );
    }
    Ok(())
}

/// Set env vars so devimint can find the correct binaries for the version.
pub fn set_binary_version_base_executable(binary: &str, version: &Version) {
    let Version::Tagged(version) = version else {
        return;
    };
    let path = env::var(nix_binary_version_env_var_name(binary, version))
        .expect("version binary must be set");
    set_env(
        format!(
            "FM_{}_BASE_EXECUTABLE",
            binary.replace("-", "_").to_uppercase()
        ),
        path,
    );
}
