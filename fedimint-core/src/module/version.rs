//! Fedimint consensus and API versioning.
//!
//! ## Introduction
//!
//! Fedimint federations are expected to last and serve over time diverse set of
//! clients running on various devices and platforms with different
//! versions of the client software. To ensure broad interoperability core
//! Fedimint logic and modules use consensus and API version scheme.
//!
//! ## Definitions
//!
//! * Fedimint *component* - either a core Fedimint logic or one of the modules
//!
//! ## Consensus versions
//!
//! By definition all instances of a given component on every peer inside a
//! Federation must be running with the same consensus version at the same time.
//!
//! Each component in the Federation can only ever be in one consensus version.
//! The set of all consensus versions of each component is a part of consensus
//! config that is identical for all peers.
//!
//! The code implementing given component can however support multiple consensus
//! versions at the same time, making it possible to use the same code for
//! diverse set of Federations created at different times. The consensus
//! version to run with is passed to the code during initialization.
//!
//! The client side components need track consensus versions of each Federation
//! they use and be able to handle the currently running version of it.
//!
//! [`CoreConsensusVersion`] and [`ModuleConsensusVersion`] are used for
//! consensus versioning.
//!
//! ## API versions
//!
//! Unlike consensus version which has to be single and identical across
//! Federation, both server and client side components can advertise
//! simultaneous support for multiple API versions. This is the main mechanism
//! to ensure interoperability in the face of hard to control and predict
//! software changes across all the involved software.
//!
//! Each peer in the Federation and each client can update the Fedimint software
//! at their own pace without coordinating API changes.
//!
//! Each client is expected to survey Federation API support and discover the
//! API version to use for each component.
//!
//! Notably the current consensus version of a software component is considered
//! a prefix to the API version it advertises.
//!
//! Software components implementations are expected to provide a good multi-API
//! support to ensure clients and Federations can always find common API
//! versions to use.
//!
//! [`ApiVersion`] and [`MultiApiVersion`] is used for API versioning.
use std::collections::BTreeMap;
use std::{cmp, result};

use serde::{Deserialize, Serialize};

use crate::core::{ModuleInstanceId, ModuleKind};
use crate::db::DatabaseVersion;
use crate::encoding::{Decodable, Encodable};

/// Consensus version of a core server
///
/// Breaking changes in the Fedimint's core consensus require incrementing it.
///
/// See [`ModuleConsensusVersion`] for more details on how it interacts with
/// module's consensus.
#[derive(Debug, Copy, Clone, Serialize, Deserialize, Encodable, Decodable, PartialEq, Eq)]
pub struct CoreConsensusVersion {
    pub major: u32,
    pub minor: u32,
}

impl CoreConsensusVersion {
    pub const fn new(major: u32, minor: u32) -> Self {
        Self { major, minor }
    }
}

/// Globally declared core consensus version
pub const CORE_CONSENSUS_VERSION: CoreConsensusVersion = CoreConsensusVersion::new(2, 0);

/// Consensus version of a specific module instance
///
/// Any breaking change to the module's consensus rules require incrementing the
/// major part of it.
///
/// Any backwards-compatible changes with regards to clients require
/// incrementing the minor part of it. Backwards compatible changes will
/// typically be introducing new input/output/consensus item variants that old
/// clients won't understand but can safely ignore while new clients can use new
/// functionality. It's akin to soft forks in Bitcoin.
///
/// A module instance can run only in one consensus version, which must be the
/// same (both major and minor) across all corresponding instances on other
/// nodes of the federation.
///
/// When [`CoreConsensusVersion`] changes, this can but is not requires to be
/// a breaking change for each module's [`ModuleConsensusVersion`].
///
/// For many modules it might be preferable to implement a new
/// [`fedimint_core::core::ModuleKind`] "versions" (to be implemented at the
/// time of writing this comment), and by running two instances of the module at
/// the same time (each of different `ModuleKind` version), allow users to
/// slowly migrate to a new one. This avoids complex and error-prone server-side
/// consensus-migration logic.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize, Encodable, Decodable)]
pub struct ModuleConsensusVersion {
    pub major: u32,
    pub minor: u32,
}

impl ModuleConsensusVersion {
    pub const fn new(major: u32, minor: u32) -> Self {
        Self { major, minor }
    }
}

/// Api version supported by a core server or a client/server module at a given
/// [`ModuleConsensusVersion`].
///
/// Changing [`ModuleConsensusVersion`] implies resetting the api versioning.
///
/// For a client and server to be able to communicate with each other:
///
/// * The client needs API version support for the [`ModuleConsensusVersion`]
///   that the server is currently running with.
/// * Within that [`ModuleConsensusVersion`] during handshake negotiation
///   process client and server must find at least one `Api::major` version
///   where client's `minor` is lower or equal server's `major` version.
///
/// A practical module implementation needs to implement large range of version
/// backward compatibility on both client and server side to accommodate end
/// user client devices receiving updates at a pace hard to control, and
/// technical and coordination challenges of upgrading servers.
#[derive(Debug, Copy, Clone, Serialize, Deserialize, PartialEq, Eq, Decodable, Encodable)]
pub struct ApiVersion {
    /// Major API version
    ///
    /// Each time [`ModuleConsensusVersion`] is incremented, this number (and
    /// `minor` number as well) should be reset to `0`.
    ///
    /// Should be incremented each time the API was changed in a
    /// backward-incompatible ways (while resetting `minor` to `0`).
    pub major: u32,
    /// Minor API version
    ///
    /// * For clients this means *minimum* supported minor version of the
    ///   `major` version required by client implementation
    /// * For servers this means *maximum* supported minor version of the
    ///   `major` version implemented by the server implementation
    pub minor: u32,
}

impl ApiVersion {
    pub const fn new(major: u32, minor: u32) -> Self {
        Self { major, minor }
    }
}

/// ```
/// use fedimint_core::module::ApiVersion;
/// assert!(ApiVersion { major: 3, minor: 3 } < ApiVersion { major: 4, minor: 0 });
/// assert!(ApiVersion { major: 3, minor: 3 } < ApiVersion { major: 3, minor: 5 });
/// assert!(ApiVersion { major: 3, minor: 3 } == ApiVersion { major: 3, minor: 3 });
/// ```
impl cmp::PartialOrd for ApiVersion {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl cmp::Ord for ApiVersion {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.major
            .cmp(&other.major)
            .then(self.minor.cmp(&other.minor))
    }
}

/// Multiple, disjoint, minimum required or maximum supported, [`ApiVersion`]s.
///
/// If a given component can (potentially) support multiple different (distinct
/// major number), of an API, this type is used to express it.
///
/// All [`ApiVersion`] values are in the context of the current consensus
/// version for the component in question.
///
/// Each element must have a distinct major api number, and means
/// either minimum required API version of this major number (for the client),
/// or maximum supported version of this major number (for the server).
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Default, Encodable, Decodable)]
pub struct MultiApiVersion(Vec<ApiVersion>);

impl MultiApiVersion {
    pub fn new() -> Self {
        Self::default()
    }

    /// Verify the invariant: sorted by unique major numbers
    fn is_consistent(&self) -> bool {
        self.0
            .iter()
            .fold((None, true), |(prev, is_sorted), next| {
                (
                    Some(*next),
                    is_sorted && prev.map_or(true, |prev| prev.major < next.major),
                )
            })
            .1
    }

    fn iter(&self) -> MultiApiVersionIter {
        MultiApiVersionIter(self.0.iter())
    }

    pub fn try_from_iter<T: IntoIterator<Item = ApiVersion>>(
        iter: T,
    ) -> result::Result<Self, ApiVersion> {
        Result::from_iter(iter)
    }

    /// Insert `version` to the list of supported APIs
    ///
    /// Returns `Ok` if no existing element with the same `major` version was
    /// found and new `version` was successfully inserted. Returns `Err` if
    /// an existing element with the same `major` version was found, to allow
    /// modifying its `minor` number. This is useful when merging required /
    /// supported version sequences with each other.
    fn try_insert(&mut self, version: ApiVersion) -> result::Result<(), &mut u32> {
        let ret = match self
            .0
            .binary_search_by_key(&version.major, |version| version.major)
        {
            Ok(found_idx) => Err(self
                .0
                .get_mut(found_idx)
                .map(|v| &mut v.minor)
                .expect("element must exist - just checked")),
            Err(insert_idx) => {
                self.0.insert(insert_idx, version);
                Ok(())
            }
        };

        ret
    }

    pub(crate) fn get_by_major(&self, major: u32) -> Option<ApiVersion> {
        self.0
            .binary_search_by_key(&major, |version| version.major)
            .ok()
            .map(|index| {
                self.0
                    .get(index)
                    .copied()
                    .expect("Must exist because binary_search_by_key told us so")
            })
    }
}

impl<'de> Deserialize<'de> for MultiApiVersion {
    fn deserialize<D>(deserializer: D) -> result::Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        use serde::de::Error;

        let inner = Vec::<ApiVersion>::deserialize(deserializer)?;

        let ret = Self(inner);

        if !ret.is_consistent() {
            return Err(D::Error::custom(
                "Invalid MultiApiVersion value: inconsistent",
            ));
        }

        Ok(ret)
    }
}

pub struct MultiApiVersionIter<'a>(std::slice::Iter<'a, ApiVersion>);

impl<'a> Iterator for MultiApiVersionIter<'a> {
    type Item = ApiVersion;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().copied()
    }
}

impl<'a> IntoIterator for &'a MultiApiVersion {
    type Item = ApiVersion;

    type IntoIter = MultiApiVersionIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl FromIterator<ApiVersion> for Result<MultiApiVersion, ApiVersion> {
    fn from_iter<T: IntoIterator<Item = ApiVersion>>(iter: T) -> Self {
        let mut s = MultiApiVersion::new();
        for version in iter {
            if s.try_insert(version).is_err() {
                return Err(version);
            }
        }
        Ok(s)
    }
}

#[test]
fn api_version_multi_sanity() {
    let mut mav = MultiApiVersion::new();

    assert_eq!(mav.try_insert(ApiVersion { major: 2, minor: 3 }), Ok(()));

    assert_eq!(mav.get_by_major(0), None);
    assert_eq!(mav.get_by_major(2), Some(ApiVersion { major: 2, minor: 3 }));

    assert_eq!(
        mav.try_insert(ApiVersion { major: 2, minor: 1 }),
        Err(&mut 3)
    );
    *mav.try_insert(ApiVersion { major: 2, minor: 2 })
        .expect_err("must be error, just like one line above") += 1;
    assert_eq!(mav.try_insert(ApiVersion { major: 1, minor: 2 }), Ok(()));
    assert_eq!(mav.try_insert(ApiVersion { major: 3, minor: 4 }), Ok(()));
    assert_eq!(
        mav.try_insert(ApiVersion { major: 2, minor: 0 }),
        Err(&mut 4)
    );
    assert_eq!(mav.get_by_major(5), None);
    assert_eq!(mav.get_by_major(3), Some(ApiVersion { major: 3, minor: 4 }));

    debug_assert!(mav.is_consistent());
}

#[test]
fn api_version_multi_from_iter_sanity() {
    assert!(result::Result::<MultiApiVersion, ApiVersion>::from_iter([]).is_ok());
    assert!(
        result::Result::<MultiApiVersion, ApiVersion>::from_iter([ApiVersion {
            major: 0,
            minor: 0
        }])
        .is_ok()
    );
    assert!(result::Result::<MultiApiVersion, ApiVersion>::from_iter([
        ApiVersion { major: 0, minor: 1 },
        ApiVersion { major: 1, minor: 2 }
    ])
    .is_ok());
    assert!(result::Result::<MultiApiVersion, ApiVersion>::from_iter([
        ApiVersion { major: 0, minor: 1 },
        ApiVersion { major: 1, minor: 2 },
        ApiVersion { major: 0, minor: 1 },
    ])
    .is_err());
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Encodable, Decodable)]
pub struct SupportedCoreApiVersions {
    pub core_consensus: CoreConsensusVersion,
    /// Supported Api versions for this core consensus versions
    pub api: MultiApiVersion,
}

impl SupportedCoreApiVersions {
    /// Get minor supported version by consensus and major numbers
    pub fn get_minor_api_version(
        &self,
        core_consensus: CoreConsensusVersion,
        major: u32,
    ) -> Option<u32> {
        if self.core_consensus.major != core_consensus.major {
            return None;
        }

        self.api.get_by_major(major).map(|v| {
            debug_assert_eq!(v.major, major);
            v.minor
        })
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Encodable, Decodable)]
pub struct SupportedModuleApiVersions {
    pub core_consensus: CoreConsensusVersion,
    pub module_consensus: ModuleConsensusVersion,
    /// Supported Api versions for this core & module consensus versions
    pub api: MultiApiVersion,
}

impl SupportedModuleApiVersions {
    /// Create `SupportedModuleApiVersions` from raw parts
    ///
    /// Panics if `api_version` parts conflict as per
    /// [`SupportedModuleApiVersions`] invariants.
    pub fn from_raw(core: (u32, u32), module: (u32, u32), api_versions: &[(u32, u32)]) -> Self {
        Self {
            core_consensus: CoreConsensusVersion::new(core.0, core.1),
            module_consensus: ModuleConsensusVersion::new(module.0, module.1),
            api: api_versions
                .iter()
                .copied()
                .map(|(major, minor)| ApiVersion { major, minor })
                .collect::<result::Result<MultiApiVersion, ApiVersion>>()
            .expect(
                "overlapping (conflicting) api versions when declaring SupportedModuleApiVersions",
            ),
        }
    }

    /// Get minor supported version by consensus and major numbers
    pub fn get_minor_api_version(
        &self,
        core_consensus: CoreConsensusVersion,
        module_consensus: ModuleConsensusVersion,
        major: u32,
    ) -> Option<u32> {
        if self.core_consensus.major != core_consensus.major {
            return None;
        }

        if self.module_consensus.major != module_consensus.major {
            return None;
        }

        self.api.get_by_major(major).map(|v| {
            debug_assert_eq!(v.major, major);
            v.minor
        })
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Decodable, Encodable)]
pub struct SupportedApiVersionsSummary {
    pub core: SupportedCoreApiVersions,
    pub modules: BTreeMap<ModuleInstanceId, SupportedModuleApiVersions>,
}

/// A summary of server API versions for core and all registered modules.
#[derive(Serialize)]
pub struct ServerApiVersionsSummary {
    pub core: MultiApiVersion,
    pub modules: BTreeMap<ModuleKind, MultiApiVersion>,
}

/// A summary of server database versions for all registered modules.
#[derive(Serialize)]
pub struct ServerDbVersionsSummary {
    pub modules: BTreeMap<ModuleKind, DatabaseVersion>,
}
