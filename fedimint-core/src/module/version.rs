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
use std::result;

use serde::{Deserialize, Serialize};

use crate::core::ModuleInstanceId;
use crate::encoding::{Decodable, Encodable};

/// Consensus version of a core server
///
/// Breaking changes in the Fedimint's core consensus require incrementing it.
///
/// See [`ModuleConsensusVersion`] for more details on how it interacts with
/// module's consensus.
#[derive(Debug, Copy, Clone, Serialize, Deserialize, Encodable, Decodable, PartialEq, Eq)]
pub struct CoreConsensusVersion(pub u32);

impl From<u32> for CoreConsensusVersion {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

/// Consensus version of a specific module instance
///
/// Any breaking change to the module's consensus rules require incrementing it.
///
/// A module instance can run only in one consensus version, which must be the
/// same across all corresponding instances on other nodes of the federation.
///
/// When [`CoreConsensusVersion`] changes, this can but is not requires to be
/// a breaking change for each module's [`ModuleConsensusVersion`].
///
/// Incrementing the module's consensus version can be considered an in-place
/// upgrade path, similar to a blockchain hard-fork consensus upgrade.
///
/// As of time of writing this comment there are no plans to support any kind
/// of "soft-forks" which mean a consensus minor version. As the set of
/// federation member's is closed and limited, it is always preferable to
/// synchronize upgrade and avoid cross-version incompatibilities.
///
/// For many modules it might be preferable to implement a new
/// [`fedimint_core::core::ModuleKind`] "versions" (to be implemented at the
/// time of writing this comment), and by running two instances of the module at
/// the same time (each of different `ModuleKind` version), allow users to
/// slowly migrate to a new one. This avoids complex and error-prone server-side
/// consensus-migration logic.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize, Encodable, Decodable)]
pub struct ModuleConsensusVersion(pub u32);

impl From<u32> for ModuleConsensusVersion {
    fn from(value: u32) -> Self {
        Self(value)
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
#[derive(Debug, Clone, Serialize, Default)]
pub struct MultiApiVersion(Vec<ApiVersion>);

impl MultiApiVersion {
    pub fn new() -> Self {
        Default::default()
    }

    /// Verify the invariant: sorted by unique major numbers
    fn is_consistent(&self) -> bool {
        self.0
            .iter()
            .fold((None, true), |(prev, is_sorted), next| {
                (
                    Some(*next),
                    is_sorted && prev.map(|prev| prev.major < next.major).unwrap_or(true),
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
        for version in iter.into_iter() {
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupportedCoreApiVersions {
    pub core_consensus: CoreConsensusVersion,
    /// Supported Api versions for this core consensus versions
    pub api: MultiApiVersion,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
    pub fn from_raw(core: u32, module: u32, api_versions: &[(u32, u32)]) -> Self {
        Self {
            core_consensus: CoreConsensusVersion(core),
            module_consensus: ModuleConsensusVersion(module),
            api: result::Result::<MultiApiVersion, ApiVersion>::from_iter(
                api_versions
                    .iter()
                    .copied()
                    .map(|(major, minor)| ApiVersion { major, minor }),
            )
            .expect(
                "overlapping (conflicting) api versions when declaring SupportedModuleApiVersions",
            ),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupportedApiVersionsSummary {
    pub core: SupportedCoreApiVersions,
    pub modules: BTreeMap<ModuleInstanceId, SupportedModuleApiVersions>,
}
