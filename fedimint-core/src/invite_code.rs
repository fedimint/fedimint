use core::fmt;
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fmt::{Display, Formatter};
use std::io::Read;
use std::str::FromStr;

use bech32::{Bech32m, Hrp};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::base32::{FEDIMINT_PREFIX, PrefixedDecodeError};
use crate::config::FederationId;
use crate::encoding::{Decodable, DecodeError, Encodable};
use crate::module::registry::{ModuleDecoderRegistry, ModuleRegistry};
use crate::util::SafeUrl;
use crate::{NumPeersExt, PeerId};

/// Information required for client to join Federation
///
/// Can be used to download the configs and bootstrap a client.
///
/// ## Invariants
/// Constructors have to guarantee that:
///   * At least one Api entry is present
///   * At least one Federation ID is present
#[derive(Clone, Debug, Eq, PartialEq, Encodable, Hash, Ord, PartialOrd)]
pub struct InviteCode(Vec<InviteCodePart>);

#[cfg(feature = "uniffi")]
uniffi::custom_type!(InviteCode, String, {
    lower: |i| i.to_string(),
    try_lift: |s| s.parse::<InviteCode>().map_err(anyhow::Error::from),
});

impl Decodable for InviteCode {
    fn consensus_decode_partial<R: Read>(
        r: &mut R,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let inner: Vec<InviteCodePart> = Decodable::consensus_decode_partial(r, modules)?;

        if !inner
            .iter()
            .any(|data| matches!(data, InviteCodePart::Api { .. }))
        {
            return Err(DecodeError::from_str(
                "No API was provided in the invite code",
            ));
        }

        if !inner
            .iter()
            .any(|data| matches!(data, InviteCodePart::FederationId(_)))
        {
            return Err(DecodeError::from_str(
                "No Federation ID provided in invite code",
            ));
        }

        Ok(Self(inner))
    }
}

impl InviteCode {
    pub fn new(
        url: SafeUrl,
        peer: PeerId,
        federation_id: FederationId,
        api_secret: Option<String>,
    ) -> Self {
        let mut s = Self(vec![
            InviteCodePart::Api { url, peer },
            InviteCodePart::FederationId(federation_id),
        ]);

        if let Some(api_secret) = api_secret {
            s.0.push(InviteCodePart::ApiSecret(api_secret));
        }

        s
    }

    pub fn from_map(
        peer_to_url_map: &BTreeMap<PeerId, SafeUrl>,
        federation_id: FederationId,
        api_secret: Option<String>,
    ) -> Self {
        let max_size = peer_to_url_map.to_num_peers().max_evil() + 1;
        let mut code_vec: Vec<InviteCodePart> = peer_to_url_map
            .iter()
            .take(max_size)
            .map(|(peer, url)| InviteCodePart::Api {
                url: url.clone(),
                peer: *peer,
            })
            .collect();

        code_vec.push(InviteCodePart::FederationId(federation_id));

        if let Some(api_secret) = api_secret {
            code_vec.push(InviteCodePart::ApiSecret(api_secret));
        }

        Self(code_vec)
    }

    /// Constructs an [`InviteCode`] which contains as many guardian URLs as
    /// needed to always be able to join a working federation
    pub fn new_with_essential_num_guardians(
        peer_to_url_map: &BTreeMap<PeerId, SafeUrl>,
        federation_id: FederationId,
    ) -> Self {
        let max_size = peer_to_url_map.to_num_peers().max_evil() + 1;
        let mut code_vec: Vec<InviteCodePart> = peer_to_url_map
            .iter()
            .take(max_size)
            .map(|(peer, url)| InviteCodePart::Api {
                url: url.clone(),
                peer: *peer,
            })
            .collect();
        code_vec.push(InviteCodePart::FederationId(federation_id));

        Self(code_vec)
    }

    /// Returns the API URL of one of the guardians.
    pub fn url(&self) -> SafeUrl {
        self.0
            .iter()
            .find_map(|data| match data {
                InviteCodePart::Api { url, .. } => Some(url.clone()),
                _ => None,
            })
            .expect("Ensured by constructor")
    }

    /// Api secret, if needed, to use when communicating with the federation
    pub fn api_secret(&self) -> Option<String> {
        self.0.iter().find_map(|data| match data {
            InviteCodePart::ApiSecret(api_secret) => Some(api_secret.clone()),
            _ => None,
        })
    }
    /// Returns the id of the guardian from which we got the API URL, see
    /// [`InviteCode::url`].
    pub fn peer(&self) -> PeerId {
        self.0
            .iter()
            .find_map(|data| match data {
                InviteCodePart::Api { peer, .. } => Some(*peer),
                _ => None,
            })
            .expect("Ensured by constructor")
    }

    /// Get all peer URLs in the [`InviteCode`]
    pub fn peers(&self) -> BTreeMap<PeerId, SafeUrl> {
        self.0
            .iter()
            .filter_map(|entry| match entry {
                InviteCodePart::Api { url, peer } => Some((*peer, url.clone())),
                _ => None,
            })
            .collect()
    }

    /// Returns the federation's ID that can be used to authenticate the config
    /// downloaded from the API.
    pub fn federation_id(&self) -> FederationId {
        self.0
            .iter()
            .find_map(|data| match data {
                InviteCodePart::FederationId(federation_id) => Some(*federation_id),
                _ => None,
            })
            .expect("Ensured by constructor")
    }
}

/// For extendability [`InviteCode`] consists of parts, where client can ignore
/// ones they don't understand.
///
/// ones they don't understand Data that can be encoded in the invite code.
/// Currently we always just use one `Api` and one `FederationId` variant in an
/// invite code, but more can be added in the future while still keeping the
/// invite code readable for older clients, which will just ignore the new
/// fields.
#[derive(Clone, Debug, Eq, PartialEq, Encodable, Decodable, Hash, Ord, PartialOrd)]
enum InviteCodePart {
    /// API endpoint of one of the guardians
    Api {
        /// URL to reach an API that we can download configs from
        url: SafeUrl,
        /// Peer id of the host from the Url
        peer: PeerId,
    },

    /// Authentication id for the federation
    FederationId(FederationId),

    /// Api secret to use
    ApiSecret(String),

    /// Unknown invite code fields to be defined in the future
    #[encodable_default]
    Default { variant: u64, bytes: Vec<u8> },
}

/// We can represent client invite code as a bech32 string for compactness and
/// error-checking
///
/// Human readable part (HRP) includes the version
/// ```txt
/// [ hrp (4 bytes) ] [ id (48 bytes) ] ([ url len (2 bytes) ] [ url bytes (url len bytes) ])+
/// ```
const BECH32_HRP: Hrp = Hrp::parse_unchecked("fed1");

impl FromStr for InviteCode {
    type Err = InviteCodeParseError;

    fn from_str(encoded: &str) -> Result<Self, Self::Err> {
        // The prefix is ASCII, so a case-insensitive match here agrees with the
        // lowercasing `decode_prefixed` does before comparing the prefix.
        if encoded
            .get(..FEDIMINT_PREFIX.len())
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(FEDIMINT_PREFIX))
        {
            return Ok(crate::base32::decode_prefixed(FEDIMINT_PREFIX, encoded)?);
        }

        let (hrp, data) = bech32::decode(encoded)?;

        if hrp != BECH32_HRP {
            return Err(InviteCodeParseError::InvalidHrp { hrp });
        }

        let invite = Self::consensus_decode_whole(&data, &ModuleRegistry::default())?;

        Ok(invite)
    }
}

/// Failure to parse an [`InviteCode`] from its string form.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum InviteCodeParseError {
    /// The string is not a valid bech32m encoding.
    #[error("Invalid bech32 encoding: {0}")]
    Bech32(#[from] bech32::DecodeError),
    /// The bech32 human-readable part is not the invite code HRP.
    #[error(
        "Invalid bech32 human-readable part '{hrp}', expected '{}'",
        BECH32_HRP
    )]
    InvalidHrp { hrp: bech32::Hrp },
    /// The payload is not a valid consensus encoding of an invite code.
    #[error("Invalid invite code payload: {0}")]
    Decode(#[from] DecodeError),
    /// The string carries the [`FEDIMINT_PREFIX`] but its base 32 payload does
    /// not decode into an invite code.
    #[error("Invalid prefixed base32 invite code: {0}")]
    Base32(#[from] PrefixedDecodeError),
}

/// Parses the invite code from a bech32 string
impl Display for InviteCode {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        let data = self.consensus_encode_to_vec();
        let encode = bech32::encode::<Bech32m>(BECH32_HRP, &data).map_err(|_| fmt::Error)?;
        formatter.write_str(&encode)
    }
}

impl Serialize for InviteCode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        String::serialize(&self.to_string(), serializer)
    }
}

impl<'de> Deserialize<'de> for InviteCode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let string = Cow::<str>::deserialize(deserializer)?;
        Self::from_str(&string).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use fedimint_core::PeerId;
    use fedimint_core::base32::FEDIMINT_PREFIX;

    use super::InviteCodeParseError;
    use crate::config::FederationId;
    use crate::invite_code::InviteCode;

    #[test]
    fn test_invite_code_to_from_string() {
        let invite_code_str = "fed11qgqpu8rhwden5te0vejkg6tdd9h8gepwd4cxcumxv4jzuen0duhsqqfqh6nl7sgk72caxfx8khtfnn8y436q3nhyrkev3qp8ugdhdllnh86qmp42pm";
        let invite_code = InviteCode::from_str(invite_code_str).expect("valid invite code");

        InviteCode::from_str(&crate::base32::encode_prefixed(
            FEDIMINT_PREFIX,
            &invite_code,
        ))
        .expect("Failed to parse base 32 invite code");

        assert_eq!(invite_code.to_string(), invite_code_str);
        assert_eq!(
            invite_code.0,
            [
                crate::invite_code::InviteCodePart::Api {
                    url: "wss://fedimintd.mplsfed.foo/".parse().expect("valid url"),
                    peer: PeerId::new(0),
                },
                crate::invite_code::InviteCodePart::FederationId(FederationId(
                    bitcoin::hashes::sha256::Hash::from_str(
                        "bea7ff4116f2b1d324c7b5d699cce4ac7408cee41db2c88027e21b76fff3b9f4"
                    )
                    .expect("valid hash")
                ))
            ]
        );
    }

    #[test]
    fn from_str_rejects_wrong_hrp() {
        let other_hrp = bech32::Hrp::parse("abcd").expect("valid hrp");
        let encoded = bech32::encode::<bech32::Bech32m>(other_hrp, &[0u8; 8]).expect("encodes");
        assert!(matches!(
            InviteCode::from_str(&encoded),
            Err(InviteCodeParseError::InvalidHrp { hrp }) if hrp == other_hrp
        ));
    }

    #[test]
    fn from_str_rejects_non_bech32() {
        assert!(matches!(
            InviteCode::from_str("definitely not bech32"),
            Err(InviteCodeParseError::Bech32(_))
        ));
    }

    #[test]
    fn from_str_reports_corrupt_prefixed_base32() {
        assert!(matches!(
            InviteCode::from_str(&format!("{FEDIMINT_PREFIX}not!base32")),
            Err(InviteCodeParseError::Base32(_))
        ));
    }
}
