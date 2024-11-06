use core::fmt;
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fmt::{Display, Formatter};
use std::io::{Cursor, Read};
use std::str::FromStr;

use anyhow::ensure;
use bech32::{Bech32m, Hrp};
use serde::{Deserialize, Serialize};

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

impl Decodable for InviteCode {
    fn consensus_decode<R: Read>(
        r: &mut R,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let inner: Vec<InviteCodePart> = Decodable::consensus_decode(r, modules)?;

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
    type Err = anyhow::Error;

    fn from_str(encoded: &str) -> Result<Self, Self::Err> {
        if let Ok(invite_code_v2) = InviteCodeV2::decode_base64(encoded) {
            return invite_code_v2.into_v1();
        }

        let (hrp, data) = bech32::decode(encoded)?;

        ensure!(hrp == BECH32_HRP, "Invalid HRP in bech32 encoding");

        let invite = Self::consensus_decode(&mut Cursor::new(data), &ModuleRegistry::default())?;

        Ok(invite)
    }
}

/// Parses the invite code from a bech32 string
impl Display for InviteCode {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        let mut data = vec![];

        self.consensus_encode(&mut data)
            .expect("Vec<u8> provides capacity");

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
    use std::collections::BTreeMap;
    use std::str::FromStr;

    use fedimint_core::util::SafeUrl;
    use fedimint_core::PeerId;

    use crate::config::FederationId;
    use crate::invite_code::{InviteCode, InviteCodeV2};

    #[test]
    fn test_invite_code_to_from_string() {
        let invite_code_str = "fed11qgqpu8rhwden5te0vejkg6tdd9h8gepwd4cxcumxv4jzuen0duhsqqfqh6nl7sgk72caxfx8khtfnn8y436q3nhyrkev3qp8ugdhdllnh86qmp42pm";
        let invite_code = InviteCode::from_str(invite_code_str).expect("valid invite code");

        assert_eq!(invite_code.to_string(), invite_code_str);
        assert_eq!(
            invite_code.0,
            [
                crate::invite_code::InviteCodePart::Api {
                    url: "wss://fedimintd.mplsfed.foo/".parse().expect("valid url"),
                    peer: PeerId::new(0),
                },
                crate::invite_code::InviteCodePart::FederationId(FederationId(
                    bitcoin30::hashes::sha256::Hash::from_str(
                        "bea7ff4116f2b1d324c7b5d699cce4ac7408cee41db2c88027e21b76fff3b9f4"
                    )
                    .expect("valid hash")
                ))
            ]
        );
    }

    #[test]
    fn invite_code_v2_encode_base64_roundtrip() {
        let invite_code = InviteCodeV2 {
            id: FederationId::dummy(),
            peers: BTreeMap::from_iter([(
                PeerId::from(0),
                SafeUrl::parse("https://mint.com").expect("Url is valid"),
            )]),
            api_secret: None,
        };

        let encoded = invite_code.encode_base64();
        let decoded = InviteCodeV2::decode_base64(&encoded).expect("Failed to decode");

        assert_eq!(invite_code, decoded);

        InviteCode::from_str(&encoded).expect("Failed to decode to legacy");
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encodable, Decodable)]
pub struct InviteCodeV2 {
    pub id: FederationId,
    pub peers: BTreeMap<PeerId, SafeUrl>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub api_secret: Option<String>,
}

impl InviteCodeV2 {
    pub fn into_v1(self) -> anyhow::Result<InviteCode> {
        Ok(InviteCode::from_map(&self.peers, self.id, self.api_secret))
    }

    pub fn encode_base64(&self) -> String {
        let json = &serde_json::to_string(self).expect("Encoding to JSON cannot fail");
        let base_64 = base64_url::encode(json);

        format!("fedimintA{base_64}")
    }

    pub fn decode_base64(s: &str) -> anyhow::Result<Self> {
        ensure!(s.starts_with("fedimintA"), "Invalid Prefix");

        let invite_code: Self = serde_json::from_slice(&base64_url::decode(&s[9..])?)?;

        ensure!(!invite_code.peers.is_empty(), "Invite code has no peer");

        Ok(invite_code)
    }
}
