use fedimint_core::config::FederationId;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::{Amount, base32};

use crate::SpendableNote;

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct ECash(Vec<ECashField>);

#[derive(Clone, Debug, Decodable, Encodable)]
enum ECashField {
    Mint(FederationId),
    Note(SpendableNote),
    Memo(String),
    #[encodable_default]
    Default {
        variant: u64,
        bytes: Vec<u8>,
    },
}

impl ECash {
    pub(crate) fn new(mint: FederationId, notes: Vec<SpendableNote>, memo: Option<String>) -> Self {
        Self(
            std::iter::once(ECashField::Mint(mint))
                .chain(notes.into_iter().map(ECashField::Note))
                .chain(memo.into_iter().map(ECashField::Memo))
                .collect(),
        )
    }

    pub fn amount(&self) -> Amount {
        self.0
            .iter()
            .filter_map(|field| match field {
                ECashField::Note(note) => Some(note.amount()),
                _ => None,
            })
            .sum()
    }

    pub fn mint(&self) -> Option<FederationId> {
        self.0.iter().find_map(|field| match field {
            ECashField::Mint(mint) => Some(*mint),
            _ => None,
        })
    }

    pub fn notes(&self) -> Vec<SpendableNote> {
        self.0
            .iter()
            .filter_map(|field| match field {
                ECashField::Note(note) => Some(note.clone()),
                _ => None,
            })
            .collect()
    }

    pub fn memo(&self) -> Option<String> {
        self.0.iter().find_map(|field| match field {
            ECashField::Memo(memo) => Some(memo.clone()),
            _ => None,
        })
    }

    pub fn encode_base32(&self) -> String {
        format!(
            "fedimint{}",
            base32::encode(&self.consensus_encode_to_vec())
        )
    }

    pub fn decode_base32(s: &str) -> anyhow::Result<Self> {
        anyhow::ensure!(s.starts_with("fedimint"), "Invalid Prefix");

        Ok(Self(Decodable::consensus_decode_whole(
            &base32::decode(&s[8..])?,
            &ModuleDecoderRegistry::default(),
        )?))
    }
}
