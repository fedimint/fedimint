use std::{collections::BTreeMap, io};

use fedimint_api::encoding::{Decodable, DecodeError};

use crate::ModuleCommon;

use super::ModuleKey;

/// Value that can be decoded, but only using the required supported modules of type `M`
pub trait ModuleDecodable<M>: Sized {
    /// Decode an object with a well-defined format
    fn consensus_decode<R: std::io::Read>(
        r: &mut R,
        modules: &BTreeMap<ModuleKey, M>,
    ) -> Result<Self, DecodeError>;
}

/*
macro_rules! impl_module_decodable_forward_to_decodable {
    ($t:ty) => {
        impl ModuleDecodable for $t {
            fn consensus_decode<D: std::io::Read>(
                d: D,
                modules: &BTreeMap<ModuleKey, FedimintModule>,
            ) -> Result<Self, DecodeError> {
                <Self as Decodable>::consensus_decode(d)
            }
        }
    };
}*/

impl<T, M> ModuleDecodable<M> for Vec<T>
where
    T: ModuleDecodable<M>,
{
    fn consensus_decode<R: std::io::Read>(
        mut r: &mut R,
        modules: &BTreeMap<ModuleKey, M>,
    ) -> Result<Self, DecodeError> {
        let len = u64::consensus_decode(&mut r)?;
        (0..len).map(|_| T::consensus_decode(r, modules)).collect()
    }
}

pub fn module_decode_key_prefixed_decodable<T, F, R, M>(
    mut d: &mut R,
    modules: &BTreeMap<ModuleKey, M>,
    decode_fn: F,
) -> Result<T, DecodeError>
where
    R: io::Read,
    F: FnOnce(&mut R, &M) -> Result<T, DecodeError>,
    M: ModuleCommon,
{
    let key = ModuleKey::consensus_decode(&mut d)?;

    match modules.get(&key) {
        Some(module) => decode_fn(d, module),
        None => Err(DecodeError::new_custom(anyhow::anyhow!(
            "Unsupported module with key: {}",
            key
        ))),
    }
}
