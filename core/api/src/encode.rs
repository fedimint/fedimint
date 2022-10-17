use std::{collections::BTreeMap, io};

use fedimint_api::encoding::{Decodable, DecodeError};

use crate::ModuleKey;

pub fn module_decode_key_prefixed_decodable<T, F, R, M>(
    mut d: &mut R,
    modules: &BTreeMap<ModuleKey, M>,
    decode_fn: F,
) -> Result<T, DecodeError>
where
    R: io::Read,
    F: FnOnce(&mut R, &M) -> Result<T, DecodeError>,
{
    let key = ModuleKey::consensus_decode(&mut d, modules)?;

    match modules.get(&key) {
        Some(module) => decode_fn(d, module),
        None => Err(DecodeError::new_custom(anyhow::anyhow!(
            "Unsupported module with key: {}",
            key
        ))),
    }
}
