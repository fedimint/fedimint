use std::io;

use fedimint_api::encoding::{Decodable, DecodeError};

use super::{ModuleDecoder, ModuleKey};
use crate::encoding::ModuleRegistry;

pub fn module_decode_key_prefixed_decodable<T, F, R, M>(
    mut r: &mut R,
    modules: &ModuleRegistry<M>,
    decode_fn: F,
) -> Result<T, DecodeError>
where
    R: io::Read,
    F: FnOnce(&mut R, &M) -> Result<T, DecodeError>,
    M: ModuleDecoder,
    T: Decodable,
{
    let key = ModuleKey::consensus_decode(&mut r, modules)?;

    match modules.get(&key) {
        Some(module) => decode_fn(r, module),
        None => Err(DecodeError::new_custom(anyhow::anyhow!(
            "Unsupported module with key: {key}",
        ))),
    }
}
