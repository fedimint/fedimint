use std::io;

use fedimint_api::encoding::{Decodable, DecodeError};

use crate::core::Decoder;
use crate::module::registry::{ModuleDecoderRegistry, ModuleKey};

pub fn module_decode_key_prefixed_decodable<T, F, R>(
    mut d: &mut R,
    modules: &ModuleDecoderRegistry,
    decode_fn: F,
) -> Result<T, DecodeError>
where
    R: io::Read,
    F: FnOnce(&mut R, &Decoder) -> Result<T, DecodeError>,
{
    let key = ModuleKey::consensus_decode(&mut d, modules)?;

    decode_fn(d, modules.get(key))
}
