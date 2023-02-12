use std::io;

use super::ModuleInstanceId;
use crate::core::DynDecoder;
use crate::encoding::{Decodable, DecodeError};
use crate::module::registry::ModuleDecoderRegistry;

pub fn module_decode_key_prefixed_decodable<T, F, R>(
    mut d: &mut R,
    modules: &ModuleDecoderRegistry,
    decode_fn: F,
) -> Result<T, DecodeError>
where
    R: io::Read,
    F: FnOnce(&mut R, &DynDecoder, ModuleInstanceId) -> Result<T, DecodeError>,
{
    let key = ModuleInstanceId::consensus_decode(&mut d, modules)?;

    decode_fn(d, modules.get_expect(key), key)
}
