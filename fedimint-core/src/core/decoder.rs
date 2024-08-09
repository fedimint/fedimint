use std::any::{Any, TypeId};
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fmt::{Debug, Formatter};
use std::io::Read;
use std::sync::Arc;

use anyhow::anyhow;
use fedimint_core::encoding::{Decodable, DecodeError};
use fedimint_core::module::registry::ModuleDecoderRegistry;

use super::{IntoDynInstance, ModuleInstanceId};
use crate::module::registry::ModuleRegistry;

type DecodeFn = Box<
    dyn for<'a> Fn(
            Box<dyn Read + 'a>,
            ModuleInstanceId,
            &ModuleDecoderRegistry,
        ) -> Result<Box<dyn Any>, DecodeError>
        + Send
        + Sync,
>;

#[derive(Default)]
pub struct DecoderBuilder {
    decode_fns: BTreeMap<TypeId, DecodeFn>,
    transparent: bool,
}

impl DecoderBuilder {
    pub fn build(self) -> Decoder {
        Decoder {
            decode_fns: Arc::new(self.decode_fns),
        }
    }

    /// Attach decoder for a specific `Type`/`DynType` pair where `DynType =
    /// <Type as IntoDynInstance>::DynType`.
    ///
    /// This allows calling `decode::<DynType>` on this decoder, returning a
    /// `DynType` object which contains a `Type` object internally.
    ///
    /// **Caution**: One `Decoder` object should only contain decoders that
    /// belong to the same [*module kind*](fedimint_core::core::ModuleKind).
    ///
    /// # Panics
    /// * If multiple `Types` with the same `DynType` are added
    pub fn with_decodable_type<Type>(&mut self)
    where
        Type: IntoDynInstance + Decodable,
    {
        let is_transparent_decoder = self.transparent;
        // TODO: enforce that all decoders are for the same module kind (+fix docs
        // after)
        let decode_fn: DecodeFn = Box::new(
            move |mut reader, instance, decoders: &ModuleDecoderRegistry| {
                // TODO: Ideally `DynTypes` decoding couldn't ever be nested, so we could just
                // pass empty `decoders`. But the client context uses nested `DynTypes` in
                // `DynState`, so we special-case it with a flag.
                let decoders = if is_transparent_decoder {
                    Cow::Borrowed(decoders)
                } else {
                    Cow::Owned(ModuleRegistry::default())
                };
                let typed_val = Type::consensus_decode(&mut reader, &decoders).map_err(|err| {
                    let err: anyhow::Error = err.into();
                    DecodeError::new_custom(
                        err.context(format!("while decoding Dyn type module_id={instance}")),
                    )
                })?;
                let dyn_val = typed_val.into_dyn(instance);
                let any_val: Box<dyn Any> = Box::new(dyn_val);
                Ok(any_val)
            },
        );
        if self
            .decode_fns
            .insert(TypeId::of::<Type::DynType>(), decode_fn)
            .is_some()
        {
            panic!("Tried to add multiple decoders for the same DynType");
        }
    }
}

/// Consensus encoding decoder for module-specific types
#[derive(Clone, Default)]
pub struct Decoder {
    decode_fns: Arc<BTreeMap<TypeId, DecodeFn>>,
}

impl Decoder {
    /// Creates a `DecoderBuilder` to which decoders for single types can be
    /// attached to build a `Decoder`.
    pub fn builder() -> DecoderBuilder {
        DecoderBuilder::default()
    }

    /// System Dyn-type, don't use.
    #[doc(hidden)]
    pub fn builder_system() -> DecoderBuilder {
        DecoderBuilder {
            transparent: true,
            ..DecoderBuilder::default()
        }
    }

    /// Decodes a specific `DynType` from the `reader` byte stream.
    ///
    /// # Panics
    /// * If no decoder is registered for the `DynType`
    pub fn decode_complete<DynType: Any>(
        &self,
        reader: &mut dyn Read,
        total_len: u64,
        module_id: ModuleInstanceId,
        decoders: &ModuleDecoderRegistry,
    ) -> Result<DynType, DecodeError> {
        let mut reader = reader.take(total_len);

        let val = self.decode_partial(&mut reader, module_id, decoders)?;
        let left = reader.limit();

        if left != 0 {
            return Err(fedimint_core::encoding::DecodeError::new_custom(
                anyhow::anyhow!(
                    "Dyn type did not consume all bytes during decoding; module_id={}; expected={}; left={}; type={}",
                    module_id,
                    total_len,
                    left,
                    std::any::type_name::<DynType>(),
                ),
            ));
        }

        Ok(val)
    }

    /// Like [`Self::decode_complete`] but does not verify that all bytes were
    /// consumed
    pub fn decode_partial<DynType: Any>(
        &self,
        reader: &mut dyn Read,
        module_id: ModuleInstanceId,
        decoders: &ModuleDecoderRegistry,
    ) -> Result<DynType, DecodeError> {
        let decode_fn = self
            .decode_fns
            .get(&TypeId::of::<DynType>())
            .ok_or_else(|| {
                anyhow!(
                    "Type unknown to decoder: {}, (registered decoders={})",
                    std::any::type_name::<DynType>(),
                    self.decode_fns.len()
                )
            })
            .expect("Types being decoded must be registered");
        Ok(*decode_fn(Box::new(reader), module_id, decoders)?
            .downcast::<DynType>()
            .expect("Decode fn returned wrong type, can't happen due to with_decodable_type"))
    }
}

impl Debug for Decoder {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Decoder(registered_types = {})", self.decode_fns.len())
    }
}
