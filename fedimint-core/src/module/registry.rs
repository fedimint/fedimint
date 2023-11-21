use std::collections::BTreeMap;

use anyhow::anyhow;

pub use crate::core::ModuleInstanceId;
use crate::core::{Decoder, ModuleKind};
use crate::server::DynServerModule;

/// Module Registry hold module-specific data `M` by the `ModuleInstanceId`
#[derive(Debug)]
pub struct ModuleRegistry<M, State = ()> {
    inner: BTreeMap<ModuleInstanceId, (ModuleKind, M)>,
    // It is sometimes useful for registries to have some state to modify
    // their behavior.
    state: State,
}

impl<M, State> Clone for ModuleRegistry<M, State>
where
    State: Clone,
    M: Clone,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            state: self.state.clone(),
        }
    }
}

impl<M, State> Default for ModuleRegistry<M, State>
where
    State: Default,
{
    fn default() -> Self {
        ModuleRegistry {
            inner: BTreeMap::new(),
            state: Default::default(),
        }
    }
}

impl<M, State> From<BTreeMap<ModuleInstanceId, (ModuleKind, M)>> for ModuleRegistry<M, State>
where
    State: Default,
{
    fn from(value: BTreeMap<ModuleInstanceId, (ModuleKind, M)>) -> Self {
        Self {
            inner: value,
            state: Default::default(),
        }
    }
}

impl<M, State> FromIterator<(ModuleInstanceId, ModuleKind, M)> for ModuleRegistry<M, State>
where
    State: Default,
{
    fn from_iter<T: IntoIterator<Item = (ModuleInstanceId, ModuleKind, M)>>(iter: T) -> Self {
        Self::new(iter)
    }
}

impl<M, State> ModuleRegistry<M, State> {
    /// Create [`Self`] from an iterator of pairs
    pub fn new(iter: impl IntoIterator<Item = (ModuleInstanceId, ModuleKind, M)>) -> Self
    where
        State: Default,
    {
        Self {
            inner: iter
                .into_iter()
                .map(|(id, kind, module)| (id, (kind, module)))
                .collect(),
            state: Default::default(),
        }
    }

    /// Is registry empty?
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Return an iterator over all module data
    pub fn iter_modules(&self) -> impl Iterator<Item = (ModuleInstanceId, &ModuleKind, &M)> {
        self.inner.iter().map(|(id, (kind, m))| (*id, kind, m))
    }

    /// Return an iterator over all module data
    pub fn iter_modules_mut(
        &mut self,
    ) -> impl Iterator<Item = (ModuleInstanceId, &ModuleKind, &mut M)> {
        self.inner
            .iter_mut()
            .map(|(id, (kind, m))| (*id, &*kind, m))
    }

    /// Return an iterator over all module data
    pub fn into_iter_modules(self) -> impl Iterator<Item = (ModuleInstanceId, ModuleKind, M)> {
        self.inner.into_iter().map(|(id, (kind, m))| (id, kind, m))
    }

    /// Get module data by instance id
    pub fn get(&self, id: ModuleInstanceId) -> Option<&M> {
        self.inner.get(&id).map(|m| &m.1)
    }

    /// Get module data by instance id, including [`ModuleKind`]
    pub fn get_with_kind(&self, id: ModuleInstanceId) -> Option<&(ModuleKind, M)> {
        self.inner.get(&id)
    }
}

impl<M: std::fmt::Debug, State> ModuleRegistry<M, State> {
    /// Return the module data belonging to the module identified by the
    /// supplied `module_id`
    ///
    /// # Panics
    /// If the module isn't in the registry
    pub fn get_expect(&self, id: ModuleInstanceId) -> &M {
        &self
            .inner
            .get(&id)
            .ok_or_else(|| {
                anyhow!(
                    "Instance ID not found: got {}, expected one of {:?}",
                    id,
                    self.inner.keys().collect::<Vec<_>>()
                )
            })
            .expect("Only existing instance should be fetched")
            .1
    }

    /// Add a module to the registry
    pub fn register_module(&mut self, id: ModuleInstanceId, kind: ModuleKind, module: M) {
        // FIXME: return result
        assert!(
            self.inner.insert(id, (kind, module)).is_none(),
            "Module was already registered!"
        )
    }
}

/// Collection of server modules
pub type ServerModuleRegistry = ModuleRegistry<DynServerModule>;

impl ServerModuleRegistry {
    /// Generate a `ModuleDecoderRegistry` from this `ModuleRegistry`
    pub fn decoder_registry(&self) -> ModuleDecoderRegistry {
        // TODO: cache decoders
        ModuleDecoderRegistry::from_iter(
            self.inner
                .iter()
                .map(|(&id, (kind, module))| (id, kind.clone(), module.decoder())),
        )
    }
}

#[derive(Default, Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum DecodingMode {
    /// Reject unknown module instance ids
    #[default]
    Reject,
    /// Fallback to decoding unknown module instance ids as
    /// [`crate::core::DynUnknown`]
    Fallback,
}

/// Collection of decoders belonging to modules, typically obtained from a
/// `ModuleRegistry`
pub type ModuleDecoderRegistry = ModuleRegistry<Decoder, DecodingMode>;

impl ModuleDecoderRegistry {
    pub fn with_fallback(self) -> Self {
        Self {
            state: DecodingMode::Fallback,
            ..self
        }
    }

    pub fn decoding_mode(&self) -> DecodingMode {
        self.state
    }

    /// Panic if the [`Self::decoding_mode`] is not `Reject`
    pub fn assert_reject_mode(&self) {
        assert_eq!(self.state, DecodingMode::Reject);
    }
}
