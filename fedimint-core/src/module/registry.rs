use std::collections::BTreeMap;

use anyhow::anyhow;

pub use crate::core::ModuleInstanceId;
use crate::core::{Decoder, ModuleKind};
use crate::server::DynServerModule;

/// Module Registry hold module-specific data `M` by the `ModuleInstanceId`
#[derive(Debug, Clone)]
pub struct ModuleRegistry<M>(BTreeMap<ModuleInstanceId, (ModuleKind, M)>);

impl<M> Default for ModuleRegistry<M> {
    fn default() -> Self {
        ModuleRegistry(BTreeMap::new())
    }
}

impl<M> From<BTreeMap<ModuleInstanceId, (ModuleKind, M)>> for ModuleRegistry<M> {
    fn from(value: BTreeMap<ModuleInstanceId, (ModuleKind, M)>) -> Self {
        Self(value)
    }
}

impl<M> FromIterator<(ModuleInstanceId, ModuleKind, M)> for ModuleRegistry<M> {
    fn from_iter<T: IntoIterator<Item = (ModuleInstanceId, ModuleKind, M)>>(iter: T) -> Self {
        Self::new(iter)
    }
}

impl<M> ModuleRegistry<M> {
    /// Create [`Self`] from an iterator of pairs
    pub fn new(iter: impl IntoIterator<Item = (ModuleInstanceId, ModuleKind, M)>) -> Self {
        Self(
            iter.into_iter()
                .map(|(id, kind, module)| (id, (kind, module)))
                .collect(),
        )
    }

    /// Return an iterator over all module data
    pub fn iter_modules(&self) -> impl Iterator<Item = (ModuleInstanceId, &ModuleKind, &M)> {
        self.0.iter().map(|(id, (kind, m))| (*id, kind, m))
    }

    /// Get module data by instance id
    pub fn get(&self, id: ModuleInstanceId) -> Option<&M> {
        self.0.get(&id).map(|m| &m.1)
    }

    /// Get module data by instance id, including [`ModuleKind`]
    pub fn get_with_kind(&self, id: ModuleInstanceId) -> Option<&(ModuleKind, M)> {
        self.0.get(&id)
    }
}

impl<M: std::fmt::Debug> ModuleRegistry<M> {
    /// Return the module data belonging to the module identified by the
    /// supplied `module_id`
    ///
    /// # Panics
    /// If the module isn't in the registry
    pub fn get_expect(&self, id: ModuleInstanceId) -> &M {
        &self
            .0
            .get(&id)
            .ok_or_else(|| {
                anyhow!(
                    "Instance ID not found: got {}, expected one of {:?}",
                    id,
                    self.0.keys().collect::<Vec<_>>()
                )
            })
            .expect("Only existing instance should be fetched")
            .1
    }

    /// Add a module to the registry
    pub fn register_module(&mut self, id: ModuleInstanceId, kind: ModuleKind, module: M) {
        // FIXME: return result
        assert!(
            self.0.insert(id, (kind, module)).is_none(),
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
            self.0
                .iter()
                .map(|(&id, (kind, module))| (id, kind.clone(), module.decoder())),
        )
    }
}

/// Collection of decoders belonging to modules, typically obtained from a
/// `ModuleRegistry`
pub type ModuleDecoderRegistry = ModuleRegistry<Decoder>;
