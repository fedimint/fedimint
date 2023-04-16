use std::collections::BTreeMap;

use anyhow::anyhow;

use crate::core::Decoder;
pub use crate::core::ModuleInstanceId;
use crate::server::DynServerModule;

/// Module Registry hold module-specific data `M` by the `ModuleInstanceId`
#[derive(Debug, Clone)]
pub struct ModuleRegistry<M>(BTreeMap<ModuleInstanceId, M>);

impl<M> Default for ModuleRegistry<M> {
    fn default() -> Self {
        ModuleRegistry(BTreeMap::new())
    }
}

impl<M> From<BTreeMap<ModuleInstanceId, M>> for ModuleRegistry<M> {
    fn from(value: BTreeMap<ModuleInstanceId, M>) -> Self {
        Self(value)
    }
}

impl<M> FromIterator<(ModuleInstanceId, M)> for ModuleRegistry<M> {
    fn from_iter<T: IntoIterator<Item = (ModuleInstanceId, M)>>(iter: T) -> Self {
        Self::new(iter)
    }
}

impl<M> ModuleRegistry<M> {
    /// Create [`Self`] from an iterator of pairs
    pub fn new(iter: impl IntoIterator<Item = (ModuleInstanceId, M)>) -> Self {
        Self(iter.into_iter().collect())
    }

    /// Return an iterator over all module data
    pub fn iter_modules(&self) -> impl Iterator<Item = (ModuleInstanceId, &M)> {
        self.0.iter().map(|(id, m)| (*id, m))
    }

    /// Get module data by instance id
    pub fn get(&self, id: ModuleInstanceId) -> Option<&M> {
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
        self.0
            .get(&id)
            .ok_or_else(|| {
                anyhow!(
                    "Instance ID not found: got {}, expected one of {:?}",
                    id,
                    self.0.keys().collect::<Vec<_>>()
                )
            })
            .expect("Only existing instance should be fetched")
    }

    /// Add a module to the registry
    pub fn register_module(&mut self, id: ModuleInstanceId, module: M) {
        // FIXME: return result
        assert!(
            self.0.insert(id, module).is_none(),
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
        ModuleDecoderRegistry::from_iter(self.0.iter().map(|(&id, module)| (id, module.decoder())))
    }
}

/// Collection of decoders belonging to modules, typically obtained from a
/// `ModuleRegistry`
pub type ModuleDecoderRegistry = ModuleRegistry<Decoder>;
