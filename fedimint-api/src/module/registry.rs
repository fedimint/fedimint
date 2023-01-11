use std::collections::BTreeMap;

use crate::core::Decoder;
pub use crate::core::ModuleInstanceId;
use crate::server::DynServerModule;

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

impl<M> ModuleRegistry<M> {
    pub fn new(decoders: impl IntoIterator<Item = (ModuleInstanceId, M)>) -> Self {
        Self(decoders.into_iter().collect())
    }

    /// Return an iterator over all modules
    pub fn iter_modules(&self) -> impl Iterator<Item = (ModuleInstanceId, &M)> {
        self.0.iter().map(|(id, m)| (*id, m))
    }

    pub fn get_mut(&mut self, key: &ModuleInstanceId) -> Option<&mut M> {
        self.0.get_mut(key)
    }

    /// Return the server module belonging to the module identified by the supplied `module_key`
    ///
    /// # Panics
    /// If the module isn't in the registry
    pub fn get(&self, module_key: ModuleInstanceId) -> &M {
        self.0
            .get(&module_key)
            .expect("CIs were decoded, so the module exists")
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

    // TODO: move into `ModuleRegistry` impl by splitting `module_key` fn into separate trait
    /// Add a module to the registry
    pub fn register_module(&mut self, id: ModuleInstanceId, module: DynServerModule) {
        assert!(
            self.0.insert(id, module).is_none(),
            "Module was already registered!"
        )
    }
}

/// Collection of decoders belonging to modules, typically obtained from a `ModuleRegistry`
#[derive(Debug, Default, Clone)]
pub struct ModuleDecoderRegistry(BTreeMap<ModuleInstanceId, Decoder>);

impl ModuleDecoderRegistry {
    /// Return the decoder belonging to the module identified by the supplied `module_key`
    ///
    /// # Panics
    /// If the decoder isn't in the registry
    pub fn get(&self, module_key: ModuleInstanceId) -> &Decoder {
        self.0.get(&module_key).expect("Module not found")
    }
}

impl FromIterator<(ModuleInstanceId, Decoder)> for ModuleDecoderRegistry {
    fn from_iter<T: IntoIterator<Item = (ModuleInstanceId, Decoder)>>(iter: T) -> Self {
        ModuleDecoderRegistry(iter.into_iter().collect())
    }
}
