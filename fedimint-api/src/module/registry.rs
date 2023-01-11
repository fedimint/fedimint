use std::collections::BTreeMap;

use crate::core::{Decoder, ModuleInstanceId};
use crate::server::ServerModule;

// TODO: unify and/or make a newtype?
/// Fedimint module identifier
pub type ModuleKey = u16;

#[derive(Debug, Clone)]
pub struct ModuleRegistry<M>(BTreeMap<ModuleInstanceId, M>);

impl<M> Default for ModuleRegistry<M> {
    fn default() -> Self {
        ModuleRegistry(BTreeMap::new())
    }
}

impl<M> From<BTreeMap<ModuleKey, M>> for ModuleRegistry<M> {
    fn from(value: BTreeMap<ModuleKey, M>) -> Self {
        Self(value)
    }
}

impl<M> ModuleRegistry<M> {
    pub fn new(decoders: impl IntoIterator<Item = (ModuleKey, M)>) -> Self {
        Self(decoders.into_iter().collect())
    }

    /// Return an iterator over all modules
    pub fn iter_modules(&self) -> impl Iterator<Item = (ModuleInstanceId, &M)> {
        self.0.iter().map(|(id, m)| (*id, m))
    }

    pub fn get_mut(&mut self, key: &ModuleKey) -> Option<&mut M> {
        self.0.get_mut(key)
    }

    /// Return the server module belonging to the module identified by the supplied `module_key`
    ///
    /// # Panics
    /// If the module isn't in the registry
    pub fn get(&self, module_key: ModuleKey) -> &M {
        self.0
            .get(&module_key)
            .expect("CIs were decoded, so the module exists")
    }
}

/// Collection of server modules
pub type ServerModuleRegistry = ModuleRegistry<ServerModule>;

impl ServerModuleRegistry {
    /// Generate a `ModuleDecoderRegistry` from this `ModuleRegistry`
    pub fn decoder_registry(&self) -> ModuleDecoderRegistry {
        // TODO: cache decoders
        ModuleDecoderRegistry::from_iter(self.0.iter().map(|(&id, module)| (id, module.decoder())))
    }

    // TODO: move into `ModuleRegistry` impl by splitting `module_key` fn into separate trait
    /// Add a module to the registry
    pub fn register_module(&mut self, id: ModuleInstanceId, module: ServerModule) {
        assert!(
            self.0.insert(id, module).is_none(),
            "Module was already registered!"
        )
    }
}

/// Collection of decoders belonging to modules, typically obtained from a `ModuleRegistry`
#[derive(Debug, Default, Clone)]
pub struct ModuleDecoderRegistry(BTreeMap<ModuleKey, Decoder>);

impl ModuleDecoderRegistry {
    /// Return the decoder belonging to the module identified by the supplied `module_key`
    ///
    /// # Panics
    /// If the decoder isn't in the registry
    pub fn get(&self, module_key: ModuleKey) -> &Decoder {
        self.0.get(&module_key).expect("Module not found")
    }
}

impl FromIterator<(ModuleKey, Decoder)> for ModuleDecoderRegistry {
    fn from_iter<T: IntoIterator<Item = (ModuleKey, Decoder)>>(iter: T) -> Self {
        ModuleDecoderRegistry(iter.into_iter().collect())
    }
}
