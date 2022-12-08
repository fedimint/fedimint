use std::collections::BTreeMap;

use crate::core::Decoder;
use crate::server::ServerModule;

// TODO: unify and/or make a newtype?
/// Fedimint module identifier
pub type ModuleKey = u16;

#[derive(Debug, Clone)]
pub struct ModuleRegistry<M>(BTreeMap<ModuleKey, M>);

impl<M> Default for ModuleRegistry<M> {
    fn default() -> Self {
        ModuleRegistry(BTreeMap::new())
    }
}

impl<M> ModuleRegistry<M> {
    /// Return an iterator over all modules
    pub fn modules(&self) -> impl Iterator<Item = &M> {
        self.0.values()
    }

    /// Return the server module belonging to the module identified by the supplied `module_key`
    ///
    /// # Panics
    /// If the module isn't in the registry
    pub fn module(&self, module_key: ModuleKey) -> &M {
        self.0
            .get(&module_key)
            .expect("CIs were decoded, so the module exists")
    }
}

/// Collection of server modules
pub type ServerModuleRegistry = ModuleRegistry<ServerModule>;

impl ServerModuleRegistry {
    /// Generate a `ModuleDecoderRegistry` from this `ModuleRegistry`
    pub fn decoders(&self) -> ModuleDecoderRegistry {
        // TODO: cache decoders
        ModuleDecoderRegistry::new(self.0.iter().map(|(&id, module)| (id, module.decoder())))
    }

    // TODO: move into `ModuleRegistry` impl by splitting `module_key` fn into separate trait
    /// Add a module to the registry
    pub fn register(&mut self, module: ServerModule) {
        assert!(
            self.0.insert(module.module_key(), module).is_none(),
            "Module was already registered!"
        )
    }
}

/// Collection of decoders belonging to modules, typically obtained from a `ModuleRegistry`
#[derive(Debug, Default, Clone)]
pub struct ModuleDecoderRegistry(BTreeMap<ModuleKey, Decoder>);

impl ModuleDecoderRegistry {
    /// Create a `ModuleDecoderRegistry` from decoders
    pub fn new(decoders: impl IntoIterator<Item = (ModuleKey, Decoder)>) -> ModuleDecoderRegistry {
        ModuleDecoderRegistry(decoders.into_iter().collect())
    }

    /// Return the decoder belonging to the module identified by the supplied `module_key`
    ///
    /// # Panics
    /// If the decoder isn't in the registry
    pub fn decoder(&self, module_key: ModuleKey) -> &Decoder {
        self.0.get(&module_key).expect("Module not found")
    }
}
