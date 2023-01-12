use std::collections::BTreeMap;

use crate::core::Decoder;
pub use crate::core::ModuleInstanceId;
use crate::server::DynServerModule;

/// Define a registry type, with some common methods
macro_rules! impl_registry_common {
    (
        $(#[$outer:meta])*
        struct $name:ident$(<$bound:ident>)?($t:ident)
    ) => {
        $(#[$outer])*
        #[derive(Debug, Clone)]
        pub struct $name$(<$bound>)?(BTreeMap<ModuleInstanceId, $t>);


        impl$(<$bound>)? $name$(<$bound>)? {

            /// Create from an iterator of values
            pub fn new(decoders: impl IntoIterator<Item = (ModuleInstanceId, $t)>) -> Self {
                Self(decoders.into_iter().collect())
            }

            /// Return $t for a given `id`
            ///
            /// # Panics
            /// If the module isn't in the registry
            pub fn get(&self, id: ModuleInstanceId) -> &$t {
                self.0
                    .get(&id)
                    .expect("CIs were decoded, so the module exists")
            }

            pub fn get_mut(&mut self, key: &ModuleInstanceId) -> Option<&mut $t> {
                self.0.get_mut(key)
            }

            /// Iterator over all elements
            // The struct using this macro is free to define a better alias
            #[allow(dead_code)]
            fn iter(&self) -> impl Iterator<Item = (ModuleInstanceId, &$t)> {
                self.0.iter().map(|(id, v)| (*id, v))
            }
        }

        impl$(<$bound>)? Default for $name$(<$bound>)? {
            fn default() -> Self {
                Self(BTreeMap::new())
            }
        }

        impl$(<$bound>)? From<BTreeMap<ModuleInstanceId, $t>> for $name$(<$bound>)? {
            fn from(value: BTreeMap<ModuleInstanceId, $t>) -> Self {
                Self(value)
            }
        }

        impl$(<$bound>)? FromIterator<(ModuleInstanceId, $t)> for $name$(<$bound>)? {
            fn from_iter<T: IntoIterator<Item = (ModuleInstanceId, $t)>>(iter: T) -> Self {
                Self(iter.into_iter().collect())
            }
        }
    };
}

/// Define a custom-named alias to `Self::iter`
// would be nicer with `concat_idents` but that's unstable
macro_rules! impl_registry_iter_alias{
    (
        $name:ident$(<$bound:ident>)?($t:ident)::$method:ident
    ) => {
        impl$(<$bound>)? $name$(<$bound>)? {
            /// Iterator over all modules
            pub fn $method(&self) -> impl Iterator<Item = (ModuleInstanceId, &$t)> {
                self.iter()
            }
        }
    }
}

impl_registry_common! {
    /// Collection of decoders for their corresponding modules
    struct ModuleDecoderRegistry(Decoder)
}

impl_registry_iter_alias! {
    ModuleDecoderRegistry(Decoder)::iter_decoders
}

impl_registry_common! {
    /// Collection of fedimint modules - either client or server side
    struct Registry<M>(M)
}

impl_registry_iter_alias! {
    Registry<M>(M)::iter_modules
}

/// Collection of server modules
pub type ServerModuleRegistry = Registry<DynServerModule>;

impl ServerModuleRegistry {
    /// Generate a `ModuleDecoderRegistry` from this `ModuleRegistry`
    pub fn decoder_registry(&self) -> ModuleDecoderRegistry {
        // TODO: cache decoders
        ModuleDecoderRegistry::from_iter(self.0.iter().map(|(&id, module)| (id, module.decoder())))
    }

    /// Add a module to the registry
    pub fn register_module(&mut self, id: ModuleInstanceId, module: DynServerModule) {
        assert!(
            self.0.insert(id, module).is_none(),
            "Module was already registered!"
        )
    }
}
