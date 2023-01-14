/// Define "dyn newtype" (a newtype over `dyn Trait`)
///
/// This is a simple pattern that make working with `dyn Trait`s
/// easier, by hiding their details.
///
/// A "dyn newtype" `Deref`s to the underlying`&dyn Trait`, making
/// it easy to access the encapsulated operations, while hiding
/// the boxing details.
#[macro_export]
macro_rules! dyn_newtype_define {
    (   $(#[$outer:meta])*
        $vis:vis $name:ident<$lifetime:lifetime>(Box<$trait:ident>)
    ) => {
        $crate::_dyn_newtype_define_inner!{
            $(#[$outer])*
            $vis $name<$lifetime>(Box<$trait>)
        }
        $crate::_dyn_newtype_impl_deref_mut!($name<$lifetime>);
    };
    (   $(#[$outer:meta])*
        $vis:vis $name:ident(Box<$trait:ident>)
    ) => {
        $crate::_dyn_newtype_define_inner!{
            $(#[$outer])*
            $vis $name(Box<$trait>)
        }
        $crate::_dyn_newtype_impl_deref_mut!($name);
    };
    (   $(#[$outer:meta])*
        $vis:vis $name:ident<$lifetime:lifetime>(Arc<$trait:ident>)
    ) => {
        $crate::_dyn_newtype_define_inner!{
            $(#[$outer])*
            $vis $name<$lifetime>(Arc<$trait>)
        }
    };
    (   $(#[$outer:meta])*
        $vis:vis $name:ident(Arc<$trait:ident>)
    ) => {
        $crate::_dyn_newtype_define_inner!{
            $(#[$outer])*
            $vis $name(Arc<$trait>)
        }
    };
}

#[macro_export]
macro_rules! dyn_newtype_define_with_instance_id{
    (   $(#[$outer:meta])*
        $vis:vis $name:ident<$lifetime:lifetime>(Box<$trait:ident>)
    ) => {
        $crate::_dyn_newtype_define_with_instance_id_inner!{
            $(#[$outer])*
            $vis $name<$lifetime>(Box<$trait>)
        }
        $crate::_dyn_newtype_impl_deref_mut!($name<$lifetime>);
    };
    (   $(#[$outer:meta])*
        $vis:vis $name:ident(Box<$trait:ident>)
    ) => {
        $crate::_dyn_newtype_define_with_instance_id_inner!{
            $(#[$outer])*
            $vis $name(Box<$trait>)
        }
        $crate::_dyn_newtype_impl_deref_mut!($name);
    };
    (   $(#[$outer:meta])*
        $vis:vis $name:ident<$lifetime:lifetime>(Arc<$trait:ident>)
    ) => {
        $crate::_dyn_newtype_define_with_instance_id_inner!{
            $(#[$outer])*
            $vis $name<$lifetime>(Arc<$trait>)
        }
    };
    (   $(#[$outer:meta])*
        $vis:vis $name:ident(Arc<$trait:ident>)
    ) => {
        $crate::_dyn_newtype_define_with_instance_id_inner!{
            $(#[$outer])*
            $vis $name(Arc<$trait>)
        }
    };
}

#[macro_export]
macro_rules! _dyn_newtype_define_inner {
    (   $(#[$outer:meta])*
        $vis:vis $name:ident($container:ident<$trait:ident>)
    ) => {
        $(#[$outer])*
        $vis struct $name($container<dyn $trait + Send + Sync + 'static>);

        impl std::ops::Deref for $name {
            type Target = dyn $trait + Send + Sync + 'static;

            fn deref(&self) -> &<Self as std::ops::Deref>::Target {
                &*self.0
            }

        }

        impl<I> From<I> for $name
        where
            I: $trait + Send + Sync + 'static,
        {
            fn from(i: I) -> Self {
                Self($container::new(i))
            }
        }

        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                std::fmt::Debug::fmt(&self.0, f)
            }
        }
    };
    (   $(#[$outer:meta])*
        $vis:vis $name:ident<$lifetime:lifetime>($container:ident<$trait:ident>)
    ) => {
        $(#[$outer])*
        $vis struct $name<$lifetime>($container<dyn $trait<$lifetime> + Send + $lifetime>);

        impl<$lifetime> std::ops::Deref for $name<$lifetime> {
            type Target = dyn $trait<$lifetime> + Send + $lifetime;

            fn deref(&self) -> &<Self as std::ops::Deref>::Target {
                &*self.0
            }
        }

        impl<$lifetime, I> From<I> for $name<$lifetime>
        where
            I: $trait<$lifetime> + Send + $lifetime,
        {
            fn from(i: I) -> Self {
                Self($container::new(i))
            }
        }
    };
}

#[macro_export]
macro_rules! _dyn_newtype_define_with_instance_id_inner {
    (   $(#[$outer:meta])*
        $vis:vis $name:ident($container:ident<$trait:ident>)
    ) => {
        $(#[$outer])*
        $vis struct $name($container<dyn $trait + Send + Sync + 'static>, ::fedimint_api::core::ModuleInstanceId);

        impl std::ops::Deref for $name {
            type Target = dyn $trait + Send + Sync + 'static;

            fn deref(&self) -> &<Self as std::ops::Deref>::Target {
                &*self.0
            }

        }

        impl $name {
            pub fn module_instance_id(&self) -> ::fedimint_api::core::ModuleInstanceId {
                self.1
            }

            pub fn from_typed<I>(module_instance_id: ::fedimint_api::core::ModuleInstanceId, typed: I) -> Self
            where
                I: $trait + Send + Sync + 'static {

                Self($container::new(typed), module_instance_id)
            }
        }

        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                std::fmt::Debug::fmt(&self.0, f)
            }
        }
    };
    (   $(#[$outer:meta])*
        $vis:vis $name:ident<$lifetime:lifetime>($container:ident<$trait:ident>)
    ) => {
        $(#[$outer])*
        $vis struct $name<$lifetime>($container<dyn $trait<$lifetime> + Send + $lifetime>, ModuleInstanceId);

        impl $name {
            pub fn module_instance_id(&self) -> ::fedimint_api::core::ModuleInstanceId {
                self.1
            }

            pub fn from_typed<I>(module_instance_id: ::fedimint_api::core::ModuleInstanceId, typed: I) -> Self
            where
                I: $trait + Send + Sync + 'static {

                Self($container::new(typed), module_instance_id)
            }
        }

        impl<$lifetime> std::ops::Deref for $name<$lifetime> {
            type Target = dyn $trait<$lifetime> + Send + $lifetime;

            fn deref(&self) -> &<Self as std::ops::Deref>::Target {
                &*self.0
            }
        }
    };
}

#[macro_export]
macro_rules! _dyn_newtype_impl_deref_mut {
    ($name:ident<$lifetime:lifetime>) => {
        impl<$lifetime> std::ops::DerefMut for $name<$lifetime> {
            fn deref_mut(&mut self) -> &mut <Self as std::ops::Deref>::Target {
                &mut *self.0
            }
        }
    };
    ($name:ident) => {
        impl std::ops::DerefMut for $name {
            fn deref_mut(&mut self) -> &mut <Self as std::ops::Deref>::Target {
                &mut *self.0
            }
        }
    };
}

/// Implement `Clone` on a "dyn newtype"
///
/// ... by calling `clone` method on the underlying
/// `dyn Trait`.
///
/// Cloning `dyn Trait`s is non trivial due to object-safety.
///
/// Note: the underlying `dyn Trait` needs to implement
/// a `fn clone(&self) -> Newtype` for this to work,
/// and this macro does not check or do anything about it.
///
/// If the newtype is using `Arc` you probably want
/// to just use standard `#[derive(Clone)]` to clone
/// the `Arc` itself.
#[macro_export]
macro_rules! dyn_newtype_impl_dyn_clone_passhthrough {
    ($name:ident) => {
        impl Clone for $name {
            fn clone(&self) -> Self {
                self.0.clone()
            }
        }
    };
}

#[macro_export]
macro_rules! dyn_newtype_impl_dyn_clone_passhthrough_with_instance_id {
    ($name:ident) => {
        impl Clone for $name {
            fn clone(&self) -> Self {
                self.0.clone(self.1)
            }
        }
    };
}

/// Creates a struct that can be used to make our module-decodable structs interact with
/// `serde`-based APIs (HBBFT, jsonrpsee). It creates a wrapper that holds the data as serialized
/// bytes internally.
#[macro_export]
macro_rules! serde_module_encoding_wrapper {
    ($wrapper_name:ident, $wrapped:ty) => {
        #[derive(Clone, Eq, PartialEq, Hash, serde::Serialize, serde::Deserialize)]
        pub struct $wrapper_name(#[serde(with = "hex::serde")] Vec<u8>);

        impl ::std::fmt::Debug for $wrapper_name {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                <_ as ::std::fmt::Display>::fmt(&$crate::fmt_utils::AbbreviateHexBytes(&self.0), f)
            }
        }

        impl From<&$wrapped> for $wrapper_name {
            fn from(eh: &$wrapped) -> Self {
                let mut bytes = vec![];
                fedimint_api::encoding::Encodable::consensus_encode(eh, &mut bytes)
                    .expect("Writing to buffer can never fail");
                $wrapper_name(bytes)
            }
        }

        impl $wrapper_name {
            pub fn try_into_inner(
                &self,
                modules: &fedimint_api::module::registry::ModuleDecoderRegistry,
            ) -> Result<$wrapped, fedimint_api::encoding::DecodeError> {
                let mut reader = std::io::Cursor::new(&self.0);
                fedimint_api::encoding::Decodable::consensus_decode(&mut reader, modules)
            }
        }
    };
}
