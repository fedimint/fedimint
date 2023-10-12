/// Define "dyn newtype" (a newtype over `dyn Trait`)
///
/// This is a simple pattern that make working with `dyn Trait`s
/// easier, by hiding their details.
///
/// A "dyn newtype" `Deref`s to the underlying `&dyn Trait`, making
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
macro_rules! _dyn_newtype_define_inner {
    (   $(#[$outer:meta])*
        $vis:vis $name:ident($container:ident<$trait:ident>)
    ) => {
        $(#[$outer])*
        $vis struct $name { inner: $container<$crate::maybe_add_send_sync!(dyn $trait + 'static)> }

        impl std::ops::Deref for $name {
            type Target = $crate::maybe_add_send_sync!(dyn $trait + 'static);

            fn deref(&self) -> &<Self as std::ops::Deref>::Target {
                &*self.inner
            }

        }

        impl<I> From<I> for $name
        where
            I: $trait + $crate::task::MaybeSend + $crate::task::MaybeSync + 'static,
        {
            fn from(i: I) -> Self {
                Self { inner: $container::new(i) }
            }
        }

        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                std::fmt::Debug::fmt(&self.inner, f)
            }
        }
    };
    (   $(#[$outer:meta])*
        $vis:vis $name:ident<$lifetime:lifetime>($container:ident<$trait:ident>)
    ) => {
        $(#[$outer])*
        $vis struct $name<$lifetime> { inner: $container<dyn $trait<$lifetime> + Send + $lifetime> }

        impl<$lifetime> std::ops::Deref for $name<$lifetime> {
            type Target = $crate::maybe_add_send!(dyn $trait<$lifetime> + $lifetime);

            fn deref(&self) -> &<Self as std::ops::Deref>::Target {
                &*self.inner
            }
        }

        impl<$lifetime, I> From<I> for $name<$lifetime>
        where
            I: $trait<$lifetime> + $crate::task::MaybeSend + $lifetime,
        {
            fn from(i: I) -> Self {
                Self($container::new(i))
            }
        }
    };
}

/// Implements the `Display` trait for dyn newtypes whose traits implement
/// `Display`
#[macro_export]
macro_rules! dyn_newtype_display_passthrough {
    ($newtype:ty) => {
        impl std::fmt::Display for $newtype {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                std::fmt::Display::fmt(&self.inner, f)
            }
        }
    };
}

/// Define a "module plugin dyn-newtype" which is like a standard "dyn newtype",
/// but with associated "module_instance_id".
#[macro_export]
macro_rules! module_plugin_dyn_newtype_define{
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
macro_rules! _dyn_newtype_define_with_instance_id_inner {
    (   $(#[$outer:meta])*
        $vis:vis $name:ident($container:ident<$trait:ident>)
    ) => {
        $(#[$outer])*
        $vis struct $name {
            module_instance_id: $crate::core::ModuleInstanceId,
            inner: $container<$crate::maybe_add_send_sync!(dyn $trait + 'static)>,
        }

        impl std::ops::Deref for $name {
            type Target = $crate::maybe_add_send_sync!(dyn $trait + 'static);

            fn deref(&self) -> &<Self as std::ops::Deref>::Target {
                &*self.inner
            }

        }

        impl $name {
            pub fn module_instance_id(&self) -> ::fedimint_core::core::ModuleInstanceId {
                self.module_instance_id
            }

            pub fn from_typed<I>(module_instance_id: ::fedimint_core::core::ModuleInstanceId, typed: I) -> Self
            where
                I: $trait + $crate::task::MaybeSend + $crate::task::MaybeSync + 'static {

                Self { inner: $container::new(typed), module_instance_id }
            }

            pub fn from_parts(module_instance_id: $crate::core::ModuleInstanceId, dynbox: $container<$crate::maybe_add_send_sync!(dyn $trait + 'static)>) -> Self {
                Self { inner: dynbox, module_instance_id }
            }
        }

        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                std::fmt::Debug::fmt(&self.inner, f)
            }
        }
    };
    (   $(#[$outer:meta])*
        $vis:vis $name:ident<$lifetime:lifetime>($container:ident<$trait:ident>)
    ) => {
        $(#[$outer])*
        $vis struct $name<$lifetime>{ inner: $container<dyn $trait<$lifetime> + Send + $lifetime>, module_instance_id: ModuleInstanceId }

        impl $name {
            pub fn module_instance_id(&self) -> ::fedimint_core::core::ModuleInstanceId {
                self.1
            }

            pub fn from_typed<I>(module_instance_id: ::fedimint_core::core::ModuleInstanceId, typed: I) -> Self
            where
                I: $trait + $crate::task::MaybeSend + $crate::task::MaybeSync + 'static {

                Self { inner: $container::new(typed), module_instance_id }
            }
        }

        impl<$lifetime> std::ops::Deref for $name<$lifetime> {
            type Target = $crate::maybe_add_send_sync!(dyn $trait + 'static);

            fn deref(&self) -> &<Self as std::ops::Deref>::Target {
                &*self.inner
            }
        }
    };
}

#[macro_export]
macro_rules! _dyn_newtype_impl_deref_mut {
    ($name:ident<$lifetime:lifetime>) => {
        impl<$lifetime> std::ops::DerefMut for $name<$lifetime> {
            fn deref_mut(&mut self) -> &mut <Self as std::ops::Deref>::Target {
                &mut *self.inner
            }
        }
    };
    ($name:ident) => {
        impl std::ops::DerefMut for $name {
            fn deref_mut(&mut self) -> &mut <Self as std::ops::Deref>::Target {
                &mut *self.inner
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
macro_rules! module_plugin_dyn_newtype_clone_passhthrough {
    ($name:ident) => {
        impl Clone for $name {
            fn clone(&self) -> Self {
                self.inner.clone(self.module_instance_id)
            }
        }
    };
}

/// Implement `Encodable` and `Decodable` for a "module dyn newtype"
///
/// "Module dyn newtype" is just a "dyn newtype" used by general purpose
/// Fedimint code to abstract away details of mint modules.
#[macro_export]
macro_rules! module_plugin_dyn_newtype_encode_decode {
    ($name:ident) => {
        impl Encodable for $name {
            fn consensus_encode<W: std::io::Write>(
                &self,
                writer: &mut W,
            ) -> Result<usize, std::io::Error> {
                let mut written = self.module_instance_id.consensus_encode(writer)?;

                let mut buf = Vec::with_capacity(512);
                let buf_written = self.inner.consensus_encode_dyn(&mut buf)?;
                assert_eq!(buf.len(), buf_written);

                written += buf.consensus_encode(writer)?;

                Ok(written)
            }
        }

        impl Decodable for $name {
            fn consensus_decode<R: std::io::Read>(
                reader: &mut R,
                modules: &$crate::module::registry::ModuleDecoderRegistry,
            ) -> Result<Self, fedimint_core::encoding::DecodeError> {
                let module_instance_id =
                    fedimint_core::core::ModuleInstanceId::consensus_decode(reader, modules)?;
                let val = match modules.get(module_instance_id) {
                    Some(decoder) => {
                        let total_len_u64 = u64::consensus_decode(reader, modules)?;
                        let mut reader = reader.take(total_len_u64);
                        let v = decoder.decode(&mut reader, module_instance_id, modules)?;

                        if reader.limit() != 0 {
                            return Err(fedimint_core::encoding::DecodeError::new_custom(
                                anyhow::anyhow!(
                                    "Dyn type did not consume all bytes during decoding"
                                ),
                            ));
                        }

                        v
                    }
                    None => match modules.decoding_mode() {
                        $crate::module::registry::DecodingMode::Reject => {
                            return Err(fedimint_core::encoding::DecodeError::new_custom(
                                anyhow::anyhow!(
                                    "Module decoder not available: {module_instance_id}"
                                ),
                            ));
                        }
                        $crate::module::registry::DecodingMode::Fallback => $name::from_typed(
                            module_instance_id,
                            $crate::core::DynUnknown(Vec::<u8>::consensus_decode(
                                reader,
                                &Default::default(),
                            )?),
                        ),
                    },
                };

                Ok(val)
            }
        }
    };
}

/// Define a "plugin" trait
///
/// "Plugin trait" is a trait that a developer of a mint module
/// needs to implement when implementing mint module. It uses associated
/// types with trait bounds to guide the developer.
///
/// Blanket implementations are used to convert the "plugin trait",
/// incompatible with `dyn Trait` into "module types" and corresponding
/// "module dyn newtypes", erasing the exact type and used in a common
/// Fedimint code.
#[macro_export]
macro_rules! module_plugin_static_trait_define{
    (   $(#[$outer:meta])*
        $dyn_newtype:ident, $static_trait:ident, $dyn_trait:ident, { $($extra_methods:tt)* }, { $($extra_impls:tt)* }
    ) => {
        pub trait $static_trait:
            std::fmt::Debug + std::fmt::Display + std::cmp::PartialEq + std::hash::Hash + DynEncodable + Decodable + Encodable + Clone + IntoDynInstance<DynType = $dyn_newtype> + Send + Sync + 'static
        {
            $($extra_methods)*
        }

        impl $dyn_trait for ::fedimint_core::core::DynUnknown {
            fn as_any(&self) -> &(dyn Any + Send + Sync) {
                self
            }

            fn clone(&self, instance_id: ::fedimint_core::core::ModuleInstanceId) -> $dyn_newtype {
                $dyn_newtype::from_typed(instance_id, <Self as Clone>::clone(self))
            }

            fn dyn_hash(&self) -> u64 {
                use std::hash::Hash;
                let mut s = std::collections::hash_map::DefaultHasher::new();
                self.hash(&mut s);
                std::hash::Hasher::finish(&s)
            }

            $($extra_impls)*
        }

        impl<T> $dyn_trait for T
        where
            T: $static_trait + DynEncodable + 'static + Send + Sync,
        {
            fn as_any(&self) -> &(dyn Any + Send + Sync) {
                self
            }

            fn clone(&self, instance_id: ::fedimint_core::core::ModuleInstanceId) -> $dyn_newtype {
                $dyn_newtype::from_typed(instance_id, <Self as Clone>::clone(self))
            }

            fn dyn_hash(&self) -> u64 {
                let mut s = std::collections::hash_map::DefaultHasher::new();
                self.hash(&mut s);
                std::hash::Hasher::finish(&s)
            }

            $($extra_impls)*
        }

        impl std::hash::Hash for $dyn_newtype {
            fn hash<H>(&self, state: &mut H)
            where
                H: std::hash::Hasher
            {
                self.module_instance_id.hash(state);
                self.inner.dyn_hash().hash(state);
            }
        }
    };
}

/// A copy of `module_lugin_static_trait_define` but for `ClientConfig`, which
/// is a snowflake that requires `: Serialize` and conditional implementation
/// for `DynUnknown`. The macro is getting gnarly, so seems easier to
/// copy-paste-modify, than pile up conditional argument.
#[macro_export]
macro_rules! module_plugin_static_trait_define_config{
    (   $(#[$outer:meta])*
        $dyn_newtype:ident, $static_trait:ident, $dyn_trait:ident, { $($extra_methods:tt)* }, { $($extra_impls:tt)* }, { $($extra_impls_unknown:tt)* }
    ) => {
        pub trait $static_trait:
            std::fmt::Debug + std::fmt::Display + std::cmp::PartialEq + std::hash::Hash + DynEncodable + Decodable + Encodable + Clone + IntoDynInstance<DynType = $dyn_newtype> + Send + Sync + serde::Serialize + serde::de::DeserializeOwned + 'static
        {
            $($extra_methods)*
        }

        impl $dyn_trait for ::fedimint_core::core::DynUnknown {
            fn as_any(&self) -> &(dyn Any + Send + Sync) {
                self
            }

            fn clone(&self, instance_id: ::fedimint_core::core::ModuleInstanceId) -> $dyn_newtype {
                $dyn_newtype::from_typed(instance_id, <Self as Clone>::clone(self))
            }

            fn dyn_hash(&self) -> u64 {
                use std::hash::Hash;
                let mut s = std::collections::hash_map::DefaultHasher::new();
                self.hash(&mut s);
                std::hash::Hasher::finish(&s)
            }

            $($extra_impls_unknown)*
        }

        impl<T> $dyn_trait for T
        where
            T: $static_trait + DynEncodable + 'static + Send + Sync,
        {
            fn as_any(&self) -> &(dyn Any + Send + Sync) {
                self
            }

            fn clone(&self, instance_id: ::fedimint_core::core::ModuleInstanceId) -> $dyn_newtype {
                $dyn_newtype::from_typed(instance_id, <Self as Clone>::clone(self))
            }

            fn dyn_hash(&self) -> u64 {
                let mut s = std::collections::hash_map::DefaultHasher::new();
                self.hash(&mut s);
                std::hash::Hasher::finish(&s)
            }

            $($extra_impls)*
        }

        impl std::hash::Hash for $dyn_newtype {
            fn hash<H>(&self, state: &mut H)
            where
                H: std::hash::Hasher
            {
                self.module_instance_id.hash(state);
                self.inner.dyn_hash().hash(state);
            }
        }
    };
}

/// Implements the necessary traits for all configuration related types of a
/// `FederationServer` module.
#[macro_export]
macro_rules! plugin_types_trait_impl_config {
    ($common_gen:ty, $gen:ty, $gen_local:ty, $gen_consensus:ty, $cfg:ty, $cfg_local:ty, $cfg_private:ty, $cfg_consensus:ty, $cfg_client:ty) => {
        impl fedimint_core::config::ModuleInitParams for $gen {
            type Local = $gen_local;
            type Consensus = $gen_consensus;

            fn from_parts(local: Self::Local, consensus: Self::Consensus) -> Self {
                Self { local, consensus }
            }

            fn to_parts(self) -> (Self::Local, Self::Consensus) {
                (self.local, self.consensus)
            }
        }

        impl fedimint_core::config::TypedServerModuleConsensusConfig for $cfg_consensus {
            fn kind(&self) -> fedimint_core::core::ModuleKind {
                <$common_gen as fedimint_core::module::CommonModuleInit>::KIND
            }

            fn version(&self) -> fedimint_core::module::ModuleConsensusVersion {
                <$common_gen as fedimint_core::module::CommonModuleInit>::CONSENSUS_VERSION
            }
        }

        impl fedimint_core::config::TypedServerModuleConfig for $cfg {
            type Local = $cfg_local;
            type Private = $cfg_private;
            type Consensus = $cfg_consensus;

            fn from_parts(
                local: Self::Local,
                private: Self::Private,
                consensus: Self::Consensus,
            ) -> Self {
                Self {
                    local,
                    private,
                    consensus,
                }
            }

            fn to_parts(self) -> (ModuleKind, Self::Local, Self::Private, Self::Consensus) {
                (
                    <$common_gen as fedimint_core::module::CommonModuleInit>::KIND,
                    self.local,
                    self.private,
                    self.consensus,
                )
            }
        }
    };
}

/// Implements the necessary traits for all associated types of a
/// `FederationServer` module.
#[macro_export]
macro_rules! plugin_types_trait_impl_common {
    ($types:ty, $client_config:ty, $input:ty, $output:ty, $outcome:ty, $ci:ty) => {
        impl fedimint_core::module::ModuleCommon for $types {
            type ClientConfig = $client_config;
            type Input = $input;
            type Output = $output;
            type OutputOutcome = $outcome;
            type ConsensusItem = $ci;
        }

        impl fedimint_core::core::ClientConfig for $client_config {}

        impl fedimint_core::core::IntoDynInstance for $client_config {
            type DynType = fedimint_core::core::DynClientConfig;

            fn into_dyn(self, instance_id: ModuleInstanceId) -> Self::DynType {
                fedimint_core::core::DynClientConfig::from_typed(instance_id, self)
            }
        }

        impl fedimint_core::core::Input for $input {}

        impl fedimint_core::core::IntoDynInstance for $input {
            type DynType = fedimint_core::core::DynInput;

            fn into_dyn(self, instance_id: ModuleInstanceId) -> Self::DynType {
                fedimint_core::core::DynInput::from_typed(instance_id, self)
            }
        }

        impl fedimint_core::core::Output for $output {}

        impl fedimint_core::core::IntoDynInstance for $output {
            type DynType = fedimint_core::core::DynOutput;

            fn into_dyn(self, instance_id: ModuleInstanceId) -> Self::DynType {
                fedimint_core::core::DynOutput::from_typed(instance_id, self)
            }
        }

        impl fedimint_core::core::OutputOutcome for $outcome {}

        impl fedimint_core::core::IntoDynInstance for $outcome {
            type DynType = fedimint_core::core::DynOutputOutcome;

            fn into_dyn(self, instance_id: ModuleInstanceId) -> Self::DynType {
                fedimint_core::core::DynOutputOutcome::from_typed(instance_id, self)
            }
        }

        impl fedimint_core::core::ModuleConsensusItem for $ci {}

        impl fedimint_core::core::IntoDynInstance for $ci {
            type DynType = fedimint_core::core::DynModuleConsensusItem;

            fn into_dyn(self, instance_id: ModuleInstanceId) -> Self::DynType {
                fedimint_core::core::DynModuleConsensusItem::from_typed(instance_id, self)
            }
        }
    };
}

#[macro_export]
macro_rules! erased_eq_no_instance_id {
    ($newtype:ty) => {
        fn erased_eq_no_instance_id(&self, other: &$newtype) -> bool {
            let other: &Self = other
                .as_any()
                .downcast_ref()
                .expect("Type is ensured in previous step");

            self == other
        }
    };
}

#[macro_export]
macro_rules! module_plugin_dyn_newtype_eq_passthrough {
    ($newtype:ty) => {
        impl PartialEq for $newtype {
            fn eq(&self, other: &Self) -> bool {
                if self.module_instance_id != other.module_instance_id {
                    return false;
                }
                self.erased_eq_no_instance_id(other)
            }
        }

        impl Eq for $newtype {}
    };
}

#[macro_export]
macro_rules! module_plugin_dyn_newtype_display_passthrough {
    ($newtype:ty) => {
        impl std::fmt::Display for $newtype {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_fmt(format_args!("{}-{}", self.module_instance_id, self.inner))
            }
        }
    };
}
