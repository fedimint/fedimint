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
macro_rules! dyn_newtype_impl_dyn_clone_passhthrough_with_instance_id {
    ($name:ident) => {
        impl Clone for $name {
            fn clone(&self) -> Self {
                self.inner.clone(self.module_instance_id)
            }
        }
    };
}
