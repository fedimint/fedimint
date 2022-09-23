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
        $name:ident($container:ident<$trait:ident>)
    ) => {
        $(#[$outer])*
        pub struct $name($container<dyn $trait + Send + Sync + 'static>);

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

    }
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
    (
        $name:ident
    ) => {
        impl Clone for $name {
            fn clone(&self) -> Self {
                self.0.clone()
            }
        }
    };
}
