use std::collections::BTreeSet;
use std::sync::Arc;

use fedimint_core::core::ModuleInstanceId;
use fedimint_core::module::ApiRequestErased;
use fedimint_core::task::{MaybeSend, MaybeSync};
use fedimint_core::{apply, async_trait_maybe_send, maybe_add_send_sync, PeerId};
use serde_json::Value;

use super::super::{DynModuleApi, IRawFederationApi};
use crate::api::PeerResult;

/// "Api Request Hook"
///
/// An "api request hook" is a function that gets a raw federation api and
/// can either pass it unmodified (no hook) or wrap it in whatever custom
/// logic and return as a new raw federation api, possibly forwarding the call
/// to the original one.
///
/// This is meant to allow downstream users to add custom logic for debugging,
/// testing (e.g. simulating network being down), collecting stats, notifing
/// about slow calls, errors, etc.
pub type ApiRequestHook =
    Arc<maybe_add_send_sync!(dyn Fn(DynIRawFederationApi) -> DynIRawFederationApi + 'static)>;

pub type DynIRawFederationApi = Box<maybe_add_send_sync!(dyn IRawFederationApi + 'static)>;

/// Convenience extension trait used for wrapping [`IRawFederationApi`] in
/// a [`RawFederationApiWithRequestHook`]
pub trait RawFederationApiWithRequestHookExt
where
    Self: Sized,
{
    fn with_request_hook(self, hook: &ApiRequestHook) -> RawFederationApiWithRequestHook;
}

impl<T> RawFederationApiWithRequestHookExt for T
where
    T: IRawFederationApi + MaybeSend + MaybeSync + 'static,
{
    fn with_request_hook(self, hook: &ApiRequestHook) -> RawFederationApiWithRequestHook {
        RawFederationApiWithRequestHook::new(self, hook)
    }
}

/// [`IRawFederationApi`] wrapping some `T: IRawFederationApi` in a user hook
///
/// Use [`RawFederationApiWithRequestHookExt::with_request_hook`] to
/// create.
#[derive(Debug)]
pub struct RawFederationApiWithRequestHook {
    pub(crate) inner: DynIRawFederationApi,
}

impl RawFederationApiWithRequestHook {
    pub fn new<T>(inner: T, hook: &ApiRequestHook) -> RawFederationApiWithRequestHook
    where
        T: IRawFederationApi + MaybeSend + MaybeSync + 'static,
    {
        RawFederationApiWithRequestHook {
            inner: hook(Box::new(inner)),
        }
    }
}

#[apply(async_trait_maybe_send!)]
impl IRawFederationApi for RawFederationApiWithRequestHook {
    fn all_peers(&self) -> &BTreeSet<PeerId> {
        self.inner.all_peers()
    }

    fn self_peer(&self) -> Option<PeerId> {
        self.inner.self_peer()
    }

    fn with_module(&self, id: ModuleInstanceId) -> DynModuleApi {
        self.inner.with_module(id)
    }

    async fn request_raw(
        &self,
        peer_id: PeerId,
        method: &str,
        params: &ApiRequestErased,
    ) -> PeerResult<Value> {
        self.inner.request_raw(peer_id, method, params).await
    }
}
