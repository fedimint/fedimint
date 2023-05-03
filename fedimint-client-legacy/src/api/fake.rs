use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::pin::Pin;
use std::sync::Arc;

use async_trait::async_trait;
use fedimint_core::api::{DynFederationApi, IFederationApi, JsonRpcResult};
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::module::ApiRequest;
use fedimint_core::PeerId;
use futures::Future;
use jsonrpsee_types::error::INVALID_PARAMS_CODE;
use jsonrpsee_types::ErrorObjectOwned;
use serde;
use serde::Serialize;
use serde_json::Value;
use tracing::{info, warn};

#[allow(clippy::type_complexity)]
type Handler<State> = Pin<
    Box<
        dyn Fn(
                Arc<State>,
                Vec<Value>,
            )
                -> Pin<Box<dyn Future<Output = jsonrpsee_core::RpcResult<serde_json::Value>> + Send>>
            + Send
            + Sync,
    >,
>;

/// A fake [`super::IFederationApi`] builder
///
/// This struct allows easily stubbing responses to given API calls,
/// by listing a list of handlers for methods that are expected to be.
pub struct FederationApiFaker<State> {
    state: Arc<State>,
    members: BTreeSet<PeerId>,
    handlers: BTreeMap<String, Handler<State>>,
}

impl<State> fmt::Debug for FederationApiFaker<State> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FederationApiFaker")
    }
}

impl<State> FederationApiFaker<State>
where
    State: fmt::Debug,
{
    pub fn new(state: Arc<State>, members: BTreeSet<PeerId>) -> Self {
        Self {
            state,
            members,
            handlers: BTreeMap::default(),
        }
    }

    /// Add a handler `f` to a `method ` call
    pub fn with<F, Fut, Param, Ret>(mut self, method: impl Into<String>, f: F) -> Self
    where
        State: Send + Sync + 'static,
        F: Fn(Arc<State>, Param) -> Fut + Send + Sync + 'static + Copy,
        Fut: Future<Output = jsonrpsee_core::RpcResult<Ret>> + std::marker::Send + 'static,
        Param: serde::de::DeserializeOwned + Send + Sync,
        Ret: Serialize,
    {
        self.handlers.insert(
            method.into(),
            Box::pin(move |state, params| {
                Box::pin(async move {
                    if params.len() != 1 {
                        return Err(ErrorObjectOwned::owned(
                            INVALID_PARAMS_CODE,
                            "wrong number of arguments".to_string(),
                            None::<()>,
                        ));
                    }

                    let request: ApiRequest<Param> = serde_json::from_value(
                        params.first().expect("just checked the len").clone(),
                    )
                    .expect("parses");
                    let ret = f(state, request.params).await?;
                    let ret = serde_json::to_value(ret)
                        .expect("Serialization of the return value must not fail");

                    Ok(ret)
                })
            }),
        );
        self
    }
}

#[cfg_attr(target_family = "wasm", async_trait(? Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
impl<State> IFederationApi for FederationApiFaker<State>
where
    State: fmt::Debug + Send + Sync,
{
    fn all_members(&self) -> &BTreeSet<PeerId> {
        &self.members
    }

    fn with_module(&self, _id: ModuleInstanceId) -> DynFederationApi {
        unimplemented!()
    }

    async fn request_raw(
        &self,
        _peer_id: PeerId,
        method: &str,
        params: &[Value],
    ) -> JsonRpcResult<Value> {
        if let Some(handler) = self.handlers.get(method) {
            info!(
                method,
                params = serde_json::to_string(&params).expect("serialization not to fail"),
                "Faker is handling an API call"
            );
            handler(self.state.clone(), params.to_owned())
                .await
                .map_err(jsonrpsee_core::Error::Call)
        } else {
            warn!(
                method,
                params = serde_json::to_string(&params).expect("serialization not to fail"),
                "Faker has no handler for the API call"
            );
            Err(jsonrpsee_core::Error::MethodNotFound(method.into()))
        }
    }
}
