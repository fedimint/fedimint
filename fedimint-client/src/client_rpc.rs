use std::marker::PhantomData;
use std::{collections::BTreeMap, pin::Pin};

use anyhow::Context;
use fedimint_core::task::{MaybeSend, MaybeSync};
use fedimint_core::{apply, async_trait_maybe_send};
use futures::{Stream, StreamExt as _};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct RpcHandlerKey<'a> {
    // Q: should we use instance id instead of module kind?
    module: &'a str,
    method: &'a str,
}
pub struct Server<Ctx> {
    handlers: BTreeMap<RpcHandlerKey<'static>, Box<dyn DynClientRpcHandler<Ctx>>>,
}

impl<Ctx> Server<Ctx> {
    pub fn new() -> Self {
        Server {
            handlers: BTreeMap::new(),
        }
    }

    pub fn add_handler<HCtx, H: ClientRpcSingleHandler<HCtx>>(&mut self, handler: H)
    where
        HCtx: MaybeSend + MaybeSync + 'static,
        Ctx: MaybeSend + MaybeSync + AsRef<HCtx>,
        H: MaybeSend + MaybeSync + 'static,
    {
        let handler = Box::new(DynClientRpcHandlerWrapper(handler, PhantomData));
        self.handlers.insert(
            RpcHandlerKey {
                module: H::MODULE,
                method: H::METHOD,
            },
            handler,
        );
    }

    pub fn handle_request<'a>(
        &'a self,
        ctx: &'a Ctx,
        module: &'a str,
        method: &'a str,
        body: serde_json::Value,
    ) -> impl Stream<Item = anyhow::Result<serde_json::Value>> + 'a {
        if let Some(handler) = self.handlers.get(&RpcHandlerKey { module, method }) {
            handler.handle(ctx, body)
        } else {
            Box::pin(futures::stream::once(async {
                Err(anyhow::anyhow!("Handler not found"))
            }))
        }
    }
}

#[apply(async_trait_maybe_send!)]
pub trait ClientRpcHandler<Ctx> {
    const MODULE: &'static str;
    const METHOD: &'static str;
    type Response: serde::Serialize;
    type Request: serde::de::DeserializeOwned;

    fn handle<'a>(
        &'a self,
        ctx: &'a Ctx,
        request: Self::Request,
    ) -> impl Stream<Item = anyhow::Result<Self::Response>> + 'a;
}

#[apply(async_trait_maybe_send!)]
pub trait ClientRpcSingleHandler<Ctx> {
    const MODULE: &'static str;
    const METHOD: &'static str;
    type Response: serde::Serialize;
    type Request: serde::de::DeserializeOwned;

    async fn handle(&self, ctx: &Ctx, request: Self::Request) -> anyhow::Result<Self::Response>;
}

impl<Ctx, H> ClientRpcHandler<Ctx> for H
where
    H: ClientRpcSingleHandler<Ctx>,
{
    const MODULE: &'static str = <Self as ClientRpcSingleHandler<Ctx>>::MODULE;
    const METHOD: &'static str = <Self as ClientRpcSingleHandler<Ctx>>::METHOD;
    type Response = <Self as ClientRpcSingleHandler<Ctx>>::Response;
    type Request = <Self as ClientRpcSingleHandler<Ctx>>::Request;

    fn handle<'a>(
        &'a self,
        ctx: &'a Ctx,
        request: Self::Request,
    ) -> impl Stream<Item = anyhow::Result<Self::Response>> + 'a {
        futures::stream::once(ClientRpcSingleHandler::handle(self, ctx, request))
    }
}
pub trait DynClientRpcHandler<Ctx>: MaybeSend + MaybeSync {
    fn handle<'a>(
        &'a self,
        ctx: &'a Ctx,
        request: serde_json::Value,
    ) -> Pin<Box<dyn Stream<Item = anyhow::Result<serde_json::Value>> + 'a>>;
}

struct DynClientRpcHandlerWrapper<Ctx, H>(H, PhantomData<fn(Ctx) -> Ctx>);
impl<Ctx, CtxOuter, H> DynClientRpcHandler<CtxOuter> for DynClientRpcHandlerWrapper<Ctx, H>
where
    H: ClientRpcHandler<Ctx> + MaybeSend + MaybeSync,
    Ctx: MaybeSync,
    CtxOuter: AsRef<Ctx> + MaybeSync,
{
    fn handle<'a>(
        &'a self,
        ctx: &'a CtxOuter,
        request: serde_json::Value,
    ) -> Pin<Box<dyn Stream<Item = anyhow::Result<serde_json::Value>> + 'a>> {
        Box::pin(async_stream::stream! {
            let Ok(request) = serde_json::from_value::<H::Request>(request) else {
                todo!()
            };
            let mut stream = std::pin::pin!(self.0.handle(ctx.as_ref(), request));

            while let Some(response) = stream.next().await {
                match response {
                    Ok(response) => {
                        yield serde_json::to_value(response).context("serde failed");
                    }
                    Err(err) => {
                        yield Err(err);
                    }
                }
            }
        })
    }
}

pub struct ClientBalanceRpc;

#[apply(async_trait_maybe_send!)]
impl ClientRpcSingleHandler<crate::Client> for ClientBalanceRpc {
    const MODULE: &'static str = "client";

    const METHOD: &'static str = "get_balance";

    type Response = u64;

    type Request = ();

    async fn handle(
        &self,
        ctx: &crate::Client,
        _: Self::Request,
    ) -> anyhow::Result<Self::Response> {
        Ok(ctx.get_balance().await.msats)
    }
}
