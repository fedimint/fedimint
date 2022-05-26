use crate::{LightningGateway, UserClient};
use futures::future::BoxFuture;
use mint_client::jsonrpc::error::RpcError;
use mint_client::jsonrpc::json::EventLog;
use rand::rngs::OsRng;
use serde_json::Value;
use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex};

///RPC-API Endpoint-Router
pub struct Shared {
    pub client: Arc<UserClient>,
    pub gateway: Arc<LightningGateway>,
    pub rng: OsRng,
    pub router: Arc<Router>,
    pub events: Arc<EventLog>,
    pub spend_lock: Arc<Mutex<()>>,
}

type HandlerArgs = Value;
type Share = Arc<Shared>;
type HandlerResult = Result<Value, RpcError>;

pub struct Handler {
    func: Box<
        dyn Fn(HandlerArgs, Share) -> BoxFuture<'static, HandlerResult> + Send + Sync + 'static,
    >,
}

impl Handler {
    pub fn new<P>(raw_func: fn(params: Value, shared: Share) -> P) -> Handler
    where
        P: Future<Output = HandlerResult> + Send + 'static,
    {
        Handler {
            func: Box::new(move |params, shared| Box::pin(raw_func(params, shared))),
        }
    }

    pub async fn call(&self, args: HandlerArgs, shared: Share) -> HandlerResult {
        (self.func)(args, shared).await
    }
}

pub struct Router {
    handlers: HashMap<String, Handler>,
}

impl Router {
    pub fn new() -> Self {
        Self {
            handlers: HashMap::new(),
        }
    }
    pub fn add_handler<P>(mut self, name: &str, fun: fn(Value, Share) -> P) -> Self
    where
        P: Future<Output = HandlerResult> + Send + 'static,
    {
        self.handlers.insert(name.to_string(), Handler::new(fun));
        self
    }
    pub fn get(&self, name: &str) -> Option<&Handler> {
        self.handlers.get(name)
    }
}

impl Default for Router {
    fn default() -> Self {
        Self::new()
    }
}
