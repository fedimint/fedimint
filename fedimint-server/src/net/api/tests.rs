use std::time::Duration;

use async_trait::async_trait;
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::db::mem_impl::MemDatabase;
use fedimint_core::db::{Database, IRawDatabaseExt as _};
use fedimint_core::module::{
    ApiEndpoint, ApiEndpointContext, ApiError, ApiRequestErased, ApiVersion,
};
use fedimint_core::runtime::sleep;
use jsonrpsee::RpcModule;
use serde_json::Value;

use super::{API_ENDPOINT_TIMEOUT, HasApiContext, attach_endpoints};

struct TestApi {
    db: Database,
    context_delay: Duration,
}

#[async_trait]
impl HasApiContext<()> for TestApi {
    async fn context(
        &self,
        _request: &ApiRequestErased,
        _id: Option<ModuleInstanceId>,
    ) -> (&(), ApiEndpointContext) {
        sleep(self.context_delay).await;
        (&(), ApiEndpointContext::new(self.db.clone(), false))
    }
}

fn test_rpc(context_delay: Duration, handler_delay: Duration) -> RpcModule<TestApi> {
    let mut rpc = RpcModule::new(TestApi {
        db: MemDatabase::new().into_database(),
        context_delay,
    });
    attach_endpoints(
        &mut rpc,
        vec![ApiEndpoint {
            path: "test_endpoint",
            version: ApiVersion::new(0, 0),
            handler: Box::new(move |(), _, request| {
                Box::pin(async move {
                    sleep(handler_delay).await;
                    assert_ne!(request.params, Value::String("panic".to_owned()));
                    if request.params == Value::Null {
                        Ok(Value::Bool(true))
                    } else {
                        Err(ApiError::unauthorized())
                    }
                })
            }),
        }],
        None,
    );
    rpc
}

#[tokio::test(start_paused = true)]
async fn websocket_deadline_includes_context_and_preserves_timeout_error() {
    // Neither phase alone exhausts the budget, but their combined time does.
    let rpc = test_rpc(API_ENDPOINT_TIMEOUT / 2, API_ENDPOINT_TIMEOUT * 3 / 4);
    let error = rpc
        .call::<_, Value>("test_endpoint", [ApiRequestErased::default()])
        .await
        .expect_err("context and handler share a single request deadline");

    let jsonrpsee::core::server::MethodsError::JsonRpc(error) = error else {
        panic!("the deadline must return a JSON-RPC error");
    };
    assert_eq!(error.code(), -32000);
    assert_eq!(error.message(), "Request timeout");
    assert!(error.data().is_none());
}

#[tokio::test(start_paused = true)]
async fn websocket_success_and_endpoint_errors_are_unchanged() {
    let rpc = test_rpc(Duration::ZERO, Duration::ZERO);
    let response = rpc
        .call::<_, Value>("test_endpoint", [ApiRequestErased::default()])
        .await
        .expect("the handler succeeds");
    assert_eq!(response, Value::Bool(true));

    for (params, code, message) in [
        (Value::Bool(false), 401, "Invalid authorization"),
        (
            Value::String("panic".to_owned()),
            500,
            "API handler panicked",
        ),
    ] {
        let error = rpc
            .call::<_, Value>("test_endpoint", [ApiRequestErased::new(params)])
            .await
            .expect_err("the handler rejects or panics");
        let jsonrpsee::core::server::MethodsError::JsonRpc(error) = error else {
            panic!("the endpoint error must remain a JSON-RPC error");
        };
        assert_eq!(error.code(), code);
        assert_eq!(error.message(), message);
    }
}
