//! jsonrpsee/tower rpc layer that collects rpc stats
//!
//! Based on implementation of logger from:
//!
//! <https://github.com/paritytech/jsonrpsee/blob/bf5952fb663bdb8193b9f8a43182454c143b0e7d/server/src/middleware/rpc/layer/logger.rs#L1>

use std::borrow::Cow;
use std::collections::HashSet;
use std::pin::Pin;
use std::sync::Arc;
use std::task;
use std::task::Poll;

use fedimint_metrics::prometheus::HistogramTimer;
use futures::Future;
use jsonrpsee::MethodResponse;
use jsonrpsee::server::middleware::rpc::RpcServiceT;
use jsonrpsee::types::Request;
use pin_project::pin_project;

use super::{JSONRPC_API_REQUEST_DURATION_SECONDS, JSONRPC_API_REQUEST_RESPONSE_CODE};

#[pin_project]
pub struct ResponseFuture<F> {
    method: &'static str,
    #[pin]
    fut: F,
    timer: Option<HistogramTimer>,
}

impl<F> std::fmt::Debug for ResponseFuture<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ResponseFuture")
    }
}

impl<F: Future<Output = MethodResponse>> Future for ResponseFuture<F> {
    type Output = F::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Self::Output> {
        let projected = self.project();
        let res = projected.fut.poll(cx);
        if let Poll::Ready(res) = &res
            && let Some(timer) = projected.timer.take()
        {
            timer.observe_duration();

            JSONRPC_API_REQUEST_RESPONSE_CODE
                .with_label_values(&[
                    *projected.method,
                    &if let Some(code) = res.as_error_code() {
                        Cow::Owned(code.to_string())
                    } else {
                        Cow::Borrowed("0")
                    },
                    if res.is_subscription() {
                        "subscription"
                    } else if res.is_batch() {
                        "batch"
                    } else {
                        "default"
                    },
                ])
                .inc();
        }
        res
    }
}

const UNKNOWN_METHOD: &str = "unknown";

#[derive(Clone, Debug)]
pub struct MetricsLayer {
    methods: Arc<HashSet<&'static str>>,
}

impl MetricsLayer {
    pub fn new(methods: impl IntoIterator<Item = &'static str>) -> Self {
        Self {
            methods: Arc::new(methods.into_iter().collect()),
        }
    }
}

impl<S> tower::Layer<S> for MetricsLayer {
    type Service = MetricsService<S>;

    fn layer(&self, service: S) -> Self::Service {
        MetricsService {
            service,
            methods: self.methods.clone(),
        }
    }
}

pub struct MetricsService<S> {
    pub(crate) service: S,
    methods: Arc<HashSet<&'static str>>,
}

impl<'a, S> RpcServiceT<'a> for MetricsService<S>
where
    S: RpcServiceT<'a> + Send + Sync,
{
    type Future = ResponseFuture<S::Future>;

    fn call(&self, req: Request<'a>) -> Self::Future {
        let method = self
            .methods
            .get(req.method_name())
            .copied()
            .unwrap_or(UNKNOWN_METHOD);
        let timer = JSONRPC_API_REQUEST_DURATION_SECONDS
            .with_label_values(&[method])
            .start_timer();

        ResponseFuture {
            method,
            fut: self.service.call(req),
            timer: Some(timer),
        }
    }
}

#[cfg(test)]
mod tests;
