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
mod tests {
    use std::borrow::Cow;

    use fedimint_metrics::prometheus::core::Collector;
    use fedimint_metrics::prometheus::proto::Metric;
    use futures::future::{Ready, ready};
    use jsonrpsee::types::{Id, ResponsePayload};

    use super::*;

    const REGISTERED_METHOD: &str = "metrics_test_registered";
    const UNREGISTERED_METHODS: [&str; 3] = [
        "metrics_test_unregistered",
        "metrics_test_unregistered_!@#$%^&*()",
        "metrics_test_unregistered_with_a_very_long_attacker_controlled_suffix",
    ];

    struct SuccessService;

    impl<'a> RpcServiceT<'a> for SuccessService {
        type Future = Ready<MethodResponse>;

        fn call(&self, _request: Request<'a>) -> Self::Future {
            ready(MethodResponse::response(
                Id::Number(1),
                ResponsePayload::success("ok").into(),
                usize::MAX,
            ))
        }
    }

    fn has_method_label(metric: &Metric, method: &str) -> bool {
        metric
            .get_label()
            .iter()
            .any(|label| label.name() == "method" && label.value() == method)
    }

    fn duration_count(method: &str) -> u64 {
        JSONRPC_API_REQUEST_DURATION_SECONDS
            .collect()
            .into_iter()
            .flat_map(|family| family.metric)
            .filter(|metric| has_method_label(metric, method))
            .map(|metric| metric.histogram.sample_count())
            .sum()
    }

    fn response_count(method: &str) -> u64 {
        JSONRPC_API_REQUEST_RESPONSE_CODE
            .collect()
            .into_iter()
            .flat_map(|family| family.metric)
            .filter(|metric| has_method_label(metric, method))
            .map(|metric| metric.counter.value() as u64)
            .sum()
    }

    #[tokio::test]
    async fn bounds_method_labels_for_all_jsonrpc_metrics() {
        let service = MetricsService {
            service: SuccessService,
            methods: Arc::new([REGISTERED_METHOD].into_iter().collect()),
        };
        let duration_before = [
            duration_count(REGISTERED_METHOD),
            duration_count(UNKNOWN_METHOD),
        ];
        let response_before = [
            response_count(REGISTERED_METHOD),
            response_count(UNKNOWN_METHOD),
        ];

        for method in std::iter::once(REGISTERED_METHOD).chain(UNREGISTERED_METHODS) {
            service
                .call(Request::new(Cow::Borrowed(method), None, Id::Number(1)))
                .await;
        }

        assert_eq!(duration_count(REGISTERED_METHOD) - duration_before[0], 1);
        assert_eq!(
            duration_count(UNKNOWN_METHOD) - duration_before[1],
            UNREGISTERED_METHODS.len() as u64
        );
        assert_eq!(response_count(REGISTERED_METHOD) - response_before[0], 1);
        assert_eq!(
            response_count(UNKNOWN_METHOD) - response_before[1],
            UNREGISTERED_METHODS.len() as u64
        );

        for method in UNREGISTERED_METHODS {
            assert_eq!(duration_count(method), 0);
            assert_eq!(response_count(method), 0);
        }
    }
}
