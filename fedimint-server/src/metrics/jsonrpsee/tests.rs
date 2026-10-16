use std::borrow::Cow;

use fedimint_metrics::prometheus::core::Collector;
use fedimint_metrics::prometheus::proto::Metric;
use futures::future::{Ready, ready};
use jsonrpsee::types::{Id, ResponsePayload};

use super::{
    Arc, JSONRPC_API_REQUEST_DURATION_SECONDS, JSONRPC_API_REQUEST_RESPONSE_CODE, MethodResponse,
    MetricsService, Request, RpcServiceT, UNKNOWN_METHOD,
};

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
