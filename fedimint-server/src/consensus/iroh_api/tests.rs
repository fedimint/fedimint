use std::collections::BTreeSet;
use std::net::SocketAddr;

use anyhow::Context as _;
use fedimint_metrics::prometheus::core::Collector;
use fedimint_metrics::prometheus::proto::Metric;
use futures::future::pending;
use futures::{pin_mut, poll};
use iroh_next::endpoint::presets::Minimal;
use iroh_next::{EndpointAddr, RelayMode, SecretKey, TransportAddr};

use super::{
    ApiError, ApiMethod, Arc, BTreeMap, Duration, IROH_API_REQUEST_DURATION_SECONDS,
    IROH_API_REQUEST_RESPONSE_CODE, ModuleInstanceId, Semaphore, UNKNOWN_METHOD,
    VersionedIrohConnection, acquire_iroh_api_permit, metric_method, record_request_metrics,
    run_handler,
};

const TEST_ALPN: &[u8] = b"fedimint-iroh-api-adapter-test";

fn has_method_label(metric: &Metric, method: &str) -> bool {
    metric
        .get_label()
        .iter()
        .any(|label| label.name() == "method" && label.value() == method)
}

fn duration_count(method: &str) -> u64 {
    IROH_API_REQUEST_DURATION_SECONDS
        .collect()
        .into_iter()
        .flat_map(|family| family.metric)
        .filter(|metric| has_method_label(metric, method))
        .map(|metric| metric.histogram.sample_count())
        .sum()
}

fn response_count(method: &str) -> u64 {
    IROH_API_REQUEST_RESPONSE_CODE
        .collect()
        .into_iter()
        .flat_map(|family| family.metric)
        .filter(|metric| has_method_label(metric, method))
        .map(|metric| metric.counter.value() as u64)
        .sum()
}

fn method_series(metrics: Vec<Metric>, method: &str) -> BTreeSet<Vec<(String, String)>> {
    metrics
        .into_iter()
        .filter(|metric| has_method_label(metric, method))
        .map(|metric| {
            metric
                .label
                .into_iter()
                .map(|label| (label.name().to_owned(), label.value().to_owned()))
                .collect()
        })
        .collect()
}

fn duration_series(method: &str) -> BTreeSet<Vec<(String, String)>> {
    method_series(
        IROH_API_REQUEST_DURATION_SECONDS
            .collect()
            .into_iter()
            .flat_map(|family| family.metric)
            .collect(),
        method,
    )
}

fn response_series(method: &str) -> BTreeSet<Vec<(String, String)>> {
    method_series(
        IROH_API_REQUEST_RESPONSE_CODE
            .collect()
            .into_iter()
            .flat_map(|family| family.metric)
            .collect(),
        method,
    )
}

#[tokio::test]
async fn bounds_method_labels_for_all_iroh_request_metrics() {
    const CORE_METHOD: &str = "metrics_test_core";
    const MODULE_ID: ModuleInstanceId = 42;
    const MODULE_METHOD: &str = "metrics_test_module";
    const MODULE_LABEL: &str = "42-metrics_test_module";

    let core = BTreeMap::from([(CORE_METHOD.to_owned(), true)]);
    let modules = BTreeMap::from([(
        MODULE_ID,
        BTreeMap::from([(MODULE_METHOD.to_owned(), true)]),
    )]);
    let hostile_methods = [
        ApiMethod::Core("metrics_test_unknown_core".to_owned()),
        ApiMethod::Core("metrics_test_unknown_core_!@#$%^&*()".to_owned()),
        ApiMethod::Module(MODULE_ID, "metrics_test_unknown_module_method".to_owned()),
        ApiMethod::Module(
            MODULE_ID,
            "metrics_test_unknown_module_method_with_a_long_suffix".to_owned(),
        ),
        ApiMethod::Module(43, "metrics_test_unknown_module".to_owned()),
        ApiMethod::Module(44, "metrics_test_unknown_module_!@#$%^&*()".to_owned()),
    ];

    assert_eq!(
        metric_method(&core, &modules, &ApiMethod::Core(CORE_METHOD.to_owned())),
        CORE_METHOD
    );
    assert_eq!(
        metric_method(
            &core,
            &modules,
            &ApiMethod::Module(MODULE_ID, MODULE_METHOD.to_owned())
        ),
        MODULE_LABEL
    );
    for method in &hostile_methods {
        assert_eq!(metric_method(&core, &modules, method), UNKNOWN_METHOD);
    }

    let duration_before = [
        duration_count(CORE_METHOD),
        duration_count(MODULE_LABEL),
        duration_count(UNKNOWN_METHOD),
    ];
    let response_before = [
        response_count(CORE_METHOD),
        response_count(MODULE_LABEL),
        response_count(UNKNOWN_METHOD),
    ];

    record_request_metrics(
        &core,
        &modules,
        &ApiMethod::Core(CORE_METHOD.to_owned()),
        "default",
        async { Ok::<_, ApiError>(()) },
    )
    .await
    .expect("registered core request succeeds");
    record_request_metrics(
        &core,
        &modules,
        &ApiMethod::Module(MODULE_ID, MODULE_METHOD.to_owned()),
        "next",
        async { Ok::<_, ApiError>(()) },
    )
    .await
    .expect("registered module request succeeds");
    for method in &hostile_methods {
        record_request_metrics(&core, &modules, method, "default", async {
            Err::<(), _>(ApiError::not_found("test rejection".to_owned()))
        })
        .await
        .expect_err("unregistered request is rejected");
    }

    {
        let cancelled_method = ApiMethod::Core("metrics_test_cancelled_attacker_input".to_owned());
        let cancelled = record_request_metrics(
            &core,
            &modules,
            &cancelled_method,
            "default",
            pending::<Result<(), ApiError>>(),
        );
        pin_mut!(cancelled);
        assert!(poll!(cancelled.as_mut()).is_pending());
    }

    assert_eq!(duration_count(CORE_METHOD) - duration_before[0], 1);
    assert_eq!(duration_count(MODULE_LABEL) - duration_before[1], 1);
    assert_eq!(
        duration_count(UNKNOWN_METHOD) - duration_before[2],
        hostile_methods.len() as u64 + 1
    );
    assert_eq!(response_count(CORE_METHOD) - response_before[0], 1);
    assert_eq!(response_count(MODULE_LABEL) - response_before[1], 1);
    assert_eq!(
        response_count(UNKNOWN_METHOD) - response_before[2],
        hostile_methods.len() as u64
    );
    assert_eq!(duration_series(UNKNOWN_METHOD).len(), 1);
    let unknown_response_series = response_series(UNKNOWN_METHOD);
    assert_eq!(unknown_response_series.len(), 1);
    assert!(unknown_response_series.iter().any(|labels| {
        labels
            .iter()
            .any(|(name, value)| name == "code" && value == "404")
            && labels
                .iter()
                .any(|(name, value)| name == "type" && value == "default")
    }));
    assert!(response_series(CORE_METHOD).iter().any(|labels| {
        labels
            .iter()
            .any(|(name, value)| name == "code" && value == "0")
            && labels
                .iter()
                .any(|(name, value)| name == "type" && value == "default")
    }));
    assert!(response_series(MODULE_LABEL).iter().any(|labels| {
        labels
            .iter()
            .any(|(name, value)| name == "code" && value == "0")
            && labels
                .iter()
                .any(|(name, value)| name == "type" && value == "next")
    }));

    for method in hostile_methods
        .iter()
        .map(ToString::to_string)
        .chain(["metrics_test_cancelled_attacker_input".to_owned()])
    {
        assert!(duration_series(&method).is_empty());
        assert!(response_series(&method).is_empty());
    }
}

#[tokio::test]
async fn panicking_handler_returns_an_error_instead_of_unwinding() {
    let error = run_handler(None, "test_endpoint", async { panic!("handler panic") })
        .await
        .expect_err("a panicking handler is reported as a server error");

    assert_eq!(error.code, 500);

    let error = run_handler(Some(3), "test_endpoint", async {
        panic!("module handler panic")
    })
    .await
    .expect_err("a panicking module handler is reported as a server error");

    assert_eq!(error.code, 500);
}

#[tokio::test]
async fn shared_connection_limit_applies_across_versions() {
    let limit = Arc::new(Semaphore::new(1));
    let legacy_permit = acquire_iroh_api_permit(&limit, 1, "0.35", "connection").await;

    assert!(
        tokio::time::timeout(
            Duration::from_millis(20),
            acquire_iroh_api_permit(&limit, 1, "1.0", "connection"),
        )
        .await
        .is_err()
    );

    drop(legacy_permit);
    let _permit = tokio::time::timeout(
        Duration::from_secs(1),
        acquire_iroh_api_permit(&limit, 1, "1.0", "connection"),
    )
    .await
    .expect("v1 acquires the shared permit after the legacy connection releases it");
}

#[tokio::test]
async fn iroh_v1_request_uses_shared_stream_adapter() -> anyhow::Result<()> {
    let server = iroh_next::Endpoint::builder(Minimal)
        .relay_mode(RelayMode::Disabled)
        .secret_key(SecretKey::from_bytes(&[11; 32]))
        .alpns(vec![TEST_ALPN.to_vec()])
        .bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))?
        .bind()
        .await?;
    let client = iroh_next::Endpoint::builder(Minimal)
        .relay_mode(RelayMode::Disabled)
        .bind()
        .await?;
    let server_addr = EndpointAddr::from_parts(
        server.id(),
        server.bound_sockets().into_iter().map(TransportAddr::Ip),
    );
    let (client_done_tx, client_done_rx) = tokio::sync::oneshot::channel();

    let server_request = async {
        let incoming = server.accept().await.context("server endpoint closed")?;
        let connection = incoming.accept()?.await?;
        let (send, mut recv) = VersionedIrohConnection::Next(connection)
            .accept_bi()
            .await?;
        assert_eq!(recv.read_request().await?, b"request");
        send.write_response(b"response").await?;
        client_done_rx.await?;
        anyhow::Ok(())
    };
    let client_request = async {
        let connection = client.connect(server_addr, TEST_ALPN).await?;
        let (mut send, mut recv) = connection.open_bi().await?;
        send.write_all(b"request").await?;
        send.finish()?;
        let response = recv.read_to_end(100_000).await?;
        anyhow::ensure!(response == b"response");
        client_done_tx.send(()).expect("server is still running");
        anyhow::Ok(())
    };

    tokio::time::timeout(Duration::from_secs(10), async {
        tokio::try_join!(server_request, client_request)
    })
    .await
    .context("Iroh v1 adapter test timed out")??;
    client.close().await;
    server.close().await;
    Ok(())
}
