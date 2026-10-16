use std::sync::Arc;
use std::time::Duration;

use fedimint_core::{apply, async_trait_maybe_send};
use tokio::sync::watch;

use crate::error::ServerError;
use crate::{ConnectionPool, ConnectorRegistry, IConnection};

#[derive(Debug)]
struct TestConnection {
    connected: watch::Sender<bool>,
}

#[apply(async_trait_maybe_send!)]
impl IConnection for TestConnection {
    async fn await_disconnection(&self) {
        self.connected
            .subscribe()
            .wait_for(|connected| !connected)
            .await
            .expect("test sender remains alive");
    }

    fn is_connected(&self) -> bool {
        *self.connected.borrow()
    }
}

#[tokio::test(start_paused = true)]
async fn cancelled_probes_reconnect_after_server_returns() {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use fedimint_core::runtime::{Instant, sleep, timeout};

    let registry = ConnectorRegistry::build_from_server_defaults().bind().await;
    let pool = ConnectionPool::<TestConnection>::new(registry);
    let url = "ws://guardian.example/".parse().unwrap();
    let available = Arc::new(AtomicBool::new(true));
    let attempts = Arc::new(AtomicUsize::new(0));
    let create = {
        let available = available.clone();
        let attempts = attempts.clone();
        move |_, _, _| {
            let available = available.clone();
            let attempts = attempts.clone();
            async move {
                attempts.fetch_add(1, Ordering::Relaxed);
                if !available.load(Ordering::Relaxed) {
                    return Err(ServerError::Connection(
                        std::io::Error::other("server offline").into(),
                    ));
                }
                Ok(Arc::new(TestConnection {
                    connected: watch::channel(true).0,
                }))
            }
        }
    };
    let first = pool
        .get_or_create_connection(&url, None, create.clone())
        .await
        .unwrap();
    available.store(false, Ordering::Relaxed);
    first.connected.send_replace(false);

    let probe_limit = Duration::from_secs(1);
    let interval = Duration::from_secs(5);
    let mut cancellations = 0;
    // Let the real backoff grow beyond the probe's deadline.
    for _ in 0..20 {
        let result = timeout(
            probe_limit,
            pool.get_or_create_connection(&url, None, create.clone()),
        )
        .await;
        assert!(!matches!(result, Ok(Ok(_))));
        cancellations += usize::from(result.is_err());
        sleep(interval).await;
    }
    assert!(cancellations > 1);
    let before = attempts.load(Ordering::Relaxed);
    assert!(
        before > 1,
        "the outage must include failed connection attempts"
    );
    available.store(true, Ordering::Relaxed);

    // Allow recovery across later probes while keeping each probe bounded.
    for _ in 0..8 {
        let started = Instant::now();
        let result = timeout(
            probe_limit,
            pool.get_or_create_connection(&url, None, create.clone()),
        )
        .await;
        assert!(started.elapsed() <= probe_limit);
        if let Ok(Ok(connection)) = result {
            assert!(attempts.load(Ordering::Relaxed) > before);
            assert!(!Arc::ptr_eq(&first, &connection));
            connection.connected.send_replace(false);
            return;
        }
        sleep(interval).await;
    }
    panic!("bounded probes never reconnected after the server returned");
}
