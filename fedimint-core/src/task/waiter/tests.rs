use std::time::Duration;

use super::Waiter;

#[tokio::test]
async fn test_simple() {
    let waiter = Waiter::new();
    assert!(!waiter.is_done());
    waiter.done();
    assert!(waiter.is_done());
}

#[tokio::test]
async fn test_async() {
    let waiter = Waiter::new();
    assert!(!waiter.is_done());
    tokio::join!(
        async {
            waiter.done();
        },
        async {
            waiter.wait().await;
        }
    );
    assert!(waiter.is_done());
    waiter.wait().await;
    assert!(waiter.is_done());
}
#[tokio::test]
async fn test_async_multi() {
    let waiter = Waiter::new();
    assert!(!waiter.is_done());
    tokio::join!(
        async {
            waiter.done();
        },
        async {
            waiter.done();
        },
        async {
            waiter.done();
        },
    );
    assert!(waiter.is_done());
    waiter.wait().await;
    assert!(waiter.is_done());
}
#[tokio::test]
async fn test_async_sleep() {
    let waiter = Waiter::new();
    assert!(!waiter.is_done());
    tokio::join!(
        async {
            fedimint_core::runtime::sleep(Duration::from_millis(10)).await;
            waiter.done();
        },
        waiter.wait(),
    );
    assert!(waiter.is_done());
    waiter.wait().await;
    assert!(waiter.is_done());
}
