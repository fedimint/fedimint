use std::time::Duration;

use super::{Jit, JitTry};

#[test_log::test(tokio::test)]
async fn sanity_jit() {
    let v = Jit::new(|| async {
        fedimint_core::runtime::sleep(Duration::from_millis(0)).await;
        3
    });

    assert_eq!(*v.get().await, 3);
    assert_eq!(*v.get().await, 3);
    assert_eq!(*v.clone().get().await, 3);
}

#[test_log::test(tokio::test)]
async fn sanity_jit_try_ok() {
    let v = JitTry::<_, std::io::Error>::new_try(|| async {
        fedimint_core::runtime::sleep(Duration::from_millis(0)).await;
        Ok(3)
    });

    assert_eq!(*v.get_try().await.expect("ok"), 3);
    assert_eq!(*v.get_try().await.expect("ok"), 3);
    assert_eq!(*v.clone().get_try().await.expect("ok"), 3);
}

#[test_log::test(tokio::test)]
async fn sanity_jit_try_err() {
    let v = JitTry::new_try(|| async {
        fedimint_core::runtime::sleep(Duration::from_millis(0)).await;
        Err::<u32, _>(std::io::Error::other("BOOM"))
    });

    assert!(v.get_try().await.is_err());
    assert!(v.get_try().await.is_err());
    assert!(v.clone().get_try().await.is_err());
}
