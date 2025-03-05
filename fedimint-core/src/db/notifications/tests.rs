use fedimint_core::db::test_utils::future_returns_shortly;

use super::{Notifications, NotifyQueue};

#[tokio::test]
async fn test_notification_after_notify() {
    let notifs = Notifications::new();
    let key = 1;
    let sub = notifs.register(key);
    notifs.notify(key);
    assert!(future_returns_shortly(sub).await.is_some(), "should notify");
}

#[tokio::test]
async fn test_no_notification_without_notify() {
    let notifs = Notifications::new();
    let key = 1;
    let sub = notifs.register(key);
    assert!(
        future_returns_shortly(sub).await.is_none(),
        "should not notify"
    );
}

#[tokio::test]
async fn test_multi_one() {
    let notifs = Notifications::new();
    let key1 = 1;
    let sub1 = notifs.register(key1);
    let sub2 = notifs.register(key1);
    let sub3 = notifs.register(key1);
    let sub4 = notifs.register(key1);
    notifs.notify(key1);
    assert!(
        future_returns_shortly(sub1).await.is_some(),
        "should notify"
    );
    assert!(
        future_returns_shortly(sub2).await.is_some(),
        "should notify"
    );
    assert!(
        future_returns_shortly(sub3).await.is_some(),
        "should notify"
    );
    assert!(
        future_returns_shortly(sub4).await.is_some(),
        "should notify"
    );
}

#[tokio::test]
async fn test_multi() {
    let notifs = Notifications::new();
    let key1 = 1;
    let key2 = 2;
    let sub1 = notifs.register(key1);
    let sub2 = notifs.register(key2);
    notifs.notify(key1);
    notifs.notify(key2);
    assert!(
        future_returns_shortly(sub1).await.is_some(),
        "should notify"
    );
    assert!(
        future_returns_shortly(sub2).await.is_some(),
        "should notify"
    );
}

#[tokio::test]
async fn test_notify_queue() {
    let notifs = Notifications::new();
    let key1 = 1;
    let key2 = 2;
    let sub1 = notifs.register(key1);
    let sub2 = notifs.register(key2);
    let mut queue = NotifyQueue::new();
    queue.add(&key1);
    queue.add(&key2);
    notifs.submit_queue(&queue);
    assert!(
        future_returns_shortly(sub1).await.is_some(),
        "should notify"
    );
    assert!(
        future_returns_shortly(sub2).await.is_some(),
        "should notify"
    );
}
