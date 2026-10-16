use futures::future;
use tokio::test;

use super::UpdateMerge;

#[test]
async fn test_merge_successful() {
    let update_merge = UpdateMerge::default();

    let result: Result<(), ()> = update_merge
        .merge(async {
            let _ = future::ready(Ok::<(), ()>(())).await;
            Ok::<(), ()>(())
        })
        .await;

    assert!(result.is_ok(), "Merge should be successful");
}

#[test]
async fn test_merge_failed() {
    let update_merge = UpdateMerge::default();

    let result: Result<(), ()> = update_merge
        .merge(async {
            let _ = future::ready(Ok::<(), ()>(())).await;
            Err::<(), ()>(())
        })
        .await;

    assert!(result.is_err(), "Merge should fail");
}

#[tokio::test]
async fn test_concurrent_merge() {
    let update_merge = UpdateMerge::default();

    let fut1 = async {
        let _ = future::ready(Ok::<(), ()>(())).await;
        update_merge
            .merge(async {
                let _ = future::ready(Ok::<(), ()>(())).await;
                Ok::<(), ()>(())
            })
            .await
    };
    let fut2 = async {
        let _ = future::ready(Ok::<(), ()>(())).await;
        update_merge
            .merge(async {
                let _ = future::ready(Ok::<(), ()>(())).await;
                Ok::<(), ()>(())
            })
            .await
    };

    let (result1, result2) = tokio::join!(fut1, fut2);

    assert!(
        result1.is_ok() && result2.is_ok(),
        "Both merges should be successful"
    );
}
