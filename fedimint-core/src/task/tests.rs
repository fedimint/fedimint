use super::{Duration, JoinAllError, TaskGroup, sleep};

#[test_log::test(tokio::test)]
async fn shutdown_task_group_after() -> anyhow::Result<()> {
    let tg = TaskGroup::new();
    tg.spawn("shutdown waiter", |handle| async move {
        handle.make_shutdown_rx().await;
    });
    sleep(Duration::from_millis(10)).await;
    tg.shutdown_join_all(None).await?;
    Ok(())
}

#[test_log::test(tokio::test)]
async fn shutdown_task_group_before() -> anyhow::Result<()> {
    let tg = TaskGroup::new();
    tg.spawn("shutdown waiter", |handle| async move {
        sleep(Duration::from_millis(10)).await;
        handle.make_shutdown_rx().await;
    });
    tg.shutdown_join_all(None).await?;
    Ok(())
}

#[test_log::test(tokio::test)]
async fn shutdown_task_subgroup_after() -> anyhow::Result<()> {
    let tg = TaskGroup::new();
    tg.make_subgroup()
        .spawn("shutdown waiter", |handle| async move {
            handle.make_shutdown_rx().await;
        });
    sleep(Duration::from_millis(10)).await;
    tg.shutdown_join_all(None).await?;
    Ok(())
}

#[test_log::test(tokio::test)]
async fn shutdown_task_subgroup_before() -> anyhow::Result<()> {
    let tg = TaskGroup::new();
    tg.make_subgroup()
        .spawn("shutdown waiter", |handle| async move {
            sleep(Duration::from_millis(10)).await;
            handle.make_shutdown_rx().await;
        });
    tg.shutdown_join_all(None).await?;
    Ok(())
}

#[test_log::test(tokio::test)]
async fn join_all_reports_tasks_that_did_not_finish_cleanly() {
    let tg = TaskGroup::new();
    tg.spawn("panics", |_handle| async { panic!("boom") });
    // Join immediately: a task that has already finished (or panicked) removes its
    // own join handle from the group, so it must still be pending when
    // `join_all` collects. `#[tokio::test]` runs single-threaded and `join_all`
    // drains the handle map before its first await, so the panicking task is
    // still registered.
    let err: JoinAllError = tg
        .join_all(None)
        .await
        .expect_err("a panicked task is not a clean finish");
    assert_eq!(err.errors.len(), 1);
    assert!(
        err.to_string()
            .starts_with("1 tasks did not finish cleanly")
    );
}
