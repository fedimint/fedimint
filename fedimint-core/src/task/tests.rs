use super::{Duration, TaskGroup, sleep};

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
