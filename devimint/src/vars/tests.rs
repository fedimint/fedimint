use std::env;
use std::time::{SystemTime, UNIX_EPOCH};

use super::Global;

#[tokio::test]
async fn global_vars_export_distinct_ldk_ports() {
    let test_dir = env::temp_dir().join(format!(
        "devimint-vars-test-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time must be after the Unix epoch")
            .as_nanos()
    ));
    let globals = Global::new(&test_dir, 1, 1, 0, None, None)
        .await
        .expect("global variables initialize");

    let ldk_port_exports = globals
        .vars()
        .filter(|(name, _)| name == "FM_PORT_LDK" || name == "FM_PORT_LDK2")
        .collect::<Vec<_>>();

    assert_eq!(
        ldk_port_exports,
        vec![
            ("FM_PORT_LDK".to_owned(), globals.FM_PORT_LDK.to_string()),
            ("FM_PORT_LDK2".to_owned(), globals.FM_PORT_LDK2.to_string()),
        ]
    );

    std::fs::remove_dir_all(test_dir).expect("remove test directory");
}
