use std::env;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::Parser as _;

use super::{
    GATEWAY_PORT_OFFSET_LDK, GATEWAY_PORT_OFFSET_LDK2_METRICS, GATEWAY_PORT_OFFSET_LND, Global,
    gateway_port,
};
use crate::cli::CommonArgs;
use crate::envs::FM_GATEWAY_BASE_PORT_ENV;

const GATEWAY_BASE_PORT_ENV_CHILD: &str = "DEVIMINT_GATEWAY_BASE_PORT_ENV_CHILD";

fn unique_test_dir(name: &str) -> std::path::PathBuf {
    env::temp_dir().join(format!(
        "devimint-vars-{name}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time must be after the Unix epoch")
            .as_nanos()
    ))
}

#[test]
fn explicit_gateway_ports_cover_the_full_valid_range() {
    assert_eq!(
        gateway_port(65_527, GATEWAY_PORT_OFFSET_LDK2_METRICS)
            .expect("maximum gateway base port is valid"),
        u16::MAX
    );
    assert_eq!(
        gateway_port(10_000, GATEWAY_PORT_OFFSET_LND).expect("ordinary LND port is valid"),
        10_003
    );
    assert_eq!(
        gateway_port(10_000, GATEWAY_PORT_OFFSET_LDK).expect("ordinary LDK port is valid"),
        10_005
    );
}

#[test]
fn explicit_gateway_ports_reject_overflowing_ranges() {
    for base in [65_528, 65_530, u16::MAX] {
        let error = gateway_port(base, GATEWAY_PORT_OFFSET_LDK2_METRICS)
            .expect_err("overflowing gateway range must be rejected")
            .to_string();

        assert!(error.contains(&base.to_string()));
        assert!(error.contains("--gateway-base-port"));
        assert!(error.contains(FM_GATEWAY_BASE_PORT_ENV));
        assert!(error.contains("offset 8"));
        assert!(error.contains("maximum base port 65527"));
    }
}

#[tokio::test]
async fn global_new_rejects_overflowing_gateway_base_before_initialization() {
    let test_dir = unique_test_dir("overflow");

    let error = Global::new(&test_dir, 1, 1, 0, None, Some(65_528))
        .await
        .expect_err("overflowing gateway range must be rejected");

    assert!(error.to_string().contains("maximum base port 65527"));
    assert!(
        !test_dir.exists(),
        "gateway range validation must precede initialization side effects"
    );
}

#[tokio::test]
async fn direct_global_init_rejects_overflowing_gateway_base() {
    let test_dir = unique_test_dir("direct-init-overflow");

    let error = Global::init(&test_dir, 1, 1, 0, 10_000, 3, Some(65_535))
        .await
        .expect_err("direct initialization must reject gateway port overflow");

    assert!(error.to_string().contains("maximum base port 65527"));
    std::fs::remove_dir_all(test_dir).expect("remove test directory");
}

#[tokio::test]
async fn cli_gateway_base_port_routes_to_range_validation() {
    let args = CommonArgs::try_parse_from(["devimint", "--gateway-base-port", "65530"])
        .expect("parse gateway base port argument");
    let test_dir = unique_test_dir("cli-overflow");

    let error = Global::new(
        &test_dir,
        args.num_feds,
        args.fed_size,
        args.offline_nodes,
        args.federations_base_port,
        args.gateway_base_port,
    )
    .await
    .expect_err("CLI gateway base port must be range validated");

    assert!(error.to_string().contains("value 65530"));
    assert!(!test_dir.exists());
}

#[test]
fn env_gateway_base_port_routes_to_range_validation() {
    let output = Command::new(env::current_exe().expect("resolve current test executable"))
        .args([
            "--exact",
            "vars::tests::env_gateway_base_port_child",
            "--nocapture",
        ])
        .env(GATEWAY_BASE_PORT_ENV_CHILD, "1")
        .env(FM_GATEWAY_BASE_PORT_ENV, "65535")
        .output()
        .expect("run isolated gateway base port environment test");

    assert!(
        output.status.success(),
        "isolated environment test failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn env_gateway_base_port_child() {
    if env::var_os(GATEWAY_BASE_PORT_ENV_CHILD).is_none() {
        return;
    }

    let args = CommonArgs::try_parse_from(["devimint"])
        .expect("parse gateway base port environment value");
    let gateway_base_port = args
        .gateway_base_port
        .expect("gateway base port environment value is present");
    let error = gateway_port(gateway_base_port, GATEWAY_PORT_OFFSET_LDK2_METRICS)
        .expect_err("environment gateway base port must be range validated");

    assert!(error.to_string().contains("value 65535"));
}
