use std::process::Command;
use std::time::Duration;

use fedimint_core::envs::{
    FM_IN_DEVIMINT_ENV, is_env_var_set, is_running_in_test_env, next_poll_delay,
};

/// This integration test links fedimint-core as a non-test dependency, just
/// like the unit-test executables of other workspace crates.
#[test]
fn detects_the_calling_crates_test_cfg() {
    const CHILD_ENV: &str = "FM_TEST_ENV_REGRESSION_CHILD";

    if std::env::var_os(CHILD_ENV).is_some() {
        assert!(!is_env_var_set("NEXTEST"));
        assert!(!is_env_var_set(FM_IN_DEVIMINT_ENV));
        let in_test_env = is_running_in_test_env!();
        assert!(in_test_env);
        assert_eq!(next_poll_delay!(true), Duration::from_secs(5));
        assert_eq!(next_poll_delay!(false), Duration::from_secs(5));
        return;
    }

    // Do not mutate the process environment: other tests may read it in
    // parallel. Clear runner assistance in a subprocess instead.
    let status = Command::new(std::env::current_exe().expect("the test executable has a path"))
        .args([
            "--exact",
            "detects_the_calling_crates_test_cfg",
            "--nocapture",
        ])
        .env_remove("NEXTEST")
        .env_remove(FM_IN_DEVIMINT_ENV)
        .env(CHILD_ENV, "1")
        .status()
        .expect("the child test executable starts");
    assert!(status.success());
}

#[test]
fn poll_delay_evaluates_its_argument_once_even_in_tests() {
    let mut calls = 0;
    let delay = next_poll_delay!({
        calls += 1;
        true
    });

    assert_eq!(calls, 1);
    assert_eq!(delay, Duration::from_secs(5));
}
