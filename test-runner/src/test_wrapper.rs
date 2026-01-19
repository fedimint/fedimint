use std::fs;
use std::path::Path;
use std::time::Instant;

use anyhow::Result;
use fedimint_core::envs::is_env_var_set_opt;
use rand::{Rng as _, thread_rng};

use crate::util::set_env;

/// Wraps the tests and print some debugging logs
pub async fn run_test(
    test_name: &str,
    version_str: &str,
    mut test: impl AsyncFnMut() -> Result<()>,
) -> Result<()> {
    let test_dir = tempfile::tempdir()?;
    set_env("FM_TEST_DIR", test_dir.path());

    let enable_iroh = is_env_var_set_opt("FM_ENABLE_IROH").unwrap_or_else(|| {
        let enable_iroh = thread_rng().gen_bool(0.5);
        set_env("FM_ENABLE_IROH", if enable_iroh { "true" } else { "false" });
        enable_iroh
    });

    let version_str = format!("{version_str}, iroh: {enable_iroh}");

    eprintln!();
    eprintln!("## RUN {test_name} ({version_str}):");

    let start = Instant::now();

    let mut result = test().await;

    if result.is_err() && should_retry_for_gatewayd_bug(test_dir.path()) {
        eprintln!("## RERUN {test_name} ({version_str}) - known old gatewayd bug.");
        result = test().await;
    }

    let elapsed = start.elapsed();

    match &result {
        Ok(()) => {
            eprintln!("## STAT: {:8.2}s", elapsed.as_secs_f64());
            eprintln!("## DONE {test_name} ({version_str}).");
        }
        Err(e) => {
            eprintln!();
            eprintln!("## FAILED {test_name} ({version_str}): {e:#}");
            print_failure_logs(test_dir.path());
            eprintln!("## FAIL END {test_name} ({version_str}).");
            let _ = test_dir.keep();
        }
    }

    result
}

fn should_retry_for_gatewayd_bug(test_dir: &Path) -> bool {
    if let Ok(content) = fs::read_to_string(test_dir.join("logs/gatewayd-lnd.log")) {
        return content.contains("please upgrade to gatewayd");
    }
    false
}

fn print_failure_logs(test_dir: &Path) {
    let log_files: &[(&str, &str, &str)] = &[
        ("logs/fedimintd-default-0.log", "fm0", "LOG FEDIMINTD-0"),
        ("logs/gatewayd-lnd.log", "lng", "LOG LND GATEWAY"),
        ("logs/lnd.log", "lnn", "LOG LND NODE"),
        ("logs/gatewayd-ldk-0.log", "ldg", "LOG LDK-0 GATEWAY"),
        (
            "gatewayd-ldk-0/ldk_node/ldk_node.log",
            "ldn",
            "LOG LDK-0 NODE",
        ),
    ];

    for (path, prefix, header) in log_files {
        let path = test_dir.join(path);
        if path.exists() {
            eprintln!();
            eprintln!("## {header}:");
            if let Ok(content) = fs::read_to_string(&path) {
                for line in content.lines() {
                    eprintln!("{prefix} {line}");
                }
            }
        }
    }
}
