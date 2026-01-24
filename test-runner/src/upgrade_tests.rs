use std::env;
use std::str::FromStr;

use anyhow::Result;
use devimint::cmd;
use devimint::util::nix_binary_version_env_var_name;
use itertools::Itertools;
use serde::{Deserialize, Serialize};

use crate::test_wrapper::wrap_test;
use crate::util::set_env;
use crate::versions::{
    LNV2_STABLE_VERSION, Version, build_previous_version_binary_with_nix,
    build_previous_versions_with_nix,
};
use crate::{
    RunTestData, RunUpgradeArgs, prebuild_cargo_workspace, run_tests_with_parallel,
    setup_basic_environment, update_resource_limit,
};

#[derive(Serialize, Deserialize, Clone)]
pub enum UpgradeTest {
    Fedimintd {
        upgrade_path: Vec<Version>,
        enable_lnv2: bool,
    },
    FedimintCli {
        upgrade_path: Vec<Version>,
        enable_lnv2: bool,
    },
    Gatewayd {
        upgrade_path: Vec<Version>,
        enable_lnv2: bool,
    },
    Mnemonic,
}

fn resolve_binary_path(binary: &str, version: &Version) -> String {
    match version {
        Version::Current => binary.to_string(),
        Version::Tagged(v) => {
            let env_var = nix_binary_version_env_var_name(binary, v);
            env::var(&env_var).unwrap_or_else(|_| panic!("{env_var} must be set for version {v}"))
        }
    }
}

fn resolve_binary_paths(binary: &str, upgrade_path: &[Version]) -> String {
    upgrade_path
        .iter()
        .map(|v| resolve_binary_path(binary, v))
        .join(" ")
}

async fn fedimintd(upgrade_path: &[Version], enable_lnv2: bool) -> Result<()> {
    cmd!(
        "devimint",
        "upgrade-tests",
        "--lnv2",
        if enable_lnv2 { "1" } else { "0" },
        "fedimintd",
        "--paths",
        resolve_binary_paths("fedimintd", upgrade_path)
    )
    .run()
    .await
}

async fn fedimint_cli(upgrade_path: &[Version], enable_lnv2: bool) -> Result<()> {
    cmd!(
        "devimint",
        "upgrade-tests",
        "--lnv2",
        if enable_lnv2 { "1" } else { "0" },
        "fedimint-cli",
        "--paths",
        resolve_binary_paths("fedimint-cli", upgrade_path)
    )
    .run()
    .await
}

async fn gatewayd(upgrade_path: &[Version], enable_lnv2: bool) -> Result<()> {
    cmd!(
        "devimint",
        "upgrade-tests",
        "--lnv2",
        if enable_lnv2 { "1" } else { "0" },
        "gatewayd",
        "--gatewayd-paths",
        resolve_binary_paths("gatewayd", upgrade_path),
        "--gateway-cli-paths",
        resolve_binary_paths("gateway-cli", upgrade_path),
    )
    .run()
    .await
}

async fn mnemonic() -> Result<()> {
    // 0.4.0 is really ancient, so we built it directly in this test
    build_previous_version_binary_with_nix("gatewayd", &"0.4.0".parse()?).await?;
    build_previous_version_binary_with_nix("gatewayd-cli", &"0.4.0".parse()?).await?;
    cmd!(
        "gateway-tests",
        "gatewayd-mnemonic",
        "--old-gatewayd-path",
        resolve_binary_path("gatewayd", &"0.4.0".parse()?),
        "--new-gatewayd-path",
        resolve_binary_path("gatewayd", &Version::Current),
        "--old-gateway-cli-path",
        resolve_binary_path("gateway-cli", &"0.4.0".parse()?),
        "--new-gateway-cli-path",
        resolve_binary_path("gateway-cli", &Version::Current),
    )
    .run()
    .await
}

impl UpgradeTest {
    pub async fn run(&self) -> Result<()> {
        match self {
            UpgradeTest::Fedimintd {
                upgrade_path,
                enable_lnv2,
            } => fedimintd(upgrade_path, *enable_lnv2).await?,
            UpgradeTest::FedimintCli {
                upgrade_path,
                enable_lnv2,
            } => fedimint_cli(upgrade_path, *enable_lnv2).await?,
            UpgradeTest::Gatewayd {
                upgrade_path,
                enable_lnv2,
            } => gatewayd(upgrade_path, *enable_lnv2).await?,
            UpgradeTest::Mnemonic => mnemonic().await?,
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct UpgradePath(Vec<Version>);

impl FromStr for UpgradePath {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        Ok(Self(
            s.split(":").map(|x| x.parse()).collect::<Result<_, _>>()?,
        ))
    }
}

pub fn generate_upgrade_test_commands(upgrade_paths: &[UpgradePath]) -> Vec<UpgradeTest> {
    let mut commands = Vec::new();
    for upgrade_path in upgrade_paths {
        let lnv2_flags = if upgrade_path.0[0] < Version::Tagged(LNV2_STABLE_VERSION) {
            vec![false]
        } else {
            vec![false, true]
        };

        for enable_lnv2 in lnv2_flags {
            commands.push(UpgradeTest::Fedimintd {
                enable_lnv2,
                upgrade_path: upgrade_path.0.clone(),
            });
            commands.push(UpgradeTest::FedimintCli {
                enable_lnv2,
                upgrade_path: upgrade_path.0.clone(),
            });
            commands.push(UpgradeTest::Gatewayd {
                enable_lnv2,
                upgrade_path: upgrade_path.0.clone(),
            });
        }
    }
    commands.push(UpgradeTest::Mnemonic);
    commands
}

/// Run all tests with parallel
pub async fn run_all_tests(args: RunUpgradeArgs) -> Result<()> {
    fedimint_logging::TracingSetup::default().init()?;
    setup_basic_environment()?;
    update_resource_limit()?;
    prebuild_cargo_workspace().await?;
    build_previous_versions_with_nix(
        &args
            .upgrade_paths
            .iter()
            .flat_map(|x| &x.0)
            .filter_map(|version| {
                if let Version::Tagged(t) = version {
                    Some(t.clone())
                } else {
                    None
                }
            })
            .collect_vec(),
    )
    .await?;

    run_tests_with_parallel(
        &args.parallel_args,
        generate_upgrade_test_commands(&args.upgrade_paths)
            .into_iter()
            .map(RunTestData::Upgrade)
            .collect_vec(),
    )
    .await
}

/// Run one test as a child
pub async fn run_one_test(test: UpgradeTest) -> anyhow::Result<()> {
    // Older version might not support iroh
    set_env("FM_ENABLE_IROH", "false");
    wrap_test(&serde_json::to_string(&test)?, "", async || {
        test.run().await
    })
    .await
}
