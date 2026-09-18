use std::collections::BTreeMap;
use std::ffi::OsString;

use super::{
    BITCOIN_RPC_KIND_ENVS, BitcoinRpcConfig, EnvParseError, FM_BITCOIN_RPC_KIND_ENV,
    FM_BITCOIN_RPC_URL_ENV, FM_DEFAULT_BITCOIN_RPC_KIND_ENV, FM_DEFAULT_BITCOIN_RPC_URL_ENV,
    FM_FORCE_BITCOIN_RPC_KIND_ENV, first_env_var_set,
};

/// A lookup over a fixed set of variables, standing in for the process
/// environment.
fn lookup(vars: Vec<(&'static str, OsString)>) -> impl Fn(&str) -> Option<OsString> {
    let vars: BTreeMap<&'static str, OsString> = vars.into_iter().collect();

    move |var: &str| vars.get(var).cloned()
}

#[test]
fn first_env_var_set_prefers_the_highest_priority_variable() {
    let all = lookup(vec![
        (FM_FORCE_BITCOIN_RPC_KIND_ENV, "forced".into()),
        (FM_DEFAULT_BITCOIN_RPC_KIND_ENV, "default".into()),
        (FM_BITCOIN_RPC_KIND_ENV, "obsolete".into()),
    ]);

    assert_eq!(
        first_env_var_set(BITCOIN_RPC_KIND_ENVS, FM_DEFAULT_BITCOIN_RPC_KIND_ENV, &all)
            .expect("the forced variable is set"),
        (FM_FORCE_BITCOIN_RPC_KIND_ENV, "forced".to_owned())
    );

    let without_force = lookup(vec![
        (FM_DEFAULT_BITCOIN_RPC_KIND_ENV, "default".into()),
        (FM_BITCOIN_RPC_KIND_ENV, "obsolete".into()),
    ]);

    assert_eq!(
        first_env_var_set(
            BITCOIN_RPC_KIND_ENVS,
            FM_DEFAULT_BITCOIN_RPC_KIND_ENV,
            &without_force
        )
        .expect("the default variable is set"),
        (FM_DEFAULT_BITCOIN_RPC_KIND_ENV, "default".to_owned())
    );

    // The obsolete variable is still honoured, and reported under its own name
    // so that a later `InvalidUrl` names the variable the user actually set.
    let only_obsolete = lookup(vec![(FM_BITCOIN_RPC_KIND_ENV, "obsolete".into())]);

    assert_eq!(
        first_env_var_set(
            BITCOIN_RPC_KIND_ENVS,
            FM_DEFAULT_BITCOIN_RPC_KIND_ENV,
            &only_obsolete
        )
        .expect("the obsolete variable is set"),
        (FM_BITCOIN_RPC_KIND_ENV, "obsolete".to_owned())
    );
}

#[test]
fn first_env_var_set_reports_the_canonical_variable_when_unset() {
    let empty = lookup(vec![]);

    assert!(matches!(
        first_env_var_set(
            BITCOIN_RPC_KIND_ENVS,
            FM_DEFAULT_BITCOIN_RPC_KIND_ENV,
            &empty
        ),
        Err(EnvParseError::NotSet {
            var: FM_DEFAULT_BITCOIN_RPC_KIND_ENV
        })
    ));
}

/// A set but non-Unicode variable fails instead of falling through to a
/// lower-priority alias.
#[cfg(unix)]
#[test]
fn first_env_var_set_rejects_a_non_unicode_value() {
    use std::os::unix::ffi::OsStringExt as _;

    let vars = lookup(vec![
        (
            FM_FORCE_BITCOIN_RPC_KIND_ENV,
            OsString::from_vec(vec![0xff]),
        ),
        (FM_DEFAULT_BITCOIN_RPC_KIND_ENV, "default".into()),
    ]);

    assert!(matches!(
        first_env_var_set(
            BITCOIN_RPC_KIND_ENVS,
            FM_DEFAULT_BITCOIN_RPC_KIND_ENV,
            &vars
        ),
        Err(EnvParseError::NotUnicode {
            var: FM_FORCE_BITCOIN_RPC_KIND_ENV
        })
    ));
}

#[test]
fn defaults_from_lookup_names_the_variable_holding_an_invalid_url() {
    let vars = lookup(vec![
        (FM_DEFAULT_BITCOIN_RPC_KIND_ENV, "bitcoind".into()),
        (FM_BITCOIN_RPC_URL_ENV, "not a url".into()),
    ]);

    assert!(matches!(
        BitcoinRpcConfig::defaults_from_lookup(&vars),
        Err(EnvParseError::InvalidUrl {
            var: FM_BITCOIN_RPC_URL_ENV,
            ..
        })
    ));
}

#[test]
fn defaults_from_lookup_builds_the_config() {
    let vars = lookup(vec![
        (FM_DEFAULT_BITCOIN_RPC_KIND_ENV, "bitcoind".into()),
        (
            FM_DEFAULT_BITCOIN_RPC_URL_ENV,
            "http://localhost:38332".into(),
        ),
    ]);

    assert_eq!(
        BitcoinRpcConfig::defaults_from_lookup(&vars).expect("both variables are set"),
        BitcoinRpcConfig {
            kind: "bitcoind".to_owned(),
            url: "http://localhost:38332"
                .parse()
                .expect("the URL is well-formed"),
        }
    );
}
