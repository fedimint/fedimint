use clap::{CommandFactory, Parser};

use super::{FM_ENABLE_IROH_ENV, ServerOpts};

fn server_opts_args() -> Vec<&'static str> {
    vec![
        "fedimintd",
        "--data-dir",
        "/tmp/fedimintd-test",
        "--bitcoind-url",
        "http://127.0.0.1:18443",
        "--bitcoind-username",
        "user",
        "--bitcoind-password",
        "pass",
    ]
}

fn parse_server_opts() -> ServerOpts {
    ServerOpts::try_parse_from(server_opts_args()).expect("server opts should parse")
}

#[test]
fn both_bitcoin_backends_parse_together() {
    let mut args = server_opts_args();
    args.extend(["--esplora-url", "http://127.0.0.1:50002"]);
    let opts = ServerOpts::try_parse_from(args).expect("both Bitcoin backends should parse");
    assert!(opts.bitcoind_url.is_some());
    assert!(opts.esplora_url.is_some());
}

fn parse_server_opts_with_enable_iroh_env(value: &str) -> ServerOpts {
    let previous = std::env::var_os(FM_ENABLE_IROH_ENV);
    // This test does not spawn threads while mutating the process
    // environment.
    unsafe {
        std::env::set_var(FM_ENABLE_IROH_ENV, value);
    }

    let opts = parse_server_opts();

    // This test does not spawn threads while mutating the process
    // environment.
    unsafe {
        if let Some(previous) = previous {
            std::env::set_var(FM_ENABLE_IROH_ENV, previous);
        } else {
            std::env::remove_var(FM_ENABLE_IROH_ENV);
        }
    }

    opts
}

#[test]
fn enable_iroh_env_accepts_numeric_booleans() {
    assert_eq!(
        parse_server_opts_with_enable_iroh_env("1").enable_iroh,
        Some(true)
    );
    assert_eq!(
        parse_server_opts_with_enable_iroh_env("0").enable_iroh,
        Some(false)
    );
}

#[test]
fn iroh_next_api_defaults_to_enabled_and_accepts_false() {
    let command = ServerOpts::command();
    let enable_iroh_next = command
        .get_arguments()
        .find(|arg| arg.get_id() == "enable_iroh_next")
        .expect("enable-iroh-next argument exists");
    assert_eq!(enable_iroh_next.get_default_values(), ["true"]);

    let mut args = server_opts_args();
    args.push("--enable-iroh-next=false");
    let opts = ServerOpts::try_parse_from(args).expect("explicit false should parse");
    assert!(!opts.enable_iroh_next);
}

#[test]
fn p2p_relay_does_not_require_enable_iroh_or_change_api_relays() {
    let opts = ServerOpts::try_parse_from([
        "fedimintd",
        "--data-dir",
        "/tmp/fedimintd-test",
        "--bitcoind-url",
        "http://127.0.0.1:18443",
        "--bitcoind-username",
        "user",
        "--bitcoind-password",
        "pass",
        "--iroh-p2p-relays",
        "https://relay.example.com/",
    ])
    .expect("P2P relay should parse independently");

    assert!(opts.iroh_relays.is_empty());
    assert_eq!(opts.iroh_p2p_relays.len(), 1);
}
