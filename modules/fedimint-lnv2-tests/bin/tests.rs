use std::collections::BTreeMap;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use anyhow::{Context as _, bail, ensure};
use bitcoin::hashes::{Hash, sha256};
use clap::{Parser, Subcommand};
use devimint::devfed::{DevFed, DevJitFed};
use devimint::envs::FM_CLIENT_DIR_ENV;
use devimint::external::Bitcoind;
use devimint::federation::{Client, Federation};
use devimint::util::{ProcessManager, almost_equal, poll_simple};
use devimint::version_constants::{
    VERSION_0_10_0_ALPHA, VERSION_0_11_0_ALPHA, VERSION_0_12_0_ALPHA, VERSION_0_12_2_ALPHA,
    VERSION_0_14_0_ALPHA,
};
use devimint::{Gatewayd, cmd, util};
use fedimint_core::core::{Account, OperationId};
use fedimint_core::encoding::Encodable;
use fedimint_core::secp256k1::rand::rngs::OsRng;
use fedimint_core::secp256k1::{SECP256K1, SecretKey};
use fedimint_core::task::{self};
use fedimint_core::util::{backoff_util, retry, write_overwrite_async};
use fedimint_lnurl::{LnurlResponse, VerifyResponse, parse_lnurl};
use fedimint_lnv2_client::FinalSendOperationState;
use lightning_invoice::{Bolt11Invoice, Bolt11InvoiceDescriptionRef};
use serde::Deserialize;
use serde_json::Value;
use tokio::try_join;
use tracing::info;

#[path = "common.rs"]
mod common;

async fn module_is_present(client: &Client, kind: &str) -> anyhow::Result<bool> {
    let modules = cmd!(client, "module").out_json().await?;

    let modules = modules["list"].as_array().expect("module list is an array");

    Ok(modules.iter().any(|m| m["kind"].as_str() == Some(kind)))
}

async fn assert_module_sanity(client: &Client) -> anyhow::Result<()> {
    if !devimint::util::is_backwards_compatibility_test() {
        ensure!(
            !module_is_present(client, "ln").await?,
            "ln module should not be present"
        );
    }

    Ok(())
}

#[derive(Parser)]
#[command(name = "lnv2-module-tests")]
#[command(about = "LNv2 module integration tests", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Run gateway registration tests
    GatewayRegistration,
    /// Run payment tests
    Payments,
    /// Run LNURL pay tests
    LnurlPay,
    /// Test LNURL receives after recovery from seed
    LnurlRecovery,
    /// Two clients racing to pay the same invoice settle exactly once
    DuplicatePayment,
    /// The gateway refuses to fund a receive while the federation cannot
    /// reach consensus
    FederationOutage,
    /// Run direct HTLC tests between two clients without a gateway
    DirectHtlc,
    /// Funds bound to a non-primary account stay there through Lightning,
    /// on-chain and recovery from seed; needs mintv2 and walletv2
    Accounts,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // The duplicate-payment test needs a second federation; every other test
    // uses a single one.
    let num_feds = if matches!(cli.command, None | Some(Commands::DuplicatePayment)) {
        2
    } else {
        1
    };

    devimint::run_devfed_test()
        .num_feds(num_feds)
        .call(|dev_fed, process_mgr| async move {
            if !devimint::util::supports_lnv2() {
                info!("lnv2 is disabled, skipping");
                return Ok(());
            }

            match &cli.command {
                Some(Commands::GatewayRegistration) => {
                    test_gateway_registration(&dev_fed).await?;
                }
                Some(Commands::Payments) => {
                    test_payments(&dev_fed).await?;
                }
                Some(Commands::LnurlPay) => {
                    pegin_gateways(&dev_fed).await?;
                    test_lnurl_pay(&dev_fed).await?;
                }
                Some(Commands::LnurlRecovery) => {
                    pegin_gateways(&dev_fed).await?;
                    test_lnurl_recovery(&dev_fed).await?;
                }
                Some(Commands::DuplicatePayment) => {
                    pegin_gateways(&dev_fed).await?;
                    test_duplicate_payment(&dev_fed, &process_mgr).await?;
                }
                Some(Commands::DirectHtlc) => {
                    test_direct_htlc(&dev_fed).await?;
                }
                Some(Commands::Accounts) => {
                    test_accounts(&dev_fed).await?;
                }
                Some(Commands::FederationOutage) => {
                    pegin_gateways(&dev_fed).await?;
                    let dev_fed = dev_fed.to_dev_fed(&process_mgr).await?;
                    test_federation_outage(dev_fed, &process_mgr).await?;
                }
                None => {
                    // Run all tests if no subcommand is specified
                    test_gateway_registration(&dev_fed).await?;
                    // Before the payments test funds the gateways, as it
                    // relies on an unfunded gateway to refund a payment.
                    test_accounts(&dev_fed).await?;
                    test_payments(&dev_fed).await?;
                    test_duplicate_payment(&dev_fed, &process_mgr).await?;
                    test_lnurl_pay(&dev_fed).await?;
                    test_lnurl_recovery(&dev_fed).await?;
                    test_direct_htlc(&dev_fed).await?;
                    // Last, since it takes ownership of the federation to
                    // stop and restart guardians.
                    pegin_gateways(&dev_fed).await?;
                    let dev_fed = dev_fed.to_dev_fed(&process_mgr).await?;
                    test_federation_outage(dev_fed, &process_mgr).await?;
                }
            }

            info!("Testing LNV2 is complete!");

            Ok(())
        })
        .await
}

async fn pegin_gateways(dev_fed: &DevJitFed) -> anyhow::Result<()> {
    info!("Pegging-in gateways...");

    let federation = dev_fed.fed().await?;

    let gw_lnd = dev_fed.gw_lnd().await?;
    let gw_ldk = dev_fed.gw_ldk().await?;

    federation
        .pegin_gateways(1_000_000, vec![gw_lnd, gw_ldk])
        .await?;

    Ok(())
}

async fn test_gateway_registration(dev_fed: &DevJitFed) -> anyhow::Result<()> {
    let client = dev_fed
        .fed()
        .await?
        .new_joined_client("lnv2-test-gateway-registration-client")
        .await?;

    assert_module_sanity(&client).await?;

    let gw_lnd = dev_fed.gw_lnd().await?;
    let gw_ldk = dev_fed.gw_ldk_connected().await?;

    let gateways = [gw_lnd.addr.clone(), gw_ldk.addr.clone()];

    info!("Removing the gateways devimint added on startup...");

    let peers = (0..dev_fed.fed().await?.members.len()).collect::<Vec<usize>>();
    remove_all_gateways(&client, &peers).await?;

    info!("Testing registration of gateways...");

    for gateway in &gateways {
        for peer in 0..dev_fed.fed().await?.members.len() {
            assert!(add_gateway(&client, peer, gateway).await?);
        }
    }

    assert_eq!(
        cmd!(client, "module", "lnv2", "gateways", "list")
            .out_json()
            .await?
            .as_array()
            .expect("JSON Value is not an array")
            .len(),
        2
    );

    assert_eq!(
        cmd!(client, "module", "lnv2", "gateways", "list", "--peer", "0")
            .out_json()
            .await?
            .as_array()
            .expect("JSON Value is not an array")
            .len(),
        2
    );

    info!("Testing selection of gateways...");

    assert!(
        gateways.contains(
            &cmd!(client, "module", "lnv2", "gateways", "select")
                .out_json()
                .await?
                .as_str()
                .expect("JSON Value is not a string")
                .to_string()
        )
    );

    cmd!(client, "module", "lnv2", "gateways", "map")
        .out_json()
        .await?;

    for _ in 0..10 {
        for gateway in &gateways {
            let invoice = common::receive(&client, gateway, 1_000_000).await?.0;

            assert_eq!(
                cmd!(
                    client,
                    "module",
                    "lnv2",
                    "gateways",
                    "select",
                    "--invoice",
                    invoice.to_string()
                )
                .out_json()
                .await?
                .as_str()
                .expect("JSON Value is not a string"),
                gateway
            )
        }
    }

    info!("Testing deregistration of gateways...");

    for gateway in &gateways {
        for peer in 0..dev_fed.fed().await?.members.len() {
            assert!(remove_gateway(&client, peer, gateway).await?);
        }
    }

    assert!(
        cmd!(client, "module", "lnv2", "gateways", "list")
            .out_json()
            .await?
            .as_array()
            .expect("JSON Value is not an array")
            .is_empty(),
    );

    assert!(
        cmd!(client, "module", "lnv2", "gateways", "list", "--peer", "0")
            .out_json()
            .await?
            .as_array()
            .expect("JSON Value is not an array")
            .is_empty()
    );

    Ok(())
}

async fn test_payments(dev_fed: &DevJitFed) -> anyhow::Result<()> {
    let federation = dev_fed.fed().await?;

    let client = federation
        .new_joined_client("lnv2-test-payments-client")
        .await?;

    assert_module_sanity(&client).await?;

    federation.pegin_client(10_000, &client).await?;

    almost_equal(client.balance().await?, 10_000 * 1000, 500_000).unwrap();

    let gw_lnd = dev_fed.gw_lnd().await?;
    let gw_ldk = dev_fed.gw_ldk().await?;
    let lnd = dev_fed.lnd().await?;

    // Gateways before 0.12 forward *every* pending HOLD invoice on their
    // Lightning node to the gateway's payment handler and cancel the ones
    // they cannot match to a registered LNv2 incoming contract. That includes
    // the HOLD invoice this test creates directly on the LND node the LND
    // gateway shares, so the gateway's cancel races this test's settle and
    // fails it with `invoice already canceled` whenever the gateway wins.
    // Only exercise HOLD invoices against gateways that filter out HOLD
    // invoices they did not create themselves.
    let test_hold_invoice = gw_lnd.gatewayd_version >= *VERSION_0_12_0_ALPHA;

    let hold_invoice = if test_hold_invoice {
        Some(lnd.create_hold_invoice(60000).await?)
    } else {
        info!(
            gatewayd_version = %gw_lnd.gatewayd_version,
            "Skipping HOLD invoice payment: gateway cancels HOLD invoices it did not create"
        );

        None
    };

    let gateway_pairs = [(gw_lnd, gw_ldk), (gw_ldk, gw_lnd)];

    let gateway_matrix = [
        (gw_lnd, gw_lnd),
        (gw_lnd, gw_ldk),
        (gw_ldk, gw_lnd),
        (gw_ldk, gw_ldk),
    ];

    info!("Testing refund of circular payments...");

    for (gw_send, gw_receive) in gateway_matrix {
        info!(
            "Testing refund of payment: client -> {} -> {} -> client",
            gw_send.ln.ln_type(),
            gw_receive.ln.ln_type()
        );

        let invoice = common::receive(&client, &gw_receive.addr, 1_000_000)
            .await?
            .0;

        let state = common::send(&client, &gw_send.addr, &invoice.to_string()).await?;
        assert!(matches!(state, FinalSendOperationState::Refunded));
    }

    pegin_gateways(dev_fed).await?;

    info!("Testing circular payments...");

    for (gw_send, gw_receive) in gateway_matrix {
        info!(
            "Testing payment: client -> {} -> {} -> client",
            gw_send.ln.ln_type(),
            gw_receive.ln.ln_type()
        );

        let (invoice, receive_op) = common::receive(&client, &gw_receive.addr, 1_000_000).await?;

        let state = common::send(&client, &gw_send.addr, &invoice.to_string()).await?;
        assert!(matches!(state, FinalSendOperationState::Success(_)));

        common::await_receive_claimed(&client, receive_op).await?;
    }

    info!("Testing payments from client to gateways...");

    for (gw_send, gw_receive) in gateway_pairs {
        info!(
            "Testing payment: client -> {} -> {}",
            gw_send.ln.ln_type(),
            gw_receive.ln.ln_type()
        );

        let invoice = gw_receive.client().create_invoice(1_000_000).await?;

        let state = common::send(&client, &gw_send.addr, &invoice.to_string()).await?;
        assert!(matches!(state, FinalSendOperationState::Success(_)));
    }

    info!("Testing payments from gateways to client...");

    for (gw_send, gw_receive) in gateway_pairs {
        info!(
            "Testing payment: {} -> {} -> client",
            gw_send.ln.ln_type(),
            gw_receive.ln.ln_type()
        );

        let (invoice, receive_op) = common::receive(&client, &gw_receive.addr, 1_000_000).await?;

        gw_send.client().pay_invoice(invoice).await?;

        common::await_receive_claimed(&client, receive_op).await?;
    }

    retry(
        "Waiting for the full balance to become available to the client".to_string(),
        backoff_util::background_backoff(),
        || async {
            ensure!(client.balance().await? >= 9000 * 1000);

            Ok(())
        },
    )
    .await?;

    if let Some((hold_preimage, hold_invoice, hold_payment_hash)) = hold_invoice {
        info!("Testing Client can pay LND HOLD invoice via LDK Gateway...");

        let (state, _) = try_join!(
            common::send(&client, &gw_ldk.addr, &hold_invoice),
            lnd.settle_hold_invoice(hold_preimage, hold_payment_hash),
        )?;
        assert!(matches!(state, FinalSendOperationState::Success(_)));
    }

    info!("Testing LNv2 lightning fees...");

    let fed_id = federation.calculate_federation_id();

    gw_lnd
        .client()
        .set_federation_routing_fee(fed_id.clone(), 0, 0)
        .await?;

    gw_lnd
        .client()
        .set_federation_transaction_fee(fed_id.clone(), 0, 0)
        .await?;

    // Gateway pays: 1_000 msat LNv2 federation base fee. Gateway receives:
    // 1_000_000 payment.
    test_fees(fed_id, &client, gw_lnd, gw_ldk, 1_000_000 - 1_000).await?;

    let online_peers: Vec<usize> = federation.members.keys().copied().collect();

    test_iroh_payment(&client, gw_lnd, gw_ldk, &online_peers).await?;

    info!("Testing payment summary...");

    let lnd_payment_summary = gw_lnd.client().payment_summary().await?;

    assert_eq!(lnd_payment_summary.outgoing.total_success, 5);
    assert_eq!(lnd_payment_summary.outgoing.total_failure, 2);
    assert_eq!(lnd_payment_summary.incoming.total_success, 4);
    assert_eq!(lnd_payment_summary.incoming.total_failure, 0);

    assert!(lnd_payment_summary.outgoing.median_latency.is_some());
    assert!(lnd_payment_summary.outgoing.average_latency.is_some());
    assert!(lnd_payment_summary.incoming.median_latency.is_some());
    assert!(lnd_payment_summary.incoming.average_latency.is_some());

    let ldk_payment_summary = gw_ldk.client().payment_summary().await?;

    assert_eq!(
        ldk_payment_summary.outgoing.total_success,
        if test_hold_invoice { 4 } else { 3 }
    );
    assert_eq!(ldk_payment_summary.outgoing.total_failure, 2);
    assert_eq!(ldk_payment_summary.incoming.total_success, 4);
    assert_eq!(ldk_payment_summary.incoming.total_failure, 0);

    assert!(ldk_payment_summary.outgoing.median_latency.is_some());
    assert!(ldk_payment_summary.outgoing.average_latency.is_some());
    assert!(ldk_payment_summary.incoming.median_latency.is_some());
    assert!(ldk_payment_summary.incoming.average_latency.is_some());

    Ok(())
}

/// Creates a fresh client and joins it to the federation identified by
/// `invite_code`, unlike `Federation::new_joined_client` which always joins
/// whichever federation last wrote the shared invite-code file.
async fn join_client(name: &str, invite_code: &str) -> anyhow::Result<Client> {
    let client = Client::create(name).await?;
    client.join_federation(invite_code.to_string()).await?;
    Ok(client)
}

/// Three independent clients — two in the primary federation and one in a
/// second federation, all served by the same gateway — race to pay the *same*
/// invoice. The gateway pays the invoice only once, so it may claim only one of
/// the three outgoing contracts regardless of which federation funded them.
/// Exactly one payment settles; how the other two end depends on the gateway
/// version, see [`assert_duplicates_refunded`] and
/// [`assert_duplicates_refused`].
async fn test_duplicate_payment(
    dev_fed: &DevJitFed,
    process_mgr: &ProcessManager,
) -> anyhow::Result<()> {
    info!(
        "Testing three clients across two federations paying the same invoice settle exactly once..."
    );

    // The LDK gateway is used to send: its `pay` is idempotent per payment hash,
    // so all contracts share a single Lightning payment and preimage.
    let gw_send = dev_fed.gw_ldk().await?;
    let gw_receive = dev_fed.gw_lnd().await?;

    // The cross-federation dedup lives in the gateway's global database, added in
    // 0.12. Older gateways would claim both contracts, so skip against them.
    if gw_send.gatewayd_version < *VERSION_0_12_0_ALPHA {
        info!(
            gatewayd_version = %gw_send.gatewayd_version,
            "Skipping: gateway predates cross-federation outgoing payment dedup"
        );
        return Ok(());
    }

    let first_federation = dev_fed.fed().await?;

    // `Federation::invite_code` reads a single shared invite-code file, so
    // capture the primary federation's invite before spawning the second one
    // overwrites it. Clients must be joined with the right invite explicitly;
    // `new_joined_client` would join whichever federation wrote that file last.
    let first_invite = first_federation.invite_code()?;

    // A second federation, also served by the sending gateway, covers the
    // cross-federation case: a contract funded in one federation must still
    // block claiming a contract for the same invoice funded in another.
    let second_federation = Federation::new(
        process_mgr,
        dev_fed.bitcoind().await?.clone(),
        false,
        false,
        false,
        1,
        "lnv2-duplicate-payment".to_string(),
    )
    .await?;
    let second_invite = second_federation.invite_code()?;

    assert_ne!(
        first_federation.calculate_federation_id(),
        second_federation.calculate_federation_id(),
        "the second federation must be distinct from the first"
    );

    // Spawning the second federation overwrote the shared invite-code file
    // with its own invite. Restore the primary federation's invite now that
    // both invites are captured: `Federation::invite_code` re-reads that file,
    // so a later `new_joined_client` on the primary federation would otherwise
    // join the second one, which is torn down when this test returns.
    let client_dir: PathBuf = std::env::var(FM_CLIENT_DIR_ENV)?.parse()?;
    write_overwrite_async(client_dir.join("invite-code"), &first_invite).await?;

    gw_send.client().connect_fed(second_invite.clone()).await?;
    second_federation
        .pegin_gateways(1_000_000, vec![gw_send])
        .await?;

    let client_a = join_client("lnv2-duplicate-payment-a", &first_invite).await?;
    let client_b = join_client("lnv2-duplicate-payment-b", &first_invite).await?;
    let client_c = join_client("lnv2-duplicate-payment-c", &second_invite).await?;

    first_federation.pegin_client(10_000, &client_a).await?;
    first_federation.pegin_client(10_000, &client_b).await?;
    second_federation.pegin_client(10_000, &client_c).await?;

    // Control: the second-federation client can pay a *different* invoice through
    // the gateway on its own. This proves the gateway serves the second
    // federation, so any refund of the shared invoice below is caused by the
    // duplicate payment rather than a second-federation setup problem.
    let second_federation_id = second_federation.calculate_federation_id();
    let second_balance_before_control = gw_send
        .client()
        .ecash_balance(second_federation_id.clone())
        .await?;
    let control_invoice = gw_receive
        .client()
        .create_invoice(1_000_000)
        .await?
        .to_string();
    let control = common::send(&client_c, &gw_send.addr, &control_invoice).await?;
    assert!(
        matches!(control, FinalSendOperationState::Success(_)),
        "second-federation control payment must succeed, got {control:?}"
    );

    // The sender sees the preimage once the gateway's claim is accepted, which
    // can be before the claimed ecash reaches the gateway. Wait for it, so the
    // gateway's balances only move below because of the shared invoice.
    poll_simple(
        "Waiting for the gateway to claim the control payment",
        || async {
            let balance = gw_send
                .client()
                .ecash_balance(second_federation_id.clone())
                .await?;
            ensure!(
                balance > second_balance_before_control,
                "gateway has not claimed the control payment yet"
            );
            Ok(())
        },
    )
    .await?;

    let invoice = gw_receive
        .client()
        .create_invoice(1_000_000)
        .await?
        .to_string();

    // Before 0.12.2 the gateway claimed the payment image only after paying,
    // and forfeited every later contract for it, so those were refunded at once.
    // Since then it claims the image when it accepts a send and refuses the
    // others outright, so their senders are only refunded at contract expiry.
    if gw_send.gatewayd_version < *VERSION_0_12_2_ALPHA {
        return assert_duplicates_refunded(&client_a, &client_b, &client_c, gw_send, &invoice)
            .await;
    }

    assert_duplicates_refused(
        [&client_a, &client_b, &client_c],
        gw_send,
        [
            first_federation.calculate_federation_id(),
            second_federation_id,
        ],
        &invoice,
    )
    .await
}

/// How long a send refused by the gateway is watched to stay unresolved.
const REFUSED_SEND_WATCH: Duration = Duration::from_secs(30);

/// The duplicate-payment assertions for gateways that claim the payment image
/// only after paying and forfeit the duplicates: one settles, two are refunded.
async fn assert_duplicates_refunded(
    client_a: &Client,
    client_b: &Client,
    client_c: &Client,
    gw_send: &Gatewayd,
    invoice: &str,
) -> anyhow::Result<()> {
    // The two clients in the first federation race for the invoice; the
    // per-federation dedup settles exactly one of them and refunds the other.
    let (state_a, state_b) = try_join!(
        common::send(client_a, &gw_send.addr, invoice),
        common::send(client_b, &gw_send.addr, invoice),
    )?;

    // The second-federation client then pays the same, now-settled invoice. The
    // gateway already holds the preimage, so without cross-federation dedup it
    // claims this contract too, being reimbursed twice for one Lightning payment.
    let state_c = common::send(client_c, &gw_send.addr, invoice).await?;

    let states = [state_a, state_b, state_c];

    info!("shared-invoice send states: {states:?}");

    let successes = states
        .iter()
        .filter(|state| matches!(state, FinalSendOperationState::Success(_)))
        .count();

    let refunds = states
        .iter()
        .filter(|state| matches!(state, FinalSendOperationState::Refunded))
        .count();

    assert_eq!(
        (successes, refunds),
        (1, 2),
        "exactly one payment must settle and the other two be refunded, got {states:?}"
    );

    Ok(())
}

/// The duplicate-payment assertions for gateways that claim the payment image
/// at intake: one send settles, the gateway refuses the other two without
/// paying or forfeiting anything, so they stay unresolved until their contracts
/// expire, and the gateway is reimbursed exactly once.
async fn assert_duplicates_refused(
    [client_a, client_b, client_c]: [&Client; 3],
    gw_send: &Gatewayd,
    [first_federation_id, second_federation_id]: [String; 2],
    invoice: &str,
) -> anyhow::Result<()> {
    let first_balance_before = gw_send
        .client()
        .ecash_balance(first_federation_id.clone())
        .await?;
    let second_balance_before = gw_send
        .client()
        .ecash_balance(second_federation_id.clone())
        .await?;

    // The two clients in the first federation race for the invoice. Whichever
    // the gateway accepts first settles; the other is refused and stays funded.
    let (op_a, op_b) = try_join!(
        common::start_send(client_a, &gw_send.addr, invoice),
        common::start_send(client_b, &gw_send.addr, invoice),
    )?;

    let (state_a, state_b) = tokio::join!(
        await_send_within(client_a, op_a, REFUSED_SEND_WATCH),
        await_send_within(client_b, op_b, REFUSED_SEND_WATCH),
    );

    // The second-federation client then pays the same, now-settled invoice. The
    // claim is global to the gateway, so it is refused as well.
    let op_c = common::start_send(client_c, &gw_send.addr, invoice).await?;
    let state_c = await_send_within(client_c, op_c, REFUSED_SEND_WATCH).await;

    let states = [state_a?, state_b?, state_c?];

    info!("shared-invoice send states (None = unresolved): {states:?}");

    let successes = states
        .iter()
        .filter(|state| matches!(state, Some(FinalSendOperationState::Success(_))))
        .count();

    let unresolved = states.iter().filter(|state| state.is_none()).count();

    assert_eq!(
        (successes, unresolved),
        (1, 2),
        "exactly one payment must settle and the other two stay unresolved, got {states:?}"
    );

    // A contract costs at least the invoice amount, so reimbursement for a
    // second one would at least double the gain.
    let invoice_msats = Bolt11Invoice::from_str(invoice)?
        .amount_milli_satoshis()
        .expect("the invoice has an amount");

    let first_gain = gw_send
        .client()
        .ecash_balance(first_federation_id)
        .await?
        .checked_sub(first_balance_before)
        .expect("the gateway's balance in the first federation must not shrink");

    assert!(
        (invoice_msats..2 * invoice_msats).contains(&first_gain),
        "the gateway must be reimbursed for exactly one contract, gained {first_gain} msat"
    );

    assert_eq!(
        gw_send.client().ecash_balance(second_federation_id).await?,
        second_balance_before,
        "the gateway must not claim the second federation's contract"
    );

    Ok(())
}

/// Waits up to `watch` for a send to reach its final state, returning `None`
/// if it is still unresolved by then.
async fn await_send_within(
    client: &Client,
    operation_id: OperationId,
    watch: Duration,
) -> anyhow::Result<Option<FinalSendOperationState>> {
    match tokio::time::timeout(watch, common::await_send(client, operation_id)).await {
        Ok(state) => state.map(Some),
        Err(_) => Ok(None),
    }
}

/// Stops enough guardians that no threshold of them can answer, checks that
/// a receive is refused without the gateway funding anything, then checks
/// that receives work again once the guardians are back.
async fn test_federation_outage(
    dev_fed: DevFed,
    process_mgr: &ProcessManager,
) -> anyhow::Result<()> {
    info!("Testing that the gateway refuses to fund a receive during a federation outage...");

    let DevFed {
        mut fed,
        gw_lnd,
        gw_ldk,
        ..
    } = dev_fed;

    if gw_lnd.gatewayd_version < *VERSION_0_12_2_ALPHA {
        info!(
            gatewayd_version = %gw_lnd.gatewayd_version,
            "Skipping: gateway predates the federation liveness probe"
        );
        return Ok(());
    }

    let client = fed
        .new_joined_client("lnv2-federation-outage-client")
        .await?;
    fed.await_all_peers().await?;

    let federation_id = fed.calculate_federation_id();
    let gateway = gw_lnd.client().address();

    // Register the invoice while the federation is healthy so that only the
    // funding decision is exercised below.
    let (invoice, _) = common::receive(&client, &gateway, 100_000).await?;
    let balance_before = gw_lnd.client().ecash_balance(federation_id.clone()).await?;

    // Stop the smallest number of guardians that leaves fewer than a
    // threshold of them running.
    let fed_size = process_mgr.globals.FM_FED_SIZE;
    let max_evil = (fed_size - 1) / 3;
    let stopped: Vec<usize> = (fed_size - max_evil - 1..fed_size).collect();
    for peer in &stopped {
        fed.terminate_server(*peer).await?;
    }

    info!(
        ?stopped,
        "Paying invoice while the federation cannot reach consensus"
    );
    // The payment runs concurrently: a gateway that funds anyway holds the
    // HTLC until the guardians are back, so awaiting it here would block the
    // restart below.
    let payment = fedimint_core::runtime::spawn("lnv2-outage-payment", {
        let gw_ldk = gw_ldk.client();
        async move { gw_ldk.pay_invoice(invoice).await }
    });

    // Bring the guardians back only once the gateway has acted on the HTLC:
    // a refusal fails the payment, while funding consumes ecash at submission
    // even though the transaction cannot land yet.
    poll_simple("Waiting for the gateway to act on the HTLC", || async {
        if payment.is_finished() {
            return Ok(());
        }
        let balance = gw_lnd.client().ecash_balance(federation_id.clone()).await?;
        if balance < balance_before {
            return Ok(());
        }
        bail!("gateway has not acted on the HTLC yet")
    })
    .await?;

    for peer in &stopped {
        fed.start_server(process_mgr, *peer).await?;
    }
    fed.await_all_peers().await?;

    // Funding queued during the outage would land now that the guardians are
    // back, and the payment would complete against it. The probe exists so
    // that it does not.
    let outcome = payment.await?;
    info!(?outcome, "Payment outcome once the guardians are back");
    ensure!(
        outcome.is_err(),
        "payment must fail: the gateway funded an incoming contract during the outage"
    );
    ensure!(
        gw_lnd.client().ecash_balance(federation_id.clone()).await? == balance_before,
        "gateway must not fund an incoming contract while the federation cannot reach consensus"
    );

    // The gateway's own connections to the restarted guardians come back on
    // their own schedule, and the probe refuses receives until they do, so
    // retry with a fresh invoice each time; a refused invoice is cancelled.
    info!("Paying a fresh invoice after the guardians are back");
    poll_simple("Waiting for receives to succeed again", || async {
        let (invoice, _) = common::receive(&client, &gateway, 100_000).await?;
        gw_ldk.client().pay_invoice(invoice).await
    })
    .await?;
    ensure!(
        gw_lnd.client().ecash_balance(federation_id).await? < balance_before,
        "gateway must fund the incoming contract once the federation is back"
    );

    info!("Federation outage test complete");
    Ok(())
}

async fn test_fees(
    fed_id: String,
    client: &Client,
    gw_lnd: &Gatewayd,
    gw_ldk: &Gatewayd,
    expected_addition: u64,
) -> anyhow::Result<()> {
    let gw_lnd_ecash_prev = gw_lnd.client().ecash_balance(fed_id.clone()).await?;

    let (invoice, receive_op) = common::receive(client, &gw_ldk.addr, 1_000_000).await?;

    let state = common::send(client, &gw_lnd.addr, &invoice.to_string()).await?;
    assert!(matches!(state, FinalSendOperationState::Success(_)));

    common::await_receive_claimed(client, receive_op).await?;

    // The sending gateway claims its outgoing contract in the background after
    // returning the preimage to the sender, so its ecash balance is credited
    // asynchronously. Wait for the claim to settle before asserting the fee.
    while almost_equal(
        gw_lnd_ecash_prev + expected_addition,
        gw_lnd.client().ecash_balance(fed_id.clone()).await?,
        5000,
    )
    .is_err()
    {
        info!("Waiting for the sending gateway's outgoing claim to settle...");
        cmd!(client, "dev", "wait", "1").out_json().await?;
    }

    Ok(())
}

async fn add_gateway(client: &Client, peer: usize, gateway: &String) -> anyhow::Result<bool> {
    cmd!(
        client,
        "--our-id",
        peer.to_string(),
        "--password",
        "pass",
        "module",
        "lnv2",
        "gateways",
        "add",
        gateway
    )
    .out_json()
    .await?
    .as_bool()
    .ok_or(anyhow::anyhow!("JSON Value is not a boolean"))
}

async fn remove_gateway(client: &Client, peer: usize, gateway: &String) -> anyhow::Result<bool> {
    cmd!(
        client,
        "--our-id",
        peer.to_string(),
        "--password",
        "pass",
        "module",
        "lnv2",
        "gateways",
        "remove",
        gateway
    )
    .out_json()
    .await?
    .as_bool()
    .ok_or(anyhow::anyhow!("JSON Value is not a boolean"))
}

/// Remove all currently registered gateways, including the ones devimint
/// adds on startup, from the given peers.
async fn remove_all_gateways(client: &Client, peers: &[usize]) -> anyhow::Result<()> {
    let gateways = cmd!(client, "module", "lnv2", "gateways", "list")
        .out_json()
        .await?
        .as_array()
        .expect("JSON Value is not an array")
        .iter()
        .map(|gateway| {
            gateway
                .as_str()
                .expect("JSON Value is not a string")
                .to_string()
        })
        .collect::<Vec<String>>();

    for gateway in &gateways {
        for &peer in peers {
            assert!(remove_gateway(client, peer, gateway).await?);
        }
    }

    Ok(())
}

// Keep this below the 310s `fm-run-test` timeout so LNURL flakes fail with
// useful balance diagnostics instead of a generic test timeout.
const LNURL_BALANCE_WAIT_ATTEMPTS: u64 = 120;

async fn wait_for_lnurl_balance(
    client: &Client,
    client_name: &str,
    expected_msats: u64,
) -> anyhow::Result<()> {
    let mut last_balance_msats = client.balance().await?;

    for attempt in 1..=LNURL_BALANCE_WAIT_ATTEMPTS {
        if last_balance_msats < expected_msats {
            info!(
                client_name,
                balance_msats = last_balance_msats,
                expected_msats,
                attempt,
                "Waiting for {client_name} to receive funds via LNURL"
            );
            cmd!(client, "dev", "wait", "1").out_json().await?;
            last_balance_msats = client.balance().await?;
        } else {
            info!(
                client_name,
                balance_msats = last_balance_msats,
                expected_msats,
                attempt,
                "{client_name} successfully received funds via LNURL"
            );
            return Ok(());
        }
    }

    if last_balance_msats < expected_msats {
        anyhow::bail!(
            "timed out waiting for {client_name} to receive funds via LNURL after {} attempts; last balance: {last_balance_msats} msats; expected balance: {expected_msats} msats",
            LNURL_BALANCE_WAIT_ATTEMPTS
        );
    }

    info!(
        client_name,
        balance_msats = last_balance_msats,
        expected_msats,
        attempt = LNURL_BALANCE_WAIT_ATTEMPTS,
        "{client_name} successfully received funds via LNURL"
    );

    Ok(())
}

async fn test_lnurl_pay(dev_fed: &DevJitFed) -> anyhow::Result<()> {
    if util::FedimintCli::version_or_default().await < *VERSION_0_11_0_ALPHA {
        return Ok(());
    }

    if util::FedimintdCmd::version_or_default().await < *VERSION_0_11_0_ALPHA {
        return Ok(());
    }

    if util::Gatewayd::version_or_default().await < *VERSION_0_11_0_ALPHA {
        return Ok(());
    }

    let federation = dev_fed.fed().await?;

    let gw_lnd = dev_fed.gw_lnd().await?;
    let gw_ldk = dev_fed.gw_ldk().await?;

    let gateway_pairs = [(gw_lnd, gw_ldk), (gw_ldk, gw_lnd)];

    let recurringd = dev_fed.recurringdv2().await?.api_url().to_string();

    let client_a = federation
        .new_joined_client("lnv2-lnurl-test-client-a")
        .await?;

    assert_module_sanity(&client_a).await?;

    let client_b = federation
        .new_joined_client("lnv2-lnurl-test-client-b")
        .await?;

    assert_module_sanity(&client_b).await?;

    for (gw_send, gw_receive) in gateway_pairs {
        info!(
            "Testing lnurl payments: {} -> {} -> client",
            gw_send.ln.ln_type(),
            gw_receive.ln.ln_type()
        );

        let lnurl_a = generate_lnurl(&client_a, &recurringd, &gw_receive.addr).await?;
        let lnurl_b = generate_lnurl(&client_b, &recurringd, &gw_receive.addr).await?;

        let (invoice_a, verify_url_a) = fetch_invoice(lnurl_a.clone(), 500_000).await?;
        let (invoice_b, verify_url_b) = fetch_invoice(lnurl_b.clone(), 500_000).await?;

        let verify_task_a = task::spawn("verify_task_a", verify_payment_wait(verify_url_a.clone()));
        let verify_task_b = task::spawn("verify_task_b", verify_payment_wait(verify_url_b.clone()));

        let response_a = verify_payment(&verify_url_a).await?;
        let response_b = verify_payment(&verify_url_b).await?;

        assert!(!response_a.settled);
        assert!(!response_b.settled);

        assert!(response_a.preimage.is_none());
        assert!(response_b.preimage.is_none());

        gw_send.client().pay_invoice(invoice_a.clone()).await?;
        gw_send.client().pay_invoice(invoice_b.clone()).await?;

        let response_a = verify_payment(&verify_url_a).await?;
        let response_b = verify_payment(&verify_url_b).await?;

        assert!(response_a.settled);
        assert!(response_b.settled);

        verify_preimage(&response_a, &invoice_a);
        verify_preimage(&response_b, &invoice_b);

        assert_eq!(verify_task_a.await??, response_a);
        assert_eq!(verify_task_b.await??, response_b);
    }

    wait_for_lnurl_balance(&client_a, "client A", 950 * 1000).await?;
    wait_for_lnurl_balance(&client_b, "client B", 950 * 1000).await?;

    Ok(())
}

/// Tests LNURL receives after recovery from seed.
///
/// LNv2 uses `NoModuleBackup`, so recovery restores funds via the mint module
/// but not the operation log or LNv2 state. Verifies:
/// 1. Balance is fully recovered.
/// 2. Payments to a pre-recovery LNURL are still claimed by the restored
///    client.
async fn test_lnurl_recovery(dev_fed: &DevJitFed) -> anyhow::Result<()> {
    // Before v0.10.0 the CLI registered LNURLs via a POST to the recurringd
    // server.  That endpoint no longer exists, so old CLIs cannot generate
    // LNURLs against the current recurringdv2.
    if util::FedimintCli::version_or_default().await < *VERSION_0_10_0_ALPHA {
        return Ok(());
    }

    let federation = dev_fed.fed().await?;
    let gw_lnd = dev_fed.gw_lnd().await?;
    let gw_ldk = dev_fed.gw_ldk().await?;
    let recurringd = dev_fed.recurringdv2().await?.api_url().to_string();

    const LNURL_AMOUNT_MSAT: u64 = 500_000;
    const LNURL_BALANCE_TOLERANCE_MSAT: u64 = 100_000;

    // ── Phase 1: Pre-recovery LNURL receives ──────────────────────────

    info!("Phase 1: Creating client and receiving via LNURL before recovery");

    let client = federation
        .new_joined_client("lnv2-lnurl-recovery-original")
        .await?;

    let lnurl = generate_lnurl(&client, &recurringd, &gw_ldk.addr).await?;

    for i in 0..3 {
        info!("Paying LNURL invoice {}/3", i + 1);
        let (invoice, _verify_url) = fetch_invoice(lnurl.clone(), LNURL_AMOUNT_MSAT).await?;
        gw_lnd.client().pay_invoice(invoice).await?;
    }

    while almost_equal(
        client.balance().await?,
        3 * LNURL_AMOUNT_MSAT,
        LNURL_BALANCE_TOLERANCE_MSAT,
    )
    .is_err()
    {
        info!("Waiting for pre-recovery LNURL payments to settle...");
        cmd!(client, "dev", "wait", "1").out_json().await?;
    }

    let pre_recovery_balance = client.balance().await?;
    info!("Pre-recovery balance: {pre_recovery_balance} msats");

    let mnemonic = cmd!(client, "print-secret").out_json().await?["secret"]
        .as_str()
        .expect("secret is a string")
        .to_owned();

    // ── Phase 2: Recovery ─────────────────────────────────────────────

    info!("Phase 2: Recovering client from seed");

    let restored = Client::create("lnv2-lnurl-recovery-restored").await?;
    // Keep command boundaries visible even when a child never exits. Log only
    // static labels: restore arguments contain the mnemonic and invite code.
    info!("LNURL recovery: starting restore");
    cmd!(
        restored,
        "restore",
        "--invite-code",
        federation.invite_code()?,
        "--mnemonic",
        &mnemonic
    )
    .run()
    .await?;
    info!("LNURL recovery: finished restore");

    loop {
        info!("LNURL recovery: starting balance info");
        let restored_balance = restored.balance().await?;
        info!("LNURL recovery: finished balance info");
        if pre_recovery_balance <= restored_balance {
            break;
        }
        info!("Waiting for recovery to complete...");
        info!("LNURL recovery: starting dev wait");
        cmd!(restored, "dev", "wait", "1").out_json().await?;
        info!("LNURL recovery: finished dev wait");
    }

    info!("LNURL recovery: starting final balance info");
    let post_recovery_balance = restored.balance().await?;
    info!("LNURL recovery: finished final balance info");
    info!("Post-recovery balance: {post_recovery_balance} msats");

    // ── Phase 3: Post-recovery LNURL receives ─────────────────────────

    info!("Phase 3: Paying to the original LNURL; restored client must claim");

    // Reuse the Phase 1 `lnurl` on purpose: this is what a third party would
    // have saved pre-recovery, and it must still pay the restored client.
    for i in 0..2 {
        info!("Paying pre-recovery LNURL invoice {}/2", i + 1);
        let (invoice, _verify_url) = fetch_invoice(lnurl.clone(), LNURL_AMOUNT_MSAT).await?;
        gw_lnd.client().pay_invoice(invoice).await?;
    }

    while almost_equal(
        restored.balance().await?,
        post_recovery_balance + 2 * LNURL_AMOUNT_MSAT,
        LNURL_BALANCE_TOLERANCE_MSAT,
    )
    .is_err()
    {
        info!("Waiting for post-recovery LNURL payments to settle...");
        cmd!(restored, "dev", "wait", "1").out_json().await?;
    }

    let final_balance = restored.balance().await?;
    info!("Final balance: {final_balance} msats");

    let operations = cmd!(restored, "list-operations", "--limit", "100")
        .out_json()
        .await?;
    let lnv2_ops: Vec<_> = operations["operations"]
        .as_array()
        .expect("operations is an array")
        .iter()
        .filter(|op| op["operation_kind"].as_str() == Some("lnv2"))
        .collect();
    assert!(
        lnv2_ops.len() >= 2,
        "Expected at least 2 LNv2 operations after post-recovery receives, found {}",
        lnv2_ops.len()
    );

    info!(
        "LNURL recovery test passed: {} new operations, balance {final_balance} msats",
        lnv2_ops.len()
    );

    Ok(())
}

async fn generate_lnurl(
    client: &Client,
    recurringd_base_url: &str,
    gw_ldk_addr: &str,
) -> anyhow::Result<String> {
    cmd!(
        client,
        "module",
        "lnv2",
        "lnurl",
        "generate",
        recurringd_base_url,
        "--gateway",
        gw_ldk_addr,
    )
    .out_json()
    .await
    .map(|s| s.as_str().unwrap().to_owned())
}

fn verify_preimage(response: &VerifyResponse, invoice: &Bolt11Invoice) {
    let preimage = response.preimage.expect("Payment should be settled");

    let payment_hash = preimage.consensus_hash::<sha256::Hash>();

    assert_eq!(payment_hash, *invoice.payment_hash());
}

async fn verify_payment(verify_url: &str) -> anyhow::Result<VerifyResponse> {
    reqwest::get(verify_url)
        .await?
        .json::<LnurlResponse<VerifyResponse>>()
        .await?
        .into_result()
        .map_err(anyhow::Error::msg)
}

async fn verify_payment_wait(verify_url: String) -> anyhow::Result<VerifyResponse> {
    reqwest::get(format!("{verify_url}?wait"))
        .await?
        .json::<LnurlResponse<VerifyResponse>>()
        .await?
        .into_result()
        .map_err(anyhow::Error::msg)
}

#[derive(Deserialize, Clone)]
struct LnUrlPayResponse {
    callback: String,
    metadata: String,
}

#[derive(Deserialize, Clone)]
struct LnUrlPayInvoiceResponse {
    pr: Bolt11Invoice,
    // LUD-06 requires this field, so parsing fails if the service omits it
    routes: Vec<serde_json::Value>,
    verify: String,
}

async fn fetch_invoice(lnurl: String, amount_msat: u64) -> anyhow::Result<(Bolt11Invoice, String)> {
    let url = parse_lnurl(&lnurl).ok_or_else(|| anyhow::anyhow!("Invalid LNURL"))?;

    let response = reqwest::get(url).await?.json::<LnUrlPayResponse>().await?;

    let callback_url = format!("{}?amount={}", response.callback, amount_msat);

    let invoice_response = reqwest::get(callback_url)
        .await?
        .json::<LnUrlPayInvoiceResponse>()
        .await?;

    ensure!(
        invoice_response.pr.amount_milli_satoshis() == Some(amount_msat),
        "Invoice amount is not set"
    );

    ensure!(
        invoice_response.routes.is_empty(),
        "LUD-06 requires routes to be an empty array"
    );

    let metadata_hash = sha256::Hash::hash(response.metadata.as_bytes());

    ensure!(
        matches!(
            invoice_response.pr.description(),
            Bolt11InvoiceDescriptionRef::Hash(hash) if hash.0 == metadata_hash
        ),
        "Invoice does not commit to the LNURL metadata via its description hash (LUD-06)"
    );

    Ok((invoice_response.pr, invoice_response.verify))
}

async fn test_iroh_payment(
    client: &Client,
    gw_lnd: &Gatewayd,
    gw_ldk: &Gatewayd,
    online_peers: &[usize],
) -> anyhow::Result<()> {
    info!("Testing iroh payment...");
    // The send below relies on automatic gateway selection picking the iroh
    // gateway, so the gateways devimint added on startup have to go first.
    remove_all_gateways(client, online_peers).await?;
    for &peer in online_peers {
        add_gateway(client, peer, &format!("iroh://{}", gw_lnd.node_id)).await?;
    }

    // If the client is below v0.10.0, also add the HTTP address so that the client
    // can fallback to using that, since the iroh gateway will fail.
    if util::FedimintCli::version_or_default().await < *VERSION_0_10_0_ALPHA
        || gw_lnd.gatewayd_version < *VERSION_0_10_0_ALPHA
    {
        for &peer in online_peers {
            add_gateway(client, peer, &gw_lnd.addr).await?;
        }
    }

    let invoice = gw_ldk.client().create_invoice(5_000_000).await?;

    let send_op = serde_json::from_value::<OperationId>(
        cmd!(client, "module", "lnv2", "send", invoice,)
            .out_json()
            .await?,
    )?;

    let send_state = common::await_send(client, send_op).await?;
    assert!(
        matches!(send_state, FinalSendOperationState::Success(_)),
        "unexpected send state: {send_state:?}"
    );

    let (invoice, receive_op) = serde_json::from_value::<(Bolt11Invoice, OperationId)>(
        cmd!(client, "module", "lnv2", "receive", "5000000",)
            .out_json()
            .await?,
    )?;

    gw_ldk.client().pay_invoice(invoice).await?;
    common::await_receive_claimed(client, receive_op).await?;

    if util::FedimintCli::version_or_default().await < *VERSION_0_10_0_ALPHA
        || gw_lnd.gatewayd_version < *VERSION_0_10_0_ALPHA
    {
        for &peer in online_peers {
            remove_gateway(client, peer, &gw_lnd.addr).await?;
        }
    }

    for &peer in online_peers {
        remove_gateway(client, peer, &format!("iroh://{}", gw_lnd.node_id)).await?;
    }

    Ok(())
}

/// Exercise the direct HTLC CLI between two clients of the same federation,
/// with the full out-of-band handoff as strings: the claimer's key, the
/// funder's funding txid and contract JSON, and the forfeit signature. The
/// claimer's secret key and preimage are passed through files and stdin.
async fn test_direct_htlc(dev_fed: &DevJitFed) -> anyhow::Result<()> {
    if util::FedimintCli::version_or_default().await < *VERSION_0_14_0_ALPHA {
        info!("fedimint-cli does not support direct HTLCs, skipping");
        return Ok(());
    }

    let federation = dev_fed.fed().await?;

    let funder = federation
        .new_joined_client("lnv2-test-direct-htlc-funder")
        .await?;

    let claimer = federation
        .new_joined_client("lnv2-test-direct-htlc-claimer")
        .await?;

    assert_module_sanity(&funder).await?;

    federation.pegin_client(10_000, &funder).await?;

    let secrets_dir = PathBuf::from(std::env::var(FM_CLIENT_DIR_ENV)?).join("direct-htlc");

    tokio::fs::create_dir_all(&secrets_dir).await?;

    let claim_sk_file = secrets_dir.join("claim-sk");
    let preimage_file = secrets_dir.join("preimage");

    info!("Generating the claim keypair...");

    let claim_keypair = cmd!(
        claimer,
        "module",
        "lnv2",
        "htlc",
        "new-claim-keypair",
        "--secret-key-file",
        claim_sk_file.display()
    )
    .out_json()
    .await?;

    ensure!(
        claim_keypair.get("secret_key").is_none(),
        "The claim secret key must not be printed"
    );

    let claim_pk = json_string(&claim_keypair["public_key"])?;

    {
        use std::os::unix::fs::PermissionsExt as _;

        let mode = tokio::fs::metadata(&claim_sk_file)
            .await?
            .permissions()
            .mode();

        ensure!(mode & 0o777 == 0o600, "Secret key file has mode {mode:o}");
    }

    ensure!(
        cmd!(
            claimer,
            "module",
            "lnv2",
            "htlc",
            "new-claim-keypair",
            "--secret-key-file",
            claim_sk_file.display()
        )
        .run()
        .await
        .is_err(),
        "An existing secret key file must not be overwritten"
    );

    info!("Testing claim of a point-locked HTLC...");

    // The preimage of a point lock is the secret key of the payment point.
    let preimage = SecretKey::new(&mut OsRng);
    let preimage_hex = preimage.display_secret().to_string();
    let payment_point = preimage.public_key(SECP256K1).to_string();

    write_overwrite_async(&preimage_file, &preimage_hex).await?;

    let (funding_txid, contract) =
        create_htlc(&funder, &claim_pk, 100, "--payment-point", &payment_point).await?;

    let remaining_blocks = cmd!(
        claimer,
        "module",
        "lnv2",
        "htlc",
        "await-funded",
        funding_txid,
        contract
    )
    .out_json()
    .await?;

    ensure!(
        remaining_blocks.as_u64().is_some_and(|blocks| blocks > 0),
        "Expected the remaining blocks until expiration, got {remaining_blocks}"
    );

    let mut claim = cmd!(
        claimer,
        "module",
        "lnv2",
        "htlc",
        "claim",
        funding_txid,
        contract,
        "--claim-sk-file",
        claim_sk_file.display(),
        "--preimage-file",
        "-"
    );

    claim.cmd.stdin(std::fs::File::open(&preimage_file)?);

    let claim_operation = claim.out_json().await?;

    await_htlc_settled(&claimer, &claim_operation).await?;

    ensure!(claimer.balance().await? > 0);

    // The funder learns the preimage from the federation.
    assert_eq!(
        cmd!(
            funder,
            "module",
            "lnv2",
            "htlc",
            "await-resolution",
            funding_txid,
            contract
        )
        .out_json()
        .await?,
        preimage_hex
    );

    info!("Testing cooperative cancellation of a hash-locked HTLC...");

    let payment_hash = [42_u8; 32].consensus_hash::<sha256::Hash>().to_string();

    let (funding_txid, contract) =
        create_htlc(&funder, &claim_pk, 100, "--payment-hash", &payment_hash).await?;

    let balance_before_cancel = funder.balance().await?;

    let mut forfeit = cmd!(
        claimer,
        "module",
        "lnv2",
        "htlc",
        "forfeit",
        contract,
        "--claim-sk-file",
        "-"
    );

    forfeit.cmd.stdin(std::fs::File::open(&claim_sk_file)?);

    let forfeit_signature = json_string(&forfeit.out_json().await?)?;

    let cancel_operation = cmd!(
        funder,
        "module",
        "lnv2",
        "htlc",
        "cancel",
        funding_txid,
        contract,
        forfeit_signature
    )
    .out_json()
    .await?;

    await_htlc_settled(&funder, &cancel_operation).await?;

    ensure!(funder.balance().await? > balance_before_cancel);

    info!("Testing refund of an expired HTLC...");

    let (funding_txid, contract) =
        create_htlc(&funder, &claim_pk, 5, "--payment-hash", &payment_hash).await?;

    let balance_before_refund = funder.balance().await?;

    dev_fed.bitcoind().await?.mine_blocks(10).await?;

    // The funder is notified that the contract expired unclaimed...
    assert_eq!(
        cmd!(
            funder,
            "module",
            "lnv2",
            "htlc",
            "await-resolution",
            funding_txid,
            contract
        )
        .out_json()
        .await?,
        Value::Null
    );

    // ...and can refund it once the consensus block count has caught up.
    let refund_operation = retry(
        "Refunding the expired HTLC",
        backoff_util::aggressive_backoff_long(),
        || async {
            cmd!(
                funder,
                "module",
                "lnv2",
                "htlc",
                "refund",
                funding_txid,
                contract
            )
            .out_json()
            .await
        },
    )
    .await?;

    await_htlc_settled(&funder, &refund_operation).await?;

    ensure!(funder.balance().await? > balance_before_refund);

    Ok(())
}

/// Fund an HTLC of one thousand sats locked to `claim_pk`, wait for the
/// funding transaction to be accepted and return the funding txid and the
/// contract JSON as the claimer receives them out of band.
async fn create_htlc(
    funder: &Client,
    claim_pk: &str,
    expiration_delta: u64,
    lock_flag: &str,
    lock_value: &str,
) -> anyhow::Result<(String, String)> {
    let created = cmd!(
        funder,
        "module",
        "lnv2",
        "htlc",
        "create",
        "1000000",
        claim_pk,
        expiration_delta,
        lock_flag,
        lock_value
    )
    .out_json()
    .await?;

    // The contract is always the first output of its funding transaction.
    assert_eq!(created["outpoint"]["out_idx"], 0);

    await_htlc_settled(funder, &created["operation_id"]).await?;

    Ok((
        json_string(&created["outpoint"]["txid"])?,
        created["contract"].to_string(),
    ))
}

async fn await_htlc_settled(client: &Client, operation_id: &Value) -> anyhow::Result<()> {
    assert_eq!(
        cmd!(
            client,
            "module",
            "lnv2",
            "htlc",
            "await-settled",
            json_string(operation_id)?
        )
        .out_json()
        .await?,
        "settled"
    );

    Ok(())
}

fn json_string(value: &Value) -> anyhow::Result<String> {
    value
        .as_str()
        .map(str::to_owned)
        .with_context(|| format!("Expected a JSON string, got {value}"))
}

/// The balance of every account, so a step can show it moved only the
/// accounts it was meant to.
async fn account_balances(client: &Client) -> anyhow::Result<BTreeMap<Account, u64>> {
    let mut balances = BTreeMap::new();

    for account in Account::ALL {
        balances.insert(account, client.balance_for(account).await?);
    }

    Ok(balances)
}

/// The fees of the steps below are not quoted up front, so a balance that
/// moved is checked against its expected value with this much slack. The
/// balances that must not move are checked exactly.
const FEE_TOLERANCE_MSAT: u64 = 500_000;

fn ensure_close(actual: u64, expected: u64, what: &str) -> anyhow::Result<()> {
    almost_equal(actual, expected, FEE_TOLERANCE_MSAT)
        .map_err(|error| anyhow::anyhow!("{what}: {error}"))
}

/// Every account outside `touched` holds exactly what it held before.
fn ensure_untouched(
    before: &BTreeMap<Account, u64>,
    after: &BTreeMap<Account, u64>,
    touched: &[Account],
) -> anyhow::Result<()> {
    for account in Account::ALL {
        if touched.contains(&account) {
            continue;
        }

        ensure!(
            before[&account] == after[&account],
            "{account} moved from {} to {} msats without being involved",
            before[&account],
            after[&account]
        );
    }

    Ok(())
}

async fn lnv2_receive_into(
    client: &Client,
    gateway: &str,
    amount: u64,
    account: Account,
) -> anyhow::Result<(Bolt11Invoice, OperationId)> {
    Ok(serde_json::from_value(
        cmd!(
            client,
            "module",
            "lnv2",
            "receive",
            amount,
            "--gateway",
            gateway,
            "--account",
            account.to_string()
        )
        .out_json()
        .await?,
    )?)
}

async fn lnv2_send_from(
    client: &Client,
    gateway: &str,
    invoice: &str,
    account: Account,
) -> anyhow::Result<FinalSendOperationState> {
    let send_op = serde_json::from_value::<OperationId>(
        cmd!(
            client,
            "module",
            "lnv2",
            "send",
            invoice,
            "--gateway",
            gateway,
            "--account",
            account.to_string()
        )
        .out_json()
        .await?,
    )?;

    common::await_send(client, send_op).await
}

async fn test_walletv2_account(
    client: &Client,
    bitcoind: &Bitcoind,
    before: BTreeMap<Account, u64>,
) -> anyhow::Result<BTreeMap<Account, u64>> {
    const DEPOSIT_SAT: u64 = 50_000;
    const WITHDRAW_SAT: u64 = 20_000;

    info!("Testing an on-chain deposit into secondary...");

    // The position is read before the address is handed out so the receive
    // cannot be missed.
    let position = cmd!(client, "dev", "next-event-log-id").out_json().await?;

    let address = cmd!(
        client,
        "module",
        "walletv2",
        "receive",
        "--account",
        "secondary"
    )
    .out_json()
    .await?;

    let address = address.as_str().context("address is a string")?;

    bitcoind.send_to(address.to_owned(), DEPOSIT_SAT).await?;
    bitcoind.mine_blocks(21).await?;

    let output = cmd!(
        client,
        "module",
        "walletv2",
        "await-receive",
        position.to_string(),
        "--account",
        "secondary"
    )
    .out_json()
    .await?;

    ensure!(output[0] == "Success", "deposit was not claimed: {output}");

    cmd!(client, "dev", "wait-complete").run().await?;

    let after = account_balances(client).await?;

    ensure_untouched(&before, &after, &[Account::Secondary])?;
    ensure!(
        after[&Account::Secondary] > before[&Account::Secondary],
        "the deposit did not reach secondary"
    );

    info!("Testing an on-chain withdrawal from secondary...");

    let before = after;

    let withdraw_address = bitcoind.get_new_address().await?;

    let output = cmd!(
        client,
        "module",
        "walletv2",
        "send",
        withdraw_address.to_string(),
        format!("{WITHDRAW_SAT} sat"),
        "--account",
        "secondary"
    )
    .out_json()
    .await?;

    let txid = output["Success"]
        .as_str()
        .with_context(|| format!("withdrawal did not succeed: {output}"))?;

    bitcoind
        .poll_get_transaction(bitcoin::Txid::from_str(txid)?)
        .await?;

    cmd!(client, "dev", "wait-complete").run().await?;

    let after = account_balances(client).await?;

    ensure_untouched(&before, &after, &[Account::Secondary])?;
    ensure!(
        after[&Account::Secondary] + WITHDRAW_SAT * 1000 <= before[&Account::Secondary],
        "the withdrawal did not leave secondary"
    );

    Ok(after)
}

/// Every module runs against the real mintv2 here, so money bound to a
/// non-primary account has to stay in it across a Lightning refund and claim,
/// an on-chain deposit and withdrawal, and a recovery from seed. The gateways
/// must not be funded when this starts: the refund relies on it.
async fn test_accounts(dev_fed: &DevJitFed) -> anyhow::Result<()> {
    if util::FedimintCli::version_or_default().await < *VERSION_0_14_0_ALPHA {
        info!("fedimint-cli predates accounts, skipping");
        return Ok(());
    }

    let federation = dev_fed.fed().await?;
    let bitcoind = dev_fed.bitcoind().await?;
    let gw_lnd = dev_fed.gw_lnd().await?;
    let gw_ldk = dev_fed.gw_ldk().await?;

    let client = federation
        .new_joined_client("lnv2-test-accounts-client")
        .await?;

    if !module_is_present(&client, "mintv2").await?
        || !module_is_present(&client, "walletv2").await?
    {
        info!("mintv2 and walletv2 are not both enabled, skipping");
        return Ok(());
    }

    const SECONDARY_FUNDING_MSAT: u64 = 10_000_000;
    const LIGHTNING_AMOUNT_MSAT: u64 = 1_000_000;

    federation.pegin_client(20_000, &client).await?;

    info!("Moving funds from primary into secondary...");

    let before = account_balances(&client).await?;

    let ecash = cmd!(client, "module", "mintv2", "send", SECONDARY_FUNDING_MSAT)
        .out_json()
        .await?;

    let ecash = ecash.as_str().context("ecash is a string")?;

    let state = cmd!(
        client,
        "module",
        "mintv2",
        "receive",
        ecash,
        "--account",
        "secondary"
    )
    .out_json()
    .await?;

    ensure!(state == "Success", "receive failed: {state}");

    cmd!(client, "dev", "wait-complete").run().await?;

    let after = account_balances(&client).await?;

    ensure_untouched(&before, &after, &[Account::Primary, Account::Secondary])?;
    ensure_close(
        after[&Account::Primary] + SECONDARY_FUNDING_MSAT,
        before[&Account::Primary],
        "primary did not pay for the funding of secondary",
    )?;
    ensure_close(
        after[&Account::Secondary],
        SECONDARY_FUNDING_MSAT,
        "secondary did not receive its funding",
    )?;

    info!("Testing a refunded payment lands back in the paying account...");

    let before = after;

    // The invoice belongs to a throwaway client: its receive never settles
    // and would otherwise keep `wait-complete` on the client below from
    // returning until the invoice expires.
    let sink = federation
        .new_joined_client("lnv2-test-accounts-sink")
        .await?;

    let invoice = common::receive(&sink, &gw_ldk.addr, LIGHTNING_AMOUNT_MSAT)
        .await?
        .0;

    let state = lnv2_send_from(
        &client,
        &gw_lnd.addr,
        &invoice.to_string(),
        Account::Secondary,
    )
    .await?;

    ensure!(
        matches!(state, FinalSendOperationState::Refunded),
        "payment through an unfunded gateway must be refunded, got {state:?}"
    );

    cmd!(client, "dev", "wait-complete").run().await?;

    let after = account_balances(&client).await?;

    ensure_untouched(&before, &after, &[Account::Secondary])?;
    ensure_close(
        after[&Account::Secondary],
        before[&Account::Secondary],
        "the refund did not return to secondary",
    )?;

    pegin_gateways(dev_fed).await?;

    info!("Testing a payment between two accounts of one client...");

    let before = after;

    let (invoice, receive_op) = lnv2_receive_into(
        &client,
        &gw_ldk.addr,
        LIGHTNING_AMOUNT_MSAT,
        Account::Tertiary,
    )
    .await?;

    let state = lnv2_send_from(
        &client,
        &gw_lnd.addr,
        &invoice.to_string(),
        Account::Secondary,
    )
    .await?;

    ensure!(
        matches!(state, FinalSendOperationState::Success(_)),
        "payment through a funded gateway must succeed, got {state:?}"
    );

    common::await_receive_claimed(&client, receive_op).await?;

    cmd!(client, "dev", "wait-complete").run().await?;

    let after = account_balances(&client).await?;

    ensure_untouched(&before, &after, &[Account::Secondary, Account::Tertiary])?;
    ensure_close(
        after[&Account::Secondary] + LIGHTNING_AMOUNT_MSAT,
        before[&Account::Secondary],
        "secondary did not pay the invoice",
    )?;
    ensure_close(
        after[&Account::Tertiary],
        LIGHTNING_AMOUNT_MSAT,
        "tertiary did not claim the invoice",
    )?;

    let after = test_walletv2_account(&client, bitcoind, after).await?;

    info!("Recovering every account from the seed...");

    let expected = after;

    ensure!(
        expected[&Account::Primary] > 0
            && expected[&Account::Secondary] > 0
            && expected[&Account::Tertiary] > 0,
        "the recovery needs three funded accounts to tell apart, got {expected:?}"
    );

    let mnemonic = cmd!(client, "print-secret").out_json().await?["secret"]
        .as_str()
        .context("secret is a string")?
        .to_owned();

    let restored = Client::create("lnv2-test-accounts-restored").await?;

    cmd!(
        restored,
        "restore",
        "--invite-code",
        federation.invite_code()?,
        "--mnemonic",
        &mnemonic
    )
    .run()
    .await?;

    // Wait on the total so notes restored into the wrong account still end
    // the wait and fail the per-account check below instead of hanging.
    let expected_total = expected.values().sum::<u64>();

    while account_balances(&restored).await?.values().sum::<u64>() < expected_total {
        info!("Waiting for the recovery to complete...");
        cmd!(restored, "dev", "wait", "1").out_json().await?;
    }

    let recovered = account_balances(&restored).await?;

    ensure!(
        recovered == expected,
        "the recovered balances differ from the original ones: {recovered:?} vs {expected:?}"
    );

    info!("Spending the recovered secondary balance...");

    let ecash = cmd!(
        restored,
        "module",
        "mintv2",
        "send-max",
        "--account",
        "secondary"
    )
    .out_json()
    .await?;

    let ecash = ecash
        .as_str()
        .context("send-max must hand out the recovered secondary notes")?;

    let state = cmd!(restored, "module", "mintv2", "receive", ecash)
        .out_json()
        .await?;

    ensure!(state == "Success", "receive failed: {state}");

    cmd!(restored, "dev", "wait-complete").run().await?;

    let after = account_balances(&restored).await?;

    ensure_untouched(&expected, &after, &[Account::Primary, Account::Secondary])?;
    ensure!(
        after[&Account::Secondary] == 0,
        "send-max left {} msats in secondary",
        after[&Account::Secondary]
    );
    ensure_close(
        after[&Account::Primary],
        expected[&Account::Primary] + expected[&Account::Secondary],
        "primary did not receive the recovered secondary notes",
    )?;

    info!("Accounts test passed");

    Ok(())
}
