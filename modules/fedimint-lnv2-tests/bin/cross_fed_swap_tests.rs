//! Cross-federation swap tests.
//!
//! Exercises the four sender/receiver direction combinations of LNv1 and LNv2
//! when a single gateway is registered with two federations. Each path should
//! settle internally on the gateway via the existing short-circuit logic
//! (`get_client_for_invoice` for LNv1->LNv1, `is_lnv2_direct_swap` for
//! LNv1->LNv2, `is_lnv1_invoice` for LNv2->LNv1, `is_direct_swap` for
//! LNv2->LNv2) without invoking the Lightning RPC.
//!
//! Runs the matrix twice: once against the LND gateway (regression that the
//! short-circuit logic works cross-fed for backends that have an LN node) and
//! once against a fresh gateway running `LightningMode::None` (the LN-less
//! gateway introduced for this test).

use devimint::external::LightningNode;
use devimint::federation::Federation;
use devimint::util::ProcessManager;
use devimint::version_constants::VERSION_0_12_0_ALPHA;
use devimint::{Gatewayd, util};
use fedimint_lnv2_client::FinalSendOperationState;
use fedimint_portalloc::port_alloc;
use tracing::info;

#[path = "common.rs"]
mod common;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    devimint::run_devfed_test()
        .num_feds(2)
        .call(|dev_fed, process_mgr| async move {
            if !util::supports_lnv2() {
                info!("lnv2 is disabled, skipping");
                return Ok(());
            }

            let fed1 = dev_fed.fed().await?.clone();
            let bitcoind = dev_fed.bitcoind().await?.clone();
            let mut fed2 = Federation::new(
                &process_mgr,
                bitcoind,
                false,
                false,
                false,
                1,
                "cross-fed-2".to_string(),
            )
            .await?;
            fed2.degrade_federation(&process_mgr).await?;
            info!(
                fed1_id = %fed1.calculate_federation_id(),
                fed1_invite = %fed1.invite_code()?,
                fed2_id = %fed2.calculate_federation_id(),
                fed2_invite = %fed2.invite_code()?,
                "Cross-fed test federations",
            );
            anyhow::ensure!(
                fed1.calculate_federation_id() != fed2.calculate_federation_id(),
                "Test setup produced two federations with the same id"
            );

            // First pass: existing LND gateway, registered with both feds.
            info!("--- cross-fed swaps via LND gateway ---");
            let gw_lnd = dev_fed.gw_lnd().await?.clone();
            gw_lnd.client().connect_fed(fed2.invite_code()?).await?;
            run_cross_fed_matrix(&fed1, &fed2, &gw_lnd).await?;

            let gatewayd_version = util::Gatewayd::version_or_default().await;
            if gatewayd_version >= *VERSION_0_12_0_ALPHA {
                // Second pass: a fresh gateway with no Lightning node,
                // registered with both feds.
                info!("--- cross-fed swaps via LN-less gateway ---");
                let gw_none = spawn_none_gateway(&process_mgr, "gatewayd-none", 3).await?;
                gw_none.client().connect_fed(fed1.invite_code()?).await?;
                gw_none.client().connect_fed(fed2.invite_code()?).await?;
                run_cross_fed_matrix(&fed1, &fed2, &gw_none).await?;

                // Third pass: gateway underfunded on the receiving side. The
                // sender's payment should refund instead of completing the swap.
                info!("--- cross-fed refund when gateway has no ecash on receiver ---");
                run_refund_when_receiver_gateway_unfunded(&process_mgr, &fed1, &fed2).await?;
            } else {
                info!(
                    %gatewayd_version,
                    "gatewayd does not support LightningMode::None, skipping LN-less gateway cases"
                );
            }

            info!("Cross-federation swap tests complete!");
            Ok(())
        })
        .await
}

/// Spawn a gateway with `LightningMode::None`. Allocates fresh ports so it
/// can coexist with the LND and LDK gateways from the dev federation.
async fn spawn_none_gateway(
    process_mgr: &ProcessManager,
    name: &str,
    gateway_index: usize,
) -> anyhow::Result<Gatewayd> {
    let gw_port = port_alloc(1)?;
    let metrics_port = port_alloc(1)?;
    Gatewayd::new(
        process_mgr,
        LightningNode::None {
            name: name.to_string(),
            gw_port,
            metrics_port,
        },
        gateway_index,
    )
    .await
}

/// Spin up a fresh `None` gateway, register it with both federations, peg-in
/// ecash *only* in the sender's federation, and attempt an LNv2 cross-fed
/// swap. The gateway has no ecash on the receiver side and so cannot fund the
/// incoming contract; the sender's outgoing contract must refund.
async fn run_refund_when_receiver_gateway_unfunded(
    process_mgr: &ProcessManager,
    fed_sender: &Federation,
    fed_receiver: &Federation,
) -> anyhow::Result<()> {
    let gw = spawn_none_gateway(process_mgr, "gatewayd-none-refund", 4).await?;
    gw.client().connect_fed(fed_sender.invite_code()?).await?;
    gw.client().connect_fed(fed_receiver.invite_code()?).await?;

    // Fund the gateway on the sender side only. Receiver-side gateway has 0
    // ecash and will fail to fund the incoming contract.
    fed_sender.pegin_gateways(1_000_000, vec![&gw]).await?;

    let sender = fed_sender.new_joined_client("refund-test-sender").await?;
    let receiver = fed_receiver
        .new_joined_client("refund-test-receiver")
        .await?;
    fed_sender.pegin_client(10_000, &sender).await?;

    info!("LNv2 -> LNv2 cross-fed swap with unfunded receiver gateway");
    let (invoice, _receive_op) = common::receive(&receiver, &gw.addr, 1_000_000).await?;
    let state = common::send(&sender, &gw.addr, &invoice.to_string()).await?;
    assert!(
        matches!(state, FinalSendOperationState::Refunded),
        "expected refund, got {state:?}"
    );
    Ok(())
}

async fn run_cross_fed_matrix(
    fed1: &Federation,
    fed2: &Federation,
    gw: &Gatewayd,
) -> anyhow::Result<()> {
    fed1.pegin_gateways(1_000_000, vec![gw]).await?;
    fed2.pegin_gateways(1_000_000, vec![gw]).await?;

    let client_a = fed1.new_joined_client("cross-fed-client-a").await?;
    let client_b = fed2.new_joined_client("cross-fed-client-b").await?;
    fed1.pegin_client(10_000, &client_a).await?;
    fed2.pegin_client(10_000, &client_b).await?;

    let gw_id = gw.gateway_id.clone();

    info!("LNv1 -> LNv1 cross-fed swap");
    let (lnv1_invoice, lnv1_op) = common::receive_lnv1(&client_b, &gw_id, 1_000_000).await?;
    common::send_lnv1(&client_a, &gw_id, &lnv1_invoice.to_string()).await?;
    common::await_receive_lnv1(&client_b, lnv1_op).await?;

    info!("LNv2 -> LNv2 cross-fed swap");
    let (lnv2_invoice, lnv2_op) = common::receive(&client_b, &gw.addr, 1_000_000).await?;
    let state = common::send(&client_a, &gw.addr, &lnv2_invoice.to_string()).await?;
    assert!(
        matches!(state, FinalSendOperationState::Success(_)),
        "expected success, got {state:?}"
    );
    common::await_receive_claimed(&client_b, lnv2_op).await?;

    info!("LNv1 -> LNv2 cross-fed swap");
    let (lnv2_invoice, lnv2_op) = common::receive(&client_b, &gw.addr, 1_000_000).await?;
    common::send_lnv1(&client_a, &gw_id, &lnv2_invoice.to_string()).await?;
    common::await_receive_claimed(&client_b, lnv2_op).await?;

    info!("LNv2 -> LNv1 cross-fed swap");
    let (lnv1_invoice, lnv1_op) = common::receive_lnv1(&client_b, &gw_id, 1_000_000).await?;
    let state = common::send(&client_a, &gw.addr, &lnv1_invoice.to_string()).await?;
    assert!(
        matches!(state, FinalSendOperationState::Success(_)),
        "expected success, got {state:?}"
    );
    common::await_receive_lnv1(&client_b, lnv1_op).await?;

    Ok(())
}
