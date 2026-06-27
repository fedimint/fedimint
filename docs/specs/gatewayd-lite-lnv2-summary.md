# Gateway-Lite (LNv2): Executive Summary

> Companion to [`gatewayd-lite-lnv2-detailed.md`](./gatewayd-lite-lnv2-detailed.md).
> Status: draft spec. Target: LNv2 (`fedimint-lnv2-*`).

## Problem

A small federation wants to offer Lightning send/receive but doesn't want to run and
operate its own Lightning node.

## Solution

Run a lightweight **gateway-lite** that proxies Lightning through a full `gatewayd`
already serving a **larger** federation. Downstream users keep their normal LNv2
custody guarantees, refund-unless-preimage (send) and claim-iff-funded (receive),
enforced by the *downstream* federation's consensus, not by any gateway.

## How it works

- **Send:** gateway-lite forwards the request to the upstream gateway, which pays over
  Lightning. The standard downstream outgoing-contract claim/refund applies.
- **Receive (the core):** the upstream gateway opens a **hold invoice** for the
  downstream payment hash. It can't produce the preimage itself, because the preimage
  is encrypted to the *downstream* federation. When the payee's downstream contract is
  funded and the federation reveals the preimage `P`, gateway-lite claims an upstream
  `OutgoingContract` with `P`. That single claim is one consensus-atomic step that both
  **reimburses** gateway-lite and **publishes `P`** so the upstream settles the held
  HTLC. It's "send run backwards."

## Key properties & caveats

- **Custody preserved, but not everything.** Custody/settlement guarantees match a full
  gateway. Availability, fees, and correlation are worse (the upstream sees the payment
  hash + amount and can fail receives before downstream funding).
- **Reimbursement atomicity has a precondition.** It holds only if the upstream settles
  the held HTLC *exclusively* from the published claim preimage. `P` has out-of-band
  reveal paths (the payee chose it, and the downstream decryption-share endpoint is
  unauthenticated), so a malicious upstream could settle elsewhere and refund. That's
  gateway-lite operator reimbursement loss, not downstream-user custody loss.
- **Timing: three clocks.** Downstream send expiry (block height), downstream receive
  expiry (unix time), and the upstream HTLC CLTV must be ordered with margins. The
  upstream HTLC deadline MUST come from the real accepted-HTLC CLTV. Surfacing that
  CLTV is a **hard prerequisite** and needs an LND backend extension (LDK already
  exposes it).
- **Fees fit existing caps.** Stacked upstream + downstream fees must fit
  `SEND/RECEIVE_FEE_LIMIT`. The client cap check is lexicographic, so gateway-lite
  self-enforces a component-wise bound and **withdraws** rather than advertising
  over-cap (clients still select it and then reject with `GatewayFeeExceedsLimit`).
- **Operator inventory (capital).** Gateway-lite still needs liquidity on both sides:
  downstream e-cash to fund receives and upstream e-cash/credit to pay sends. It must
  withdraw or refuse capacity when reserves run low.
- **Transparent to clients (MVP scope).** Unmodified LNv2 clients work, and gateway-lite is
  visible only as price (a higher quote). MVP receive support is for ordinary LNv2
  BOLT11 receive contracts with real unix expirations. LNURL-style receives, which
  overload `expiration_or_fee` with a fee, need separate handling.

## What's new to build

An authenticated, contract-decoupled **external hold-invoice API** (create / await /
settle / cancel) on the upstream gateway, a generalized hold-invoice filter
(`Lnv2HoldInvoiceFilter`), and the gateway-lite proxy itself. **No downstream
consensus changes.**

## How it compares

Gateway-lite is the complex fallback for when **no real-node gateway operator will
directly register with the small federation and hold inventory there**. Direct
registration of a normal LNv2 gateway is preferable whenever available. If the
federation or an operator can run a node, use a normal gateway instead, which avoids
the upstream trust/availability surface entirely.

## Status

Directionally sound and reviewed (core reimbursement atomicity verified, no Critical
findings). It isn't implementation-ready until the LND HTLC-deadline visibility and the
component-wise fee-cap items land. See the detailed spec for the full API surface,
timing model, trust analysis, and failure modes.
