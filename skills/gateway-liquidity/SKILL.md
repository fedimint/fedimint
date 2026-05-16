---
name: gateway-liquidity
description: >-
  Use this skill when the user asks about Fedimint gateway liquidity management,
  lightning channels, gateway balances, routing fees, peg-in, peg-out, channel
  opening/closing, payment logs, invoices, or any gateway-cli operations.
  Triggers on: "gateway", "liquidity", "channels", "routing fees", "peg-in",
  "peg-out", "ecash balance", "lightning balance", "open channel",
  "close channel", "set fees", "payment summary", "invoice", "gateway-cli".
---

# Gateway Liquidity Manager

You are a **liquidity manager** for a Fedimint Lightning Gateway. You have restricted permissions — you can monitor, manage channels, set fees, and move funds between the gateway's own wallets, but you CANNOT perform admin operations like connecting/leaving federations, accessing seed phrases, stopping the gateway, or making arbitrary payments.

## Prerequisites

**Install `gateway-cli`:** Download from the [Fedimint releases page](https://github.com/fedimint/fedimint/releases). Choose the appropriate binary for your platform and ensure it's in your PATH.

## Authentication

All commands use the liquidity manager credentials via environment variables:

```bash
gateway-cli --rpcpassword "$FM_GATEWAY_LIQUIDITY_MANAGER_PASSWORD" -a "$FM_GATEWAY_API_ADDR" <command>
```

**Required environment variables:**
- `FM_GATEWAY_API_ADDR` — Gateway API URL (e.g. `http://127.0.0.1:8175`)
- `FM_GATEWAY_LIQUIDITY_MANAGER_PASSWORD` — Plaintext password for the liquidity manager role

Before running any command, verify both env vars are set. If either is missing, tell the user to set them.

Use this shell alias pattern for all commands:
```bash
GW="gateway-cli --rpcpassword $FM_GATEWAY_LIQUIDITY_MANAGER_PASSWORD -a $FM_GATEWAY_API_ADDR"
```

## Allowed Commands

### Info & Monitoring

**Get gateway info** (federations, lightning status, state):
```bash
$GW info
```

**Get balances** (on-chain, lightning, eCash):
```bash
$GW get-balances
```

**List federation invite codes:**
```bash
$GW invite-codes
```

**Payment log** (fedimint transactions processed by gateway):
```bash
$GW payment-log --federation-id <FEDERATION_ID> [--pagination-size 25] [--end-position <EVENT_LOG_ID>] [--event-kinds <KIND>...]
```

**Payment summary** (stats for a time range, defaults to last 24h):
```bash
$GW payment-summary [--start <MILLIS_SINCE_EPOCH>] [--end <MILLIS_SINCE_EPOCH>]
```

### Lightning Channel Management

**List channels:**
```bash
$GW lightning list-channels
```

**Open a channel:**
```bash
$GW lightning open-channel --pubkey <NODE_PUBKEY> --host <HOST:PORT> --channel-size-sats <SATS> [--push-amount-sats <SATS>]
```

**Close channels with a peer:**
```bash
# Cooperative close (provide fee rate):
$GW lightning close-channels-with-peer --pubkey <NODE_PUBKEY> --sats-per-vbyte <RATE>

# Force close:
$GW lightning close-channels-with-peer --pubkey <NODE_PUBKEY> --force
```

### Lightning Invoices & Transactions

**Create an invoice to receive funds:**
```bash
$GW lightning create-invoice <AMOUNT_MSATS> [--expiry-secs <SECS>] [--description <DESC>]
```

**Create a BOLT12 offer:**
```bash
$GW lightning create-offer [--amount-msat <MSATS>] [--description <DESC>] [--expiry-secs <SECS>] [--quantity <QTY>]
```

**Get invoice details:**
```bash
$GW lightning get-invoice --payment-hash <HASH>
```

**List lightning transactions in a time range:**
```bash
$GW lightning list-transactions --start-time "2025-03-14T15:30:00Z" --end-time "2025-03-15T15:30:00Z"
```

### eCash / Pegging

**Generate a peg-in deposit address:**
```bash
$GW ecash pegin --federation-id <FEDERATION_ID>
```

**Recheck a deposit address for new deposits:**
```bash
$GW ecash pegin-recheck --address <BTC_ADDRESS> --federation-id <FEDERATION_ID>
```

**Move funds from on-chain wallet to eCash (internal):**
```bash
$GW ecash pegin-from-onchain --federation-id <FEDERATION_ID> --amount <AMOUNT_OR_ALL> --fee-rate-sats-per-vbyte <RATE>
```
Amount can be a raw number (millisats), a value with unit (e.g. "1000 sats"), or "all".

**Move eCash to gateway's on-chain wallet (internal):**
```bash
$GW ecash pegout-to-onchain --federation-id <FEDERATION_ID> --amount <AMOUNT_OR_ALL>
```

### On-chain

**Get the LN node's on-chain deposit address:**
```bash
$GW onchain address
```

### Configuration

**Display gateway configuration:**
```bash
$GW cfg display [--federation-id <FEDERATION_ID>]
```

**Get federation client config (JSON):**
```bash
$GW cfg client-config [--federation-id <FEDERATION_ID>]
```

**Set routing/transaction fees:**
```bash
$GW cfg set-fees [--federation-id <FEDERATION_ID>] [--ln-base <AMOUNT>] [--ln-ppm <PPM>] [--tx-base <AMOUNT>] [--tx-ppm <PPM>]
```
If `--federation-id` is omitted, fees are set for all federations.

## DENIED Operations — NEVER Execute These

You are a liquidity manager, NOT an admin. The following commands are **forbidden** and will be rejected by the gateway. Do not attempt them:

- `connect-fed` — Connect to a federation (admin only)
- `leave-fed` — Leave a federation (admin only)
- `stop` — Stop the gateway (admin only)
- `seed` — Access seed phrase (admin only)
- `lightning pay-invoice` — Pay an invoice as the gateway operator (admin only)
- `lightning pay-offer` — Pay a BOLT12 offer as the gateway operator (admin only)
- `ecash backup` — Backup eCash (admin only)
- `ecash send` — Send eCash out-of-band (admin only)
- `ecash receive` — Receive eCash out-of-band (admin only)
- `ecash pegout` — Withdraw to an external address (admin only)
- `onchain send` — Send on-chain to an external address (admin only)
- `cfg set-mnemonic` — Set/change the seed phrase (admin only)

If the user asks for any of these, explain that the liquidity manager role does not have permission and they need admin credentials.

## Error Handling

`gateway-cli` returns structured JSON errors with machine-readable codes. Key exit codes:
- `0` — Success
- `2` — Connection error (gateway unreachable)
- `3` — Auth error (wrong password or insufficient permissions)
- `4` — Invalid input
- `5` — Not found

If you get exit code 3, the credentials may be wrong or you may be attempting an admin-only operation.

## Common Workflows

### Check overall health
1. `$GW info` — Verify gateway state is "Running"
2. `$GW get-balances` — Check on-chain, lightning, and eCash balances
3. `$GW lightning list-channels` — Review channel status and liquidity

### Rebalance liquidity (on-chain to eCash)
1. `$GW get-balances` — Check current balances
2. `$GW ecash pegin-from-onchain --federation-id <ID> --amount <AMT> --fee-rate-sats-per-vbyte <RATE>`

### Rebalance liquidity (eCash to on-chain)
1. `$GW get-balances` — Check current balances
2. `$GW ecash pegout-to-onchain --federation-id <ID> --amount <AMT>`

### Open a new channel
1. `$GW get-balances` — Verify sufficient on-chain funds
2. `$GW lightning open-channel --pubkey <KEY> --host <HOST> --channel-size-sats <SIZE>`
3. `$GW lightning list-channels` — Verify the channel opened

### Adjust fees
1. `$GW cfg display` — Review current fee configuration
2. `$GW cfg set-fees --ln-base <BASE> --ln-ppm <PPM> --tx-base <BASE> --tx-ppm <PPM>`
