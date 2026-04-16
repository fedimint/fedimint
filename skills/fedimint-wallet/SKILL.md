---
name: fedimint-wallet
description: >-
  Use this skill when the user asks about Fedimint wallet operations,
  eCash payments, spending or receiving notes, checking balances,
  lightning invoices, on-chain deposits or withdrawals, peg-in, peg-out,
  or any fedimint-cli operations for managing a Fedimint wallet.
  Triggers on: "fedimint", "ecash", "wallet", "spend", "receive",
  "balance", "notes", "peg-in", "peg-out", "deposit", "withdraw",
  "lightning invoice", "ln-pay", "reissue", "OOB notes", "bearer tokens",
  "federation", "fedimint-cli".
argument-hint: "[wallet operation or amount]"
allowed-tools: [Bash, Read]
---

# Fedimint Wallet

You are a **wallet operator** for a Fedimint federation. You can check balances, spend and receive eCash notes, make and receive Lightning payments, and manage on-chain peg-in/peg-out operations. You hold bearer tokens (eCash notes) — no account needed, no identity linked.

eCash notes are Chaumian blind-signed bearer tokens. Whoever holds the notes owns the value. Notes are private — the federation that signed them cannot link the spender to the receiver.

## Prerequisites

**Install `fedimint-cli`:** Download from the [Fedimint releases page](https://github.com/fedimint/fedimint/releases). Choose the appropriate binary for your platform and ensure it's in your PATH.

**Join a federation** (one-time setup):
```bash
fedimint-cli join "fed11..."
```

## Authentication

All commands use `fedimint-cli` with the data directory pointing to your wallet state:

```bash
export FM_CLIENT_DIR="$HOME/.fedimint-client"
```

If the federation requires authentication, set:
```bash
export FM_PASSWORD="your-password"
```

Use this alias for all commands:
```bash
FM="fedimint-cli"
```

Before running any command, verify the wallet is connected:
```bash
$FM info
```

This should return your balance and federation details. If it errors, the wallet is not joined to a federation.

## Allowed Commands

### Info & Balance

**Display wallet info (holdings by denomination tier):**
```bash
$FM info
```

**List recent operations:**
```bash
$FM list-operations --limit 25
```

**Get federation client config:**
```bash
$FM config
```

**Get current session count (AlephBFT consensus round):**
```bash
$FM session-count
```

**Discover common API version with federation:**
```bash
$FM discover-version
```

### Spending eCash (Sending)

**Spend notes (create OOB notes to send to someone):**
```bash
$FM spend <AMOUNT_MSATS>
```

Options:
```bash
# Allow overpayment (eCash comes in denominations — exact amounts may not be possible)
$FM spend <AMOUNT_MSATS> --allow-overpay

# Set timeout in seconds for the spend operation
$FM spend <AMOUNT_MSATS> --timeout 60

# Include federation invite code in the notes (helps receiver join if not already a member)
$FM spend <AMOUNT_MSATS> --include-invite
```

The command returns a string of OOB notes. Send this string to the recipient through any channel (message, QR code, HTTP header, file).

### Receiving eCash

**Reissue notes received from someone (claim them into your wallet):**
```bash
$FM reissue "<OOB_NOTES_STRING>"
```

Options:
```bash
# Wait for the reissue to complete before returning
$FM reissue "<OOB_NOTES_STRING>" --wait
```

The reissue operation validates the blind signatures and adds the notes to your wallet. If the notes were already spent (double-spend attempt), this will fail.

**Split a multi-note string into individual notes:**
```bash
$FM split "<OOB_NOTES_STRING>"
```

**Combine multiple note strings into one:**
```bash
$FM combine "<NOTES_1>" "<NOTES_2>" "<NOTES_3>"
```

### Lightning Payments (via Gateway)

**List available Lightning gateways:**
```bash
$FM list-gateways
```

**Create a Lightning invoice to receive a payment:**
```bash
$FM ln-invoice <AMOUNT_MSATS> "<DESCRIPTION>"
```

Options:
```bash
# Set expiry time in seconds
$FM ln-invoice <AMOUNT_MSATS> "<DESCRIPTION>" --expiry-time 3600

# Use a specific gateway
$FM ln-invoice <AMOUNT_MSATS> "<DESCRIPTION>" --gateway-id <GATEWAY_PUBKEY>

# Force internal payment (within same federation — no Lightning, faster)
$FM ln-invoice <AMOUNT_MSATS> "<DESCRIPTION>" --force-internal
```

**Wait for an invoice to be paid:**
```bash
$FM await-invoice <OPERATION_ID>
```

**Pay a Lightning invoice or LNURL:**
```bash
$FM ln-pay "<BOLT11_INVOICE_OR_LNURL>"
```

Options:
```bash
# Specify amount (required for zero-amount invoices and LNURL)
$FM ln-pay "<LNURL>" --amount <AMOUNT_MSATS>

# Add LNURL comment
$FM ln-pay "<LNURL>" --lnurl-comment "payment for service"

# Use a specific gateway
$FM ln-pay "<BOLT11>" --gateway-id <GATEWAY_PUBKEY>

# Force internal payment
$FM ln-pay "<BOLT11>" --force-internal
```

**Wait for a Lightning payment to complete:**
```bash
$FM await-ln-pay <OPERATION_ID>
```

### On-Chain (Peg-In / Peg-Out)

**Generate a new deposit address (peg-in):**
```bash
$FM deposit-address
```

This returns a Bitcoin address controlled by the federation. Send BTC to this address to peg in. The federation will mint eCash once the deposit is confirmed on-chain.

**Wait for a deposit to be confirmed:**
```bash
$FM await-deposit <OPERATION_ID>
```

**Withdraw to an on-chain Bitcoin address (peg-out):**
```bash
$FM withdraw <AMOUNT_SATS_OR_ALL> <BITCOIN_ADDRESS>
```

Amount can be a specific satoshi amount or "all" to withdraw the entire balance.

### Backup & Recovery

**Upload encrypted wallet backup to the federation:**
```bash
$FM backup
```

Options:
```bash
# Add metadata to the backup
$FM backup --metadata "description=daily backup" --metadata "date=2026-04-15"
```

**Restore a wallet from backup (join + restore):**
```bash
$FM restore --invite-code "fed11..."
```

Options:
```bash
# Provide mnemonic explicitly (if not stored)
$FM restore --invite-code "fed11..." --mnemonic "word1 word2 word3 ..."
```

## DENIED Operations — NEVER Execute These

You are a wallet operator, NOT a federation administrator or gateway operator. The following operations are **forbidden**:

- `print-secret` — Display the wallet's secret key (NEVER expose key material)
- Any direct database manipulation or file access to `$FM_CLIENT_DIR`
- Starting, stopping, or configuring `fedimintd` (guardian operations)
- Opening, closing, or managing Lightning channels (gateway operator operations — use the `gateway-liquidity` skill)
- Setting or modifying gateway fees (gateway operator operations)
- Connecting or disconnecting gateways from federations (gateway admin operations)
- Running `fedimint-cli module` with admin-level module subcommands
- Accessing seed phrases or mnemonics outside of the restore flow
- Sharing OOB notes strings in logs, error messages, or public channels (notes are bearer tokens — sharing them is sharing money)

If the user asks for any of these, explain that the wallet skill does not have permission and they need the appropriate admin or gateway operator credentials.

## Error Handling

`fedimint-cli` returns structured output. Key error patterns:

- **"Federation error"** — federation is unreachable or consensus is down. Check internet connection and federation status.
- **"Insufficient balance"** — not enough eCash to complete the operation. Check balance with `$FM info`.
- **"Double spend"** / **"Already spent"** — notes have already been redeemed. They are gone. Do not retry.
- **"Invoice expired"** — Lightning invoice expired before payment. Request a new invoice.
- **"Gateway not available"** — no Lightning gateway registered or gateway is offline. Check with `$FM list-gateways`.
- **"Timeout"** — operation took too long. For spend operations, the notes may still be locked. Wait and check balance.
- **Connection errors** — fedimint-cli cannot reach the federation API. Verify `$FM_CLIENT_DIR` is correct and federation is online.

If a spend operation fails mid-way, check your balance. The notes may be temporarily locked with a timeout — they will return to your balance after the timeout expires.

## Common Workflows

### Check wallet status
1. `$FM info` — view balance by denomination tier
2. `$FM list-gateways` — verify Lightning gateway is available
3. `$FM list-operations --limit 5` — check recent operations

### Send eCash to someone
1. `$FM info` — verify sufficient balance
2. `$FM spend <AMOUNT> --allow-overpay` — create OOB notes
3. Send the notes string to the recipient (message, QR, file, HTTP header)
4. Recipient runs `$FM reissue "<NOTES>"` on their side

### Receive eCash from someone
1. Receive OOB notes string from the sender
2. `$FM reissue "<NOTES>" --wait` — claim notes into your wallet
3. `$FM info` — verify balance increased

### Pay a Lightning invoice
1. `$FM list-gateways` — verify a gateway is available
2. `$FM ln-pay "<BOLT11_INVOICE>"` — pay the invoice
3. Note the operation_id from the output
4. `$FM await-ln-pay <OPERATION_ID>` — wait for confirmation
5. Confirmation includes the preimage as proof of payment

### Receive via Lightning
1. `$FM ln-invoice <AMOUNT> "description"` — create an invoice
2. Share the BOLT11 invoice with the payer
3. Note the operation_id from the output
4. `$FM await-invoice <OPERATION_ID>` — wait for payment
5. `$FM info` — verify balance increased

### Peg in (deposit BTC)
1. `$FM deposit-address` — get a federation deposit address
2. Note the operation_id from the output
3. Send BTC to the address from any Bitcoin wallet
4. `$FM await-deposit <OPERATION_ID>` — wait for on-chain confirmation
5. `$FM info` — verify eCash balance reflects the deposit

### Peg out (withdraw BTC)
1. `$FM info` — verify sufficient balance
2. `$FM withdraw <AMOUNT_OR_ALL> <YOUR_BITCOIN_ADDRESS>` — withdraw
3. Wait for on-chain confirmation (federation broadcasts the transaction)
4. Check your Bitcoin wallet for the incoming transaction

### Backup wallet
1. `$FM backup --metadata "description=weekly backup"` — upload encrypted backup
2. Backup is stored by the federation — encrypted with your key, federation cannot read it
3. To restore on a new device: `$FM restore --invite-code "fed11..."`

### x402 Payment (agent paying for an HTTP resource)
1. Receive 402 response with payment requirements (amount in msats)
2. `$FM spend <AMOUNT> --allow-overpay` — create OOB notes
3. Retry the HTTP request with notes in the `PAYMENT-SIGNATURE` header
4. Server reissues the notes (settlement) and returns the resource
5. If server returns error after payment: attempt `$FM reissue "<NOTES>"` to recover

### Agent-to-agent eCash transfer
1. Agent A: `$FM spend <AMOUNT> --allow-overpay` — create notes
2. Agent A sends notes to Agent B via any channel (API call, message, file)
3. Agent B: `$FM reissue "<NOTES>" --wait` — claim notes
4. Transfer is complete — private, instant, no fees inside the federation
