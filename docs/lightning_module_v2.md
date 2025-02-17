# Lightning Module V2 Protocol
The Lightning Module V2 protocol also extends the Lightning network into the federation, but makes some distinct changes from the V1 protocol. The gateway still holds e-cash (federation IOUs) and a balance in LN channels in the associated Lightning node. Below is a description of the changes from the V1 protocol and the associated diagrams.

## Receive
1) When receiving, the gateway uses HOLD invoices instead of HTLC interception to determine if a payment is destined for a Fedimint.
2) Users no longer put up a preimage for "sale" in an offer and instead directly create the `IncomingContract` and send it to a specific gateway.
3) The gateway is responsible for creating the Bolt11 invoice instead of the Fedimint client.
4) The gateway decrypts the preimage from the federation using the received decryption shares.

```mermaid
sequenceDiagram;
    participant r as Payee
    participant f as Federation
    participant g as Gateway
    participant gl as GW LN Node
    participant s as Payer
    g-->>gl: Subscribe to payment updates
    r->>g: Create IncomingContract and send to Gateway
    g->>r: Return Bolt11 Invoice
    par Payment
        r->>s: Invoice with hash(preimage)
        s->>gl: Payment with hash(preimage)
        gl->>g: Payment with hash(preimage)
        g->>f: Fund incoming contract
        f->>g: Decryption share for preimage
        f->>g: 
        f->>g: 
        g->>g: Decrypt preimage
        g->>gl: Claim Payment<br>with preimage
        gl->>s: Preimage
    and Claim Payment
        r->>f: Wait for incoming contract
        f->>r: 
        r->>f: Claim contract
        f->>r: E-Cash
    end
```

## Send
The V2 send protocol is very similar to the V1 send protocol. The main difference from V1 is that if the gateway fails to pay an invoice, in V2 it will return a `forfeit signature` to the client, which the client can use to claim the e-cash locked in the `OutgoingContract` before the specified timeout. Previously in V1, the gateway would need to submit a Fedimint transaction to modify the `OutgoingContract` to make it "cancellable".

The happy path for paying a Bolt 11 invoice in V1 and V2 remain the same:

```mermaid
sequenceDiagram;
    participant s as Payer
    participant f as Federation
    participant g as Gateway
    participant gl as GW LN Node
    participant r as Payee

    r->>s: Invoice with hash(preimage)
    s->>f: Fund outgoing contract
    f->>s: 
    s->>g: Instruct to pay invoice
    g->>f: Check outgoing contract exists
    f->>g: 
    g->>gl: Pay invoice
    gl->>r: Payment with hash(preimage)
    r->>gl: Preimage
    gl->>g: Preimage
    g->>f: Claim outgoing contract<br>with preimage
    f->>g: E-Cash
    s->>f: Wait for outgoing<br>contract claimed
    f->>s: Preimage
```