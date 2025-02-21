# Lightning Module V1 Protocol
On a high-level, we simply extend the LN network into the federation. The LN
Gateway acts as a translation layer between the trustless LN network and the
trusted federation. To do so, the LN gateway holds both e-cash (federation
IOUs) and balance in LN channels in its associated LN node. When sending
or receiving payments on behalf of users it exchanges one for the other.

See the diagrams below for details on incoming and outgoing flows.

## Receive

In the V1 Lightning protocol, the gateway uses HTLC interception to determine if an incoming payment is destined for a Fedimint.

```mermaid
sequenceDiagram;
    participant r as Payee
    participant f as Federation
    participant g as Gateway
    participant gl as GW LN Node
    participant s as Payer

    r->>f: Put preimage for sale<br>(Incoming Contract Offer)
    f->>r: 

    par Payment
        r->>s: Invoice with hash(preimage)
        g-->>gl: Subscribe to HTLCs
        s->>gl: HTLC with hash(preimage)
        gl->>g: HTLC with hash(preimage)
        g->>f: Fund incoming contract
        f->>f: Decrypt preimage<br>from Offer
        f->>g: Preimage
        g->>gl: Claim HTLC<br>with preimage
        gl->>s: Preimage
    and Claim Payment
        r->>f: Wait for incoming contract
        f->>r: 
        r->>f: Claim contract
        f->>r: E-Cash
    end
```

## Send

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
    gl->>r: HTLC with hash(preimage)
    r->>gl: Preimage
    gl->>g: Preimage
    g->>f: Claim outgoing contract<br>with preimage
    f->>g: E-Cash
    s->>f: Wait for outgoing<br>contract claimed
    f->>s: Preimage
```
