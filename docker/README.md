# Docker support

Our CI
[automatically](https://github.com/fedimint/fedimint/blob/67760e2f21d2fa628ec9cd549b4bfb65571e4511/.github/workflows/ci-
nix.yml#L375C3-L375C13) publishes [docker container images of all fedimintd
components](https://hub.docker.com/u/fedimint).

See [./deploy-fedimintd] for a script deploying `fedimintd` to a fresh system.
It is reguarily tried, so should stay working.

In the past we had more elaborated tutorial and documentation, but we had to scale
it down, due to amount of time required to keep them up to date. See content
of this directory in the past releases for more info.

For help please try [Fedimint Github Discussions](https://github.com/fedimint/fedimint/discussions)
or `#mint-ops` channel on [Fedimint's Discord server](https://chat.fedimint.org/).

## Iroh (Experimental)

To try the experimental Iroh integration with Mutinynet, use the provided Docker Compose setup:

```bash
cd iroh-fedimintd
docker compose up -d
```

Then, access the web UI at [http://localhost:8175](http://localhost:8175).

If Docker runs on a remote machine, forward the port locally with:

```bash
ssh -NL 8175:127.0.0.1:8175 <your_server>
```

### Mutinynet Deposit

#### Join

Using the invite code from your guardian dashboard, join the federation using `fedimint-cli`:

```bash
docker run -it --rm \
  -e RUST_LOG=off \
  -v "$(pwd)/mutinynet-client":/mutinynet-client \
  fedimint/fedimint-cli:v0.7.0-beta.1 \
  fedimint-cli \
    --data-dir /mutinynet-client \
    join-federation <invite_code>
```

This will join the federation and create a client database in your current directory.

#### Deposit

Get a new deposit address

```bash
docker run -it --rm \
  -e RUST_LOG=off \
  -v "$(pwd)/mutinynet-client":/mutinynet-client \
  fedimint/fedimint-cli:v0.7.0-beta.1 \
  fedimint-cli \
    --data-dir /mutinynet-client \
    module wallet new-deposit-address
```

Take the address and request funds from the Mutinynet [faucet](https://faucet.mutinynet.com/). This requires logging in with GitHub.

Await the deposit:

```bash
docker run -it --rm \
  -e RUST_LOG=off \
  -e FM_FORCE_BITCOIN_RPC_URL=https://mutinynet.com/api \
  -v "$(pwd)/mutinynet-client":/mutinynet-client \
  fedimint/fedimint-cli:v0.7.0-beta.1 \
  fedimint-cli \
    --data-dir /mutinynet-client \
    module wallet await-deposit <address>
```

This command may take over 10 minutes to complete since we need several confirmations to claim the deposit.

Once you've claimed the deposit, check the wallet balance in the guardian dashboard and the client balance:

```bash
docker run -it --rm \
  -e RUST_LOG=off \
  -e FM_FORCE_BITCOIN_RPC_URL=https://mutinynet.com/api \
  -v "$(pwd)/mutinynet-client":/mutinynet-client \
  fedimint/fedimint-cli:v0.7.0-beta.1 \
  fedimint-cli \
    --data-dir /mutinynet-client \
    info
```

#### Send Back Sats

When you're done experimenting with the setup, send your sats back to the friendly folks operating the Mutinynet faucet:

```bash
docker run -it --rm \
  -e RUST_LOG=off \
  -e FM_FORCE_BITCOIN_RPC_URL=https://mutinynet.com/api \
  -v "$(pwd)/mutinynet-client":/mutinynet-client \
  fedimint/fedimint-cli:v0.7.0-beta.1 \
  fedimint-cli \
    --data-dir /mutinynet-client \
    withdraw --amount all --address tb1qd28npep0s8frcm3y7dxqajkcy2m40eysplyr9v
```
