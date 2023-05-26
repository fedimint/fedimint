# Gateway UI

Web app experience for managing Fedimint gateways. This is used by Gateway administrators

## Development

### Environment setup

From root repo directory:

1. Start nix shell for developing UIs: `nix develop .#fedimint-ui`
1. Navigate to this directory: `cd /fedimint-ui/apps/gateway-ui`
1. Install dependencies if necessary: `yarn install`

### Run Federation and Gateways

In a new shell

1. Confirm you are in the root of fedimint repository
1. Run `nix #develop`
1. Start the test federation and two connected gateways by running `./scripts/tmuxinator.sh`

### Run UI with CLN gateway

1. Confirm you are in `gateway-ui/` app directory
1. Run `REACT_APP_FM_GATEWAY_API="http://127.0.0.1:8175" REACT_APP_FM_GATEWAY_PASSWORD="theresnosecondbest" yarn dev`

This will show you a running Gateway UI connected to a CLN gateway. You should see a federation listed since the gateway is already connected to a running federation

### Run UI with LND gateway

1. Confirm you are in `gateway-ui/` app directory
1. Run `REACT_APP_FM_GATEWAY_API="http://127.0.0.1:28175" REACT_APP_FM_GATEWAY_PASSWORD="theresnosecondbest" yarn dev`

This will show you a running Gateway UI connected to a LND gateway. You should see a federation listed since the gateway is already connected to a running federation

## Run Tests

TODO

## CI and misc

TODO
