# Gateway UI

Web app experience for managing Fedimint gateways. This is used by Gateway administrators

## Development

### Environment setup

From root repo directory:

1. Start nix shell: `nix develop`
1. Navigate to this directory: `cd /fedimint-ui/apps/gateway-ui`
1. Install dependencies if necessary: `yarn install`

### Run Federations and UI

1. Confirm you are in `gateway-ui/` directory
1. Run `REACT_APP_FM_GATEWAY_API="http://127.0.0.1:8175" yarn dev`

This will show you a running gateway UI with mock data

## Run Tests

TODO

## CI and misc

TODO
