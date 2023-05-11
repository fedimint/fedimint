# Guardian UI

Web app experience for setting up and administering fedimints. This is used by the Fedimint guardians

## Development

### Environment setup

From root repo directory:

1. Start nix shell for developing UIs: `nix develop .#fedimint-ui`
1. Navigate to this directory: `cd /fedimint-ui/apps/guardian-ui`
1. Install dependencies if necessary: `yarn install`

### Run Federations and UI

Do the following in separate terminals:

- **First terminal**

1. Confirm you are in the root of fedimint repository
1. Start fedimintd servers by running `./scripts/run-ui.sh new`

- **Second Terminal**

1. Confirm you are in `guardian-ui/` directory
1. Run `PORT=3000 REACT_APP_FM_CONFIG_API="ws://127.0.0.1:18174" yarn dev`
   - This will be your "Leader" instance

- **Third Terminal**

1. Confirm you are in `guardian-ui/` directory
1. Run `PORT=3001 REACT_APP_FM_CONFIG_API="ws://127.0.0.1:18184" yarn dev`
   - This will be your "Follower" instance

- **Other Terminals** (optional)

1. Adapt the steps above to run the UI instances for other "Follower" guardians

This will allow you to complete the full setup process locally with a federation of 2 or more guardians.

## Run Tests

TODO

## CI and misc

TODO
