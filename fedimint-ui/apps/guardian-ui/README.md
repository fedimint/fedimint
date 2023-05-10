# Guardian UI

Web app experience for setting up and administering fedimints. This is used by the Fedimint guardians

## Development

### Environment setup

From root repo directory:

1. Start nix shell for developing UIs with `nix develop .#fedimint-ui`
1. Navigate to this directory `cd /fedimint-ui/apps/guardian-ui`

### Run Federations and UI

Run the following in separate terminals:

1. Start fedimintd servers from repository root by running `./scripts/run-ui.sh new`
1. From the current directory, `guardian-ui/`, run `PORT=3000 REACT_APP_FM_CONFIG_API="ws://127.0.0.1:18174" yarn dev`
   - This will be your "Leader" instance
1. From the current directory, `guardian-ui/`, run `PORT=3001 REACT_APP_FM_CONFIG_API="ws://127.0.0.1:18184" yarn dev`
   - This will be your "Follower" instance

This will allow you to complete the full setup process locally with a federation of 2 guardians.

## Run Tests

TODO

## CI and misc

TODO
