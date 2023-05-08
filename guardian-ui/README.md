# Guardian UI

## Development

### Environment setup

From root repo directory:

1. `cd guardian-ui`
1. `nix develop .#fedimint-ui`
1. `yarn` (only needs done on first init)

### Run Federations and UI

Run the following in separate terminals:

1. In repository root, run `./scripts/run-ui.sh new`
1. In `guardian-ui/`, run `PORT=3000 REACT_APP_FM_CONFIG_API="ws://127.0.0.1:18174" yarn start`
   - This will be your "Host" instance
1. In `guardian-ui/`, run `PORT=3001 REACT_APP_FM_CONFIG_API="ws://127.0.0.1:18184" yarn start`
   - This will be your "Follower" instance

This will allow you to complete the full setup process locally with a federation of 2 guardians.

## Run Tests

TODO

## CI and misc.

TODO

## NOTE

To the 🦀 devs, we're sorry for the javascript.
