# Fedimint UI Projects

## What's Inside

This project includes the following apps / packages:

### Apps

- `guardian-ui`: Web app experience for setting up and administering fedimints. This is used by the Fedimint guardians
- `gateway-ui`: Web app experience for managing Fedimint gateways. This is used by Gateway administrators

### Packages

- `ui`: Shared React UI component library for building Fedimint UI experiences
- `eslint-config`: Shared `eslint` configurations (includes `eslint-plugin-react` and `eslint-config-prettier`)
- `tsconfig`: Shared `tsconfig.json`s used throughout Fedimint UI apps

## Development

From root repo directory:

1. `cd fedimint-ui`
1. `nix develop .#fedimint-ui`
1. `yarn install` (First time only)
1. You can run any of the following commands from `fedimint-ui/` directory

> - `yarn test` - Tests all apps and packages in the project
> - `yarn build` - Build all apps and packages in the project
> - `yarn clean` - Cleans previous build outputs from all apps and packages in the project
> - `yarn format` - Fixes formatting in all apps and packages in the project

Alternatively, you can navigate to a specific app or package within `fedimint-ui/` directory and run it's respective development commands
