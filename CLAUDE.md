# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Fedimint is a modular framework for building federated financial applications. It provides a trust-minimized, censorship-resistant, and private alternative to centralized applications. The core implementation focuses on a federated Chaumian e-cash mint that's natively compatible with Bitcoin and the Lightning Network.

## Essential Commands

### Build and Development
- `just build` - Build the entire workspace
- `just check` - Run cargo check on everything  
- `just test` - Run tests (builds first)
- `cargo check -q` - Quick syntax/type checking
- `just lint` - Run linters (git pre-commit hook)
- `just clippy` - Run clippy with warnings as errors
- `just format` - Format code with rustfmt and nixfmt

### Testing
- `just test-ci-all` - Run all tests in parallel like CI
- `just final-check` - All checks recommended before opening a PR
- `just check-wasm` - Verify WASM compatibility

### Development Environment  
- `just devimint-env` - Spawn development federation environment
- `just devimint-env-pre-dkg` - Start pre-DKG federation on fixed ports
- `nix develop` - Enter Nix development shell

### Documentation
- `just build-docs` - Build cargo doc documentation
- `just docs` - Build and open documentation

## Architecture Overview

### Core Components
- **fedimint-core** - Core framework, types, and utilities shared between client/server
- **fedimint-server** - Federation consensus logic using AlephBFT
- **fedimint-client** - Client library for interacting with federations
- **modules/** - Pluggable modules (mint, wallet, lightning, meta)
- **gateway/** - Lightning gateway for payment routing

### Module Structure Pattern
Each module follows a three-crate pattern:
```
fedimint-<module>-common/     # Shared types and config
fedimint-<module>-client/     # Client-side functionality  
fedimint-<module>-server/     # Server-side consensus logic
```

### Key Modules
- **Mint Module** (`fedimint-mint-*`) - Chaumian e-cash implementation
- **Wallet Module** (`fedimint-wallet-*`) - Bitcoin on-chain functionality
- **Lightning Module** (`fedimint-ln-*`, `fedimint-lnv2-*`) - Lightning Network integration
- **Meta Module** (`fedimint-meta-*`) - Federation metadata management

### Entry Points
- `fedimintd/src/bin/main.rs` - Federation node daemon
- `fedimint-cli/src/main.rs` - Command-line client interface
- `gateway/fedimint-gateway-server/src/bin/main.rs` - Lightning gateway

## Development Patterns

### Consensus Architecture
- Byzantine fault-tolerant consensus using AlephBFT
- Epoch-based transaction processing
- Module-specific consensus contributions
- Client operations driven by async state machines

### Key Design Patterns
- **Extensible Module System** - Modules implement `ServerModule` and `ClientModule` traits
- **Type-Safe Encoding** - Custom `Encodable`/`Decodable` traits with module registries
- **Operation-Based Client API** - Long-running operations with `OperationId` tracking
- **Database Abstraction** - Key-value store with module-specific namespacing

### Testing Strategy
- Integration tests using `devimint` development environment
- Module-specific test suites in `fedimint-*-tests` crates
- Database migration testing with snapshot validation
- WASM compatibility verification
- Real service testing against bitcoind/Lightning nodes

### Code Organization
- Workspace with 78+ member crates
- Nix-based reproducible development environment
- `just` for build automation and common tasks
- Multi-process development using `mprocs`
- Extensive CI pipeline with compatibility testing

### Code Quality Standards
- **Never use `unwrap()` in non-test code** - Always use `expect()` with a succinct message explaining why the condition cannot fail
- **Use structured logging** - Break logging statements into multiple lines for readability and use tracing's structured logging (field = value) instead of string interpolation
- **Group related parameters** - When passing many related parameters, create utility structs (like `ConnectionLimits`) to reduce function parameter count and improve readability
- Follow existing patterns and conventions in the codebase
- Use meaningful error messages that help with debugging

## Common Workflows

### Adding New Module Functionality
1. Implement consensus logic in `*-server` crate
2. Add client-side operations in `*-client` crate  
3. Update shared types in `*-common` crate
4. Add integration tests in `*-tests` crate
5. Update database migrations if needed

### Before Opening a PR
Run `just final-check` which includes:
- Linting and formatting
- Full test suite
- Documentation tests
- WASM compatibility check
