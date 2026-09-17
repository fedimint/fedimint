---
name: fedimint-development
description: >-
  Use before changing or reviewing Fedimint code, or using the project's build,
  test, lint, formatting, documentation, or development-environment workflows.
---

# Fedimint Development

## Commands

### Build and development

- `just build` — Build the entire workspace.
- `just check` — Run Cargo checks on everything.
- `just test` — Run tests after building.
- `cargo check -q` — Run a quick syntax and type check.
- `just lint` — Run the linters used by the Git pre-commit hook.
- `just clippy` — Run Clippy with warnings treated as errors.
- `just format` — Format Rust and Nix code.

### Testing

- `just test-ci-all` — Run all tests in parallel as CI does.
- `just final-lint` — Run the fast, lint-only subset of pre-PR checks.
- `just final-check` — Run all checks recommended before opening a PR.
- `just check-wasm` — Verify WASM compatibility.

### Development environment

- `just devimint-env` — Start a development federation environment.
- `just devimint-env-pre-dkg` — Start a pre-DKG federation on fixed ports.
- `nix develop` — Enter the Nix development shell.

### Documentation

- `just build-docs` — Build Cargo documentation.
- `just docs` — Build and open the documentation.

## Code quality

- Never use `unwrap()` in non-test code. Use `expect()` with a succinct message
  that explains why the condition cannot fail.
- Use structured logging. Break logging statements across multiple lines for
  readability, and use tracing fields (`field = value`) instead of string
  interpolation.
- Group related parameters into utility structs such as `ConnectionLimits`
  rather than passing many related function parameters.
- Follow existing project patterns and conventions.
- Use meaningful error messages that help with debugging.

## Adding module functionality

1. Implement consensus logic in the `*-server` crate.
2. Add client-side operations in the `*-client` crate.
3. Update shared types in the `*-common` crate.
4. Add integration tests in the `*-tests` crate.
5. Update database migrations when needed.

## After code changes

Always run `just format` after making code changes.

Before creating or updating a pull request, load the
`pr-submissions-checklist` skill for PR description and pre-submit guidance.
Run `just final-lint` to catch easy issues without waiting for CI. For larger or
riskier changes, or when extra confidence is needed, run `just final-check`; it
includes linting and formatting, the full test suite, documentation tests, and
WASM compatibility checks.
