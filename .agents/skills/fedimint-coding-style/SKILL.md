---
name: fedimint-coding-style
description: Use before writing, modifying, or reviewing Rust code in Fedimint.
---

# Fedimint Coding Style

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

## Module and test layout

- Never create inline Rust modules. Use standalone file modules instead,
  including for test modules.
- Write new tests in standalone test files. When modifying existing inline
  tests, extract them into a standalone test file as part of the change.
- Preserve `cfg` conditions, visibility, imports, and behavior when extracting
  an existing module.
- Apply this incrementally: do not bulk-migrate untouched inline tests.

For example, declare a test module in `src/widget.rs`:

```rust
#[cfg(test)]
mod tests;
```

Then put its tests in `src/widget/tests.rs`.
