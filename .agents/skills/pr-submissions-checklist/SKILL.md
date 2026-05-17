---
name: pr-submissions-checklist
description: Must read before submitting PRs to Fedimint project
---

# PR Submissions Checklist

Use this before creating or updating a PR for the Fedimint project.

## Pre-submit checks

- Verify `just final-lint` passes locally before submitting, to catch easy issues without waiting for CI. This is the fast lint-only subset of `just final-check`, which also runs tests and WASM checks.

## PR description

A PR description should typically use these sections:

### Summary

Start with a single paragraph summarizing the change.

### Details

Explain why the change is being done, how its goals are achieved, and the most important design decisions.

### Reviewing

Optionally explain which aspects reviewers should think through carefully, be opinionated about, or just be aware of.

### Testing

Optionally explain how reviewers can gain confidence that the change is solid. Mention automated tests added, existing tests that cover the functionality, or manual testing instructions.
