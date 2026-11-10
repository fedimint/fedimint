---
name: pr-submissions-checklist
description: Must read before submitting PRs to Fedimint project
---

# PR Submissions Checklist

Use this before creating or updating a PR for the Fedimint project.

## Pre-submit checks

- Verify `just final-lint` passes locally before submitting, to catch easy issues without waiting for CI. This is the fast lint-only subset of `just final-check`, which also runs tests and WASM checks.

## PR description

### Goal

The goal of a change description is to help readers understand all the important aspects of the change without having to deduce them from the code.

Your responsibility goes beyond writing or editing the text itself: ensure a good result.

Read the change itself. If at any point you're missing important information to write a good change description and follow these instructions, request additional information, work or research from whoever requested or prepared the changes (or delegate yourself if no requester is available).

### Structure

Start by understanding the context, severity, importance, and scope of the change.

Keep the length and level of detail of the change description proportionate to these aspects.

Decide how much detail and deliberation are justified. Consider the following dimensions of "more detail vs less detail needed":

* A PR to a public collaborative project vs an internal change to a personal repository.
* Production code changes vs test code.
* Key load-bearing behavior vs minor reversible detail.
* Architectural changes vs implementation details.
* Large scope vs small scope.
* Difficult change vs trivial/obvious change.

When judging scope or size, use logical scope, not the line count. A trivial refactor can generate a large diff without changing actual behavior.

Use the format below as a guide, but adapt it according to your judgment: skip or merge parts that do not apply or are too trivial to be worthwhile on their own, and add parts that you think are needed. Avoid spelling out things that are obvious from the nature of the change or from other information.

Treat the instructions in each section as prompts, not a checklist to answer point by point.

```markdown
### Motivation

{Why are you making this change? How did it come about? Did someone request it? Is it a follow-up to existing work? Is it part of or related to other work already done, happening in parallel or planned for the future?}

{What is the goal and desired result?}

### Context

{Assume the reader is a junior developer or a bystander looking at this change. Do the Motivation and other sections give them enough background to understand the important aspects of this change? You can assume they know what the project is in general, but don't assume they know architectural, design, or implementation details.}

### Summary

{Usually 3–5 sentences or paragraphs. A TL;DR of the Details sections below. You might leave a placeholder and fill it in after writing the details.}

### {Potentially multiple relevant details sections}

{relevant details}
```

Some candidates for "details sections". Use these as a starting point and examples, not a checklist:

* Key changes - pointers to the most important changes if the diff contains a substantial amount of less important changes (mechanical API adjustments, tests). Use type names and file paths.
* Testing - explain how external readers can verify and test the changes themselves when this requires non-obvious instructions or special handling. Do not report what the author or agent ran, list passing checks, or catalog tests as evidence of confidence. The pre-submit checks above still apply.
* Alternatives - if the approach in the change had viable alternatives, list and contrast them.
* Consequences - does this change have important consequences?
* Downsides - does this change have any non-trivial downsides?
* Tradeoffs - did you consider any tradeoffs?
* Benchmark - are performance and resource usage relevant? Did you collect any metrics?
* Behavior - is the behavior of the code in question non-trivial? Would additional explanation of how things worked before and/or how they work now be useful? Sequence diagrams?
* Examples - does the change involve serialization formats, human-readable outputs, syntax changes, etc. that could benefit from an example of how things "look" now (and possibly how they looked before)?
* Screenshots - if the change involves UI, are there any visual artefacts that would make it easier to understand?
* Non-goals - did you choose to avoid any aspects of the change?

### Style

Use concrete, active prose.

Avoid jargon - prefer accessible terms. Assume some readers may need a simple explanation or may be distracted. Keep things simple and lead the reader towards understanding.
Prefer a precise contrast ("the previous code did X; the new code does Y,
which improves Z") over a list of changes or a summary of behavior. For example:

> Before, callers had to configure each endpoint separately. Now one shared
> default applies to all endpoints, so new callers work without duplicated
> configuration; endpoint-specific overrides still take precedence.

Avoid internal details irrelevant to an external reader. Exclude conversations, agent names, review iterations, agent
workflow, and an implementation diary unless one explains a remaining
constraint. Do not include routine validation or a work log.
