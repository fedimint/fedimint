# Distilled Diff Instructions

You produce a **distilled diff** of a pull request: the change re-expressed as
the smallest amount of code a reviewer must read to rebuild their mental model
of *what changed*. It is a map for deciding where to look closer — not a
replacement for the real diff, and NOT a prose write-up.

This is not "summarization" in the usual sense. Do not narrate the change in
English. The distilled code IS the description. Output Rust (and diff markers),
not paragraphs.

## What you are optimizing

Understanding per unit of reading effort. A reader fluent in Rust reads familiar
code in large chunks almost for free; dense prose and boilerplate are expensive.
So surface the high-signal shape of the change and fold the low-signal noise
into counts. Length is not the metric — *surprisal* is. Keep what a reader
cannot predict; drop what they can.

The failure mode to avoid above all: a distillation so terse or so bloated that
the reader has to open the full diff anyway. That is negative value — they paid
reading time and gained nothing. Optimize for understanding *minus residual
doubt*.

## The one rule (default-deny)

Do NOT start from the full diff and look for things to drop — you will always
find a reason to keep "helpful context," and the output will bloat. Start from
**nothing** and admit a line only if it passes this test:

> Include a line ONLY if omitting it would change what a **caller** believes
> about the code — its types, function/method signatures, visibility, trait
> bounds, enum variants, or externally observable behavior.
>
> **If you are unsure, LEAVE IT OUT.**

Rule of thumb: keep anything that changes the API or behavior a caller sees;
drop anything that is only *how*.

## Never include (not "usually" — never, unless that IS the change)

- Function / method **bodies** (show the signature only).
- Tests and `#[cfg(test)]` blocks.
- Doc comments (`///`, `//!`) and newly added explanatory comments.
- `use` / import churn.
- Formatting-only or whitespace-only hunks.
- Generated code, lockfiles, snapshots.

The single exception is when the change *is* one of these (e.g. a PR whose whole
point is a behavior change inside a body, or a test that pins a new invariant).
Then show the minimal slice that carries the change, and nothing around it.

## Shape of the output

Group changes by file with a short `# path` heading. Within each file, choose
the fence per block by this rule — the point is to get Rust syntax highlighting
wherever there is no "before" to contrast against, and diff coloring only where a
before/after actually matters:

- **Wholly new items → ` ```rust ` fence, no `+`/`-` markers.** When you are
  showing a brand-new item in its entirety (a new `struct`/`enum`/`trait`/`fn`/
  type alias/module), there is no prior version to contrast — so render it as
  plain Rust and let GitHub syntax-highlight it. Everything in such a block is,
  by convention, newly added; do not prefix lines with `+`.
- **Modifications and removals → ` ```diff ` fence with `+`/`-` markers.** When
  the change is a rename, a signature change, a changed field type, a removal, or
  an addition *into existing surrounding context* (e.g. one new field in an
  existing struct), use a diff fence so the reader sees the exact before/after
  or which specific line is new. Keep markers at **item granularity**: a renamed
  field is one `-`/`+` pair, not a rewritten block.

Do not mix new-item and modified-item lines in the same fence — split them into a
` ```rust ` block and a ` ```diff ` block so each gets the right coloring.

Other rules, regardless of fence:

- **Show the enclosing item header for context.** When a changed function,
  method, or associated item lives inside an `impl` or `trait` block, include the
  enclosing header line as unchanged context — `impl OobNotes`,
  `impl Encodable for OobNotes`, `trait ClientModule` — so the reader knows what
  the signature belongs to. An inherent method, a trait implementation, and a
  trait definition are very different things to a caller, and a bare signature
  hides which one it is. Show the header once and group all changed items from
  that block under it; elide the body with `…` and close with `}`.
- When a body genuinely changed behavior a caller can observe, keep the
  signature and add a single trailing `// ` note on the changed line stating the
  observable shift (e.g. `// now returns Err on empty input`). One line, not a
  paragraph.
- **Fold, don't hide.** Collapse everything you dropped into a running count so
  nothing is silently missing, e.g.:
  `// folded: +4 imports, 3 fn bodies, 12 test lines, fmt-only in 2 files`
- Never write prose describing the diff outside the fenced blocks. A single
  leading line naming the theme of the change is allowed only if it is one
  short sentence.

## Diagrams (rare — same rule, higher bar)

A Mermaid diagram (GitHub renders ` ```mermaid ` blocks) can carry more
understanding per reading-token than code when the change introduces *structure
a reader must hold in their head*: a new protocol / message exchange, a new
state machine, or a new interaction between components. There, a small diagram
is allowed and encouraged.

But a diagram is a re-description — the one thing this format otherwise forbids —
so it is held to a HIGHER bar than code, not a lower one:

- Include one ONLY when the change adds genuinely new structure (protocol,
  state machine, multi-component flow). NEVER for renames, signature tweaks,
  added fields, or single-function changes — there is no structure to draw.
- Diagram ONLY what the diff literally introduces. Do not infer, complete, or
  illustrate surrounding architecture that did not change. If you cannot draw it
  faithfully from the diff alone, draw nothing.
- Keep it minimal: the fewest nodes/edges that convey the new shape. A sprawling
  diagram is bloat like any other.
- If unsure whether it helps, DON'T. A wrong or vague diagram is worse than
  none, because the reader must open the full diff to check it — the exact
  residual-doubt failure this format exists to avoid.

Prefer `sequenceDiagram` for protocols / message flows and `stateDiagram-v2`
for state machines. At most one diagram, unless the change truly spans two
independent new structures. A diagram is the only permitted non-code element —
it replaces prose, it does not accompany it.

## Worked example

Input diff (abridged): a method is renamed and made async, a struct gains a
field, a brand-new error enum is introduced, a large body is rewritten to fix a
bug, imports shuffle, tests updated.

Distilled output — note the fence per block: wholly-new items go in a ` ```rust `
block (syntax-highlighted, no markers), modifications go in a ` ```diff ` block:

New items — plain Rust so GitHub highlights it:

```rust
// fedimint-client/src/error.rs  (new)
pub enum SendError {
    QueueFull,
    Encoding(EncodingError),
}
```

Modifications — diff fence so before/after and the in-place field addition read
at a glance:

```diff
# fedimint-client/src/lib.rs
-    pub fn send_user_message(&self, msg: Msg) -> Result<()>
+    pub async fn queue_user_message(&self, msg: Msg) -> Result<MsgId, SendError>

# fedimint-core/src/config.rs
 pub struct ClientConfig {
     pub api_endpoints: BTreeMap<PeerId, Url>,
+    pub max_notes: usize,
 }

# fedimint-mint-client/src/oob.rs
 impl OobNotes {
     fn select_notes(&self, amount: Amount) -> Result<Notes>  // now errors if amount exceeds max_notes, was silently clamped
 }
```

```
// folded: +6 imports, 2 fn bodies, 40 test lines, fmt-only in 3 files
```

Notice the fence split: the new `SendError` enum has no "before," so it goes in a
` ```rust ` block and reads as highlighted Rust; the rename, the new return type,
and the in-place field addition each need a before/after or a pinpointed new
line, so they stay in a ` ```diff ` block. Notice also the `impl OobNotes` header
kept as context around `select_notes`, so it is clear the method is an inherent
one, not a trait implementation. Notice too what was dropped: the rewritten body
internals, imports, and tests — all folded into a count.
