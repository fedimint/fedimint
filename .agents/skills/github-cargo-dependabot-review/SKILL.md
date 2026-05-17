---
name: github-cargo-dependabot-review
description: Review Dependabot PRs updating Rust/Cargo crates with a security-focused crates.io tarball diff before commenting.
---

# GitHub Cargo Dependabot Review

Use when asked to review Dependabot PRs that update Rust dependencies in `Cargo.toml` or `Cargo.lock`.

## Find PRs

```bash
gh auth status
gh pr list -R OWNER/REPO --state open --author app/dependabot \
  --json number,title,headRefName,url --limit 100
```

Target PRs usually have `cargo` in the branch name or titles like `bump CRATE from OLD to NEW`.

## Review each PR

Delegate one subagent per PR. For each PR:

1. First check whether a whole-PR Cargo Dependabot review was already done by the current GitHub user or one of their bot accounts:

```bash
me=$(gh api user --jq .login)
gh pr view PR -R OWNER/REPO --json reviews,comments,reviewDecision
```

Inspect both review bodies and issue comments. Treat `$me` and any bot logins explicitly named by the user as self. If a self-authored comment/review already covers the whole PR, says it downloaded or diffed the crates.io tarballs, and gives an overall `OK to merge` / `not OK to merge` recommendation, stop for that PR and report that it was already reviewed. Do not repeat the work just to refresh wording. Dependency-specific comments for only one crate do not count as whole-PR reviews; handle those in the multi-dependency coordination step.

2. If no self-authored Cargo Dependabot review exists, inspect PR metadata, Dependabot notes, changed manifests, and lockfile diff:

```bash
gh pr view PR -R OWNER/REPO --json title,body,files,commits,url
review_tmp="${TMPDIR:-/tmp}/pr-review"
rm -rf "$review_tmp" && mkdir -p "$review_tmp"
gh pr diff PR -R OWNER/REPO --patch | tee "$review_tmp/pr.patch"
```

Extract every crate whose version changed. Prefer explicit Dependabot notes from the PR body, then confirm against `Cargo.lock` and `Cargo.toml` diffs. Separate direct dependency bumps from transitive lockfile-only changes.

3. Decide whether the PR is small enough for one agent. If it updates multiple dependency units, do not review them all in one context. Treat each direct crate bump, Dependabot group member, or lockfile-only crate update with its attributable transitive changes as a separate dependency review unit.

For multi-dependency PRs, the PR-level subagent is a coordinator:

- First inspect existing PR comments and reviews for dependency-specific reviews by the current user or explicitly named bot accounts. A dependency review comment should be considered complete when it names the crate and old/new versions, says it downloaded or diffed the crates.io tarballs, and has a per-dependency `OK to merge` / `not OK to merge` recommendation.
- Skip dependency units that already have such a self-authored review comment. Do not redo those reviews just to make the wording uniform.
- For every remaining dependency unit, delegate one fresh sub-sub-agent. Give it the PR URL, crate name, old/new versions, relevant `Cargo.toml` / `Cargo.lock` diff snippets, any suspected transitive changes belonging to that unit, and these single-dependency review instructions. Tell it to review only that unit and to post its own dependency-specific PR comment.
- Each sub-sub-agent comment must start with a stable marker like `Cargo dependency review: CRATE OLD_VERSION to NEW_VERSION` so later coordinators can detect it.
- After all dependency units have dependency-specific comments, the PR-level subagent posts one short roll-up comment. Recommend merging the whole PR only if every dependency unit was reviewed and every per-dependency recommendation is `OK to merge`. If any unit is unreviewed or not OK, the roll-up must say `not OK to merge` and list why.

For a single dependency unit, continue below directly.

4. For the dependency review unit, download both published crate tarballs from crates.io into a temp directory, never into the working tree:

```bash
tmp=$(mktemp -d)
crate=CRATE
old=OLD_VERSION
new=NEW_VERSION

for version in "$old" "$new"; do
  curl -fsSL "https://crates.io/api/v1/crates/$crate/$version" \
    -o "$tmp/$crate-$version.meta.json"
  curl -fsSL "https://static.crates.io/crates/$crate/$crate-$version.crate" \
    -o "$tmp/$crate-$version.crate"
  mkdir -p "$tmp/unpacked"
  tar -xzf "$tmp/$crate-$version.crate" -C "$tmp/unpacked"
done
```

5. Verify crates.io metadata before trusting the tarballs:

```bash
jq '{name: .version.crate, num: .version.num, created_at: .version.created_at, yanked: .version.yanked, license: .version.license, repository: .version.repository, checksum: .version.checksum}' \
  "$tmp/$crate-$old.meta.json" "$tmp/$crate-$new.meta.json"
sha256sum "$tmp/$crate-$old.crate" "$tmp/$crate-$new.crate"
jq -r '.version.checksum' "$tmp/$crate-$old.meta.json" "$tmp/$crate-$new.meta.json"
```

The SHA-256 values from `sha256sum` must match the metadata checksums. Flag yanked versions, missing or changed license, repository changes, newly published versions younger than one week, and crates with suspiciously low maturity for critical code.

6. Diff the published tarballs, starting broad and then reading changed files:

```bash
diff -ruN --brief \
  -x .cargo-ok \
  -x .cargo_vcs_info.json \
  -x Cargo.toml \
  "$tmp/unpacked/$crate-$old" \
  "$tmp/unpacked/$crate-$new"

diff -ruN \
  -x .cargo-ok \
  -x .cargo_vcs_info.json \
  -x Cargo.toml \
  "$tmp/unpacked/$crate-$old" \
  "$tmp/unpacked/$crate-$new" \
  | tee "$tmp/$crate-$old..$new.diff"
```

`Cargo.toml` is rewritten by `cargo publish`; compare `Cargo.toml.orig` instead when present. Read the full diff for changed Rust, build, generated, shell, and configuration files. If the diff is huge, prioritize security-sensitive files and state exactly what was not reviewed.

7. Compare the tarball diff to changelog and release notes. Use metadata repository URLs, PR body links, and crates.io links. If the upstream repo is available, verify the tarball source mapping:

```bash
repo=$(jq -r '.version.repository // empty' "$tmp/$crate-$new.meta.json")
git clone --filter=blob:none "$repo" "$tmp/upstream"
cat "$tmp/unpacked/$crate-$new/.cargo_vcs_info.json"
```

When `.cargo_vcs_info.json` exists, confirm its `git.sha1` exists upstream and corresponds to a plausible version tag such as `vNEW_VERSION`, `NEW_VERSION`, `CRATE-vNEW_VERSION`, or `CRATE-NEW_VERSION`. Record any mismatch. This check is especially important if the published tarball contains changes not explained by the changelog.

8. Review with a security-critical mindset. Look for:

- New or changed `build.rs`, proc-macro code, `links` metadata, FFI, or native library probing.
- New `unsafe`, `extern`, pointer manipulation, `transmute`, or unchecked indexing in code that handles untrusted input.
- New process spawning, shell invocation, filesystem writes outside normal build output, environment-variable harvesting, network access, downloads, telemetry, or credential/token handling.
- New dependencies, default features, optional features enabled by the bump, or feature unification surprises.
- Binary blobs, generated code, minified JavaScript/WebAssembly, vendored C/C++/assembly, or large encoded string constants.
- Serialization, parsing, cryptography, consensus, or money-handling behavior changes relevant to the repository.
- License changes, repository ownership changes, yanked releases, or maintainer/release anomalies.

9. Inspect dependency consequences in the target repository. Prefer a temp clone or temp worktree, not the user's working tree:

```bash
repo_tmp=$(mktemp -d)
gh repo clone OWNER/REPO "$repo_tmp/repo"
cd "$repo_tmp/repo"
gh pr checkout PR
cargo tree -i CRATE
```

If many transitive crates changed, do not ignore them. At minimum, list them, check crates.io metadata for new/yanked/young versions, and deeply review any new build script, proc macro, FFI crate, crypto crate, networking crate, or obscure crate. If that is infeasible, mark the PR `not OK to merge` until the unreviewed risky changes are inspected.

10. Decide and comment. A safe dependency-specific comment is concise but evidence-backed. Include:

- PR link and dependency unit reviewed.
- Crate old/new versions, crates.io checksums or short hashes, release age, yanked status, and whether tarball diff matches release notes.
- Security-relevant changes found, or explicitly say none were found in reviewed areas.
- Transitive dependency changes attributable to this unit and how much review they received.
- Anything skipped or too large to inspect.
- Clear per-dependency recommendation: `OK to merge` or `not OK to merge`.

```bash
gh pr comment PR -R OWNER/REPO --body-file COMMENT.md
```

## Dependency comment template

```markdown
Cargo dependency review: `CRATE` OLD_VERSION to NEW_VERSION

Crate reviewed:
- `CRATE` OLD_VERSION to NEW_VERSION: crates.io checksums matched metadata; NEW_VERSION was published DATE; not yanked.

What I checked:
- Downloaded and diffed the published crates.io tarballs for OLD_VERSION and NEW_VERSION.
- Compared the code diff with the Dependabot/release-note summary.
- Checked `Cargo.toml.orig`, feature/dependency changes, build scripts, proc-macro/FFI/unsafe surfaces, and suspicious network/process/filesystem behavior.
- Checked attributable transitive dependency changes: ...

Findings:
- ...

Recommendation for this dependency: OK to merge / not OK to merge.
```

## Roll-up comment template

Use only after every dependency unit in a multi-dependency PR has a dependency-specific review comment.

```markdown
Cargo Dependabot roll-up review

Dependency reviews:
- `CRATE_A` OLD_VERSION to NEW_VERSION: OK to merge, reviewed in COMMENT_URL
- `CRATE_B` OLD_VERSION to NEW_VERSION: OK to merge, reviewed in COMMENT_URL

All dependency units in this PR have dependency-specific reviews, and all are OK.

Recommendation: OK to merge.
```

If any dependency unit is missing a review or has a `not OK to merge` recommendation, do not use the positive roll-up. Post a roll-up saying `not OK to merge` and list the missing or blocked units.

## Final report

Summarize PR link, whether it was already reviewed, whether dependency units were delegated or reviewed directly, whether comments were posted, crates reviewed, any risky or skipped areas, and the recommendation.
