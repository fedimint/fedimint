---
name: github-actions-dependabot-review
description: >-
  Review Dependabot PRs updating GitHub Actions workflows/actions, with a
  security-focused upstream diff check before commenting.
---

# GitHub Actions Dependabot Review

Use when asked to review Dependabot PRs for GitHub Actions updates.

## Find PRs

```bash
gh auth status
gh pr list -R OWNER/REPO --state open --author app/dependabot \
  --json number,title,headRefName,url --limit 100
```

Target PRs usually have `github_actions` in the branch name or a title like `bump OWNER/ACTION from OLD to NEW`.

## Review each PR

Delegate one subagent per PR. For each PR:

1. Check if a non-bot human already reviewed it:

```bash
gh pr view PR -R OWNER/REPO --json reviews,comments,reviewDecision
```

If yes, stop for that PR.

2. If not reviewed, inspect PR metadata for the action repo, old/new versions, git hashes, and changelog notes:

```bash
gh pr view PR -R OWNER/REPO --json title,body,files,commits,url
gh pr diff PR -R OWNER/REPO
```

3. Clone the upstream action repo into a temp dir, never into the working tree:

```bash
tmp=$(mktemp -d)
git clone https://github.com/OWNER/ACTION "$tmp/action"
cd "$tmp/action"
```

4. Diff old vs new. Prefer Dependabot-listed hashes; otherwise resolve tags locally:

```bash
git rev-parse OLD
git rev-parse NEW
git diff --stat OLD..NEW
git diff OLD..NEW
```

5. Compare the diff to the changelog. Review with a security-critical mindset: secret/token exfiltration, eval/dynamic code, shell injection, new network calls or downloads, dependency/lockfile surprises, token/permission handling, workflow-command injection, and suspicious generated/minified artifacts.

If dependency manifests or lockfiles change (`package-lock.json`, `Cargo.lock`, etc.), review each dependency update similarly. If the dependency diff is too large or infeasible, at least check metadata on the relevant registry (`npm`, `crates.io`, etc.) and verify the new version is at least a week old. Raise anything not clearly safe as a concern in the PR comment.

6. Post a concise PR comment using the current agent's normal attribution prefix. Include old/new hashes, what changed, whether it matches the changelog, risks found or explicitly not found, and a clear `OK to merge` / `not OK to merge` recommendation.

```bash
gh pr comment PR -R OWNER/REPO --body-file COMMENT.md
```

## Final report

Summarize PR link, whether it was already reviewed, whether a comment was posted, and the recommendation.
