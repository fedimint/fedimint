---
name: github-stale-pr-triage
description: >-
  Triage stale GitHub PRs. Use when asked to review old, inactive,
  least-recently-updated, obsolete, or closeable pull requests, comment with a
  recommendation, and close PRs that are clearly no longer useful.
---

# GitHub stale PR triage

Use this when asked to look through old open PRs and decide what should happen with them.

First find the exact PRs under consideration. Usually this means the least recently updated open PRs, filtered by the user's age cutoff:

```bash
gh pr list -R OWNER/REPO --state open --limit 20 \
  --search 'updated:<YYYY-MM-DD sort:updated-asc' \
  --json number,title,author,createdAt,updatedAt,isDraft,url,labels
```

For each PR, one by one:

- Read the PR description, comments, changed files, and diff.
- Check current code and related issues/PRs to see if the work is still needed or was done another way.
- Decide what maintainers should do:
  - close it if it is obsolete, irrelevant, already done, or would need a fresh rewrite;
  - leave it open if it is still useful and looks easy to finish;
  - leave it open with a clear question if the answer is genuinely unclear.
- If possible, delegate each PR to a self-contained sub-agent.

Always write the analysis as a PR comment. Keep it polite and short. Say what you checked, what you concluded, and what the next step should be. If closing, say it can always be reopened if we missed something.

Close when it seems like the PR should be closed:

```bash
gh pr close NUMBER -R OWNER/REPO --comment-file /tmp/comment.md
```

Report back with a short table: PR, decision, action taken, rationale.
