---
name: github-stale-issue-triage
description: >-
  Triage stale GitHub issues. Use when asked to review old, inactive,
  least-recently-updated, obsolete, or closeable issues, comment with a
  recommendation, and close issues that are clearly no longer useful.
---

# GitHub stale issue triage

Use this when asked to review old open issues and decide what to do with them.

First, identify the issues under consideration. Usually these are the least recently updated open issues, filtered by the user's age cutoff:

```bash
gh issue list -R OWNER/REPO --state open --limit 20 \
  --search 'updated:<YYYY-MM-DD sort:updated-asc' \
  --json number,title,author,createdAt,updatedAt,url,labels
```

Review each issue in turn:

- Read the issue description, comments, reproduction steps, and linked work.
- Check current code and related issues/PRs to see whether the problem or request is still relevant or was resolved another way. A linked PR alone does not prove resolution; check what landed and whether it addresses the issue.
- Decide what maintainers should do:
  - close it if evidence shows it is resolved, obsolete, out of scope, or a duplicate with a useful canonical issue;
  - leave it open if it still describes a valid unresolved problem or useful request, regardless of how hard it would be to fix;
  - leave it open with a clear question if the answer is genuinely unclear.
- Age or inactivity alone is not a reason to close an issue.
- If possible, delegate each issue to a self-contained sub-agent.

Write the analysis as a short, polite issue comment. Say what you checked, what you concluded, and what the next step should be. Link supporting resolutions or the canonical issue when relevant. If closing, say it can always be reopened if we missed something.

Post the comment, then close only when the evidence supports closure:

```bash
gh issue comment NUMBER -R OWNER/REPO --body-file /tmp/comment.md
gh issue close NUMBER -R OWNER/REPO --reason completed
```

Use `--reason completed` for resolved issues and `--reason 'not planned'` for duplicates, obsolete issues, or requests outside the project's scope. Omit the close command when leaving an issue open.

Report back with a short table: issue, decision, action taken, and rationale.
