# Weekly dev-call agenda: read-only collection

The `Weekly dev-call agenda (read-only)` workflow generates a draft from public
`fedimint/fedimint` issue and pull-request evidence. It runs Mondays at 14:00 UTC
or on manual dispatch with an explicit UTC endpoint. It is not a committed
roadmap, an approval decision, or a wiki publisher.

## Window and reruns

The window is exactly 184 hours (7 days plus 16 hours), half-open:
`start <= activity timestamp < end`. Scheduled runs derive `end` as the most
recent Monday at 14:00 UTC at or before the **original workflow run creation
timestamp**, obtained using the Actions API. Delayed jobs and reruns of the same
run therefore keep the same endpoint rather than using their current start time.
A delay crossing another Monday requires manual dispatch with the intended
endpoint; the workflow cannot recover a missing schedule event's nominal time.

Manual dispatch requires `end` in whole-second UTC form
`YYYY-MM-DDTHH:MM:SSZ`, for example `2026-10-05T14:00:00Z`. Empty, offset,
fractional-second, and malformed endpoints fail rather than silently selecting
the current time. An endpoint is stable across reruns, but current GitHub
observations are not: the report deliberately refreshes current state and
discussion, and records observation times.

The collector can also be run with an already configured read-only `gh` session:

```sh
python3 .github/scripts/weekly-dev-call-agenda.py \
  --end 2026-10-05T14:00:00Z --output-dir agenda-output
```

It uses Python's standard library and `gh`; no model or external summarizer is
invoked. Do not place credentials in the command line, output directory, or docs.

## Evidence and suggestions

The collector paginates the all-state issue/PR inventory. Candidates were created
before `end` and have `updated_at >= start`; there is deliberately **no upper
cutoff on `updated_at`**, so later discussion does not hide earlier activity.
Excluded inventory entries retain timestamps and reasons in the evidence ledger.
Each candidate's available timeline, comments, and PR reviews, review comments,
and commits are paginated before selecting timestamped activity in the window.
Commit author/committer dates alone are not treated as push times.

Included entries get a refreshed current state, labels, milestone, and discussion.
PR evidence also includes current reviews, current-head check runs and statuses,
draft/merge state, and GitHub's mergeability observation. Unknown CI or conflicts
are not a readiness judgment. Source titles and metadata are escaped as data,
not executed as instructions.

The draft separates PR and issue activity and links a date-matched weekly wiki
summary; the existence of that summary link is not verified. Discussion
suggestions are deterministic, restricted to included open items:

- **Week:** labels `bug`, `regression`, `blocker`, or `priority: high`.
- **Month:** a current public milestone.
- **Release:** labels `release` or `backport`.

All suggestions are marked **Suggested—needs maintainer agreement**. No owners,
deadlines, release dates, or maintainer consensus are inferred. Missing public
metadata means clarification is needed, not permission to invent a plan.

## Outputs, failures, and limits

On success, `agenda-output/evidence.json` contains source evidence, window,
observations, pagination/selection ledger, and limitations;
`agenda-output/agenda.md` contains the human-readable draft. Both are uploaded
as `weekly-dev-call-agenda-<run-id>-<attempt>` with 30-day retention.
The draft records the intended separate destination `Dev-call-YYYY-MM-DD.md`;
it does not create that wiki page or edit an existing page.
The job summary includes the complete agenda only when it fits a conservative
900,000-byte budget, including the artifact pointer. Otherwise it links the
complete artifact; it never silently truncates.

The collector fails closed on incomplete pagination, malformed required data,
unexplained in-window updates, changed PR heads during refresh, resource limits,
or API failures. A failed collection emits `failure.json` and no successful
agenda. Artifact upload runs even after failure, without turning the failed
collection into success. Failures before collection starts, or runner
termination, may produce no artifact.

Collection bounds are 4,000 API requests, 1,000 pages per collection, 8 MiB per
page, 256 MiB cumulative response bytes, and 45 minutes; the workflow has a
50-minute job timeout. Rate limits may stop a collection sooner. Verify an actual
scheduled run's resource use and completeness before relying on this operationally.
Do not publish partial output or weaken completeness checks to hide failure.

The evidence is sequential, not an atomic historical snapshot. Deleted or
inaccessible activity, prior edits, force-push history, or activity not reflected
in inventory timestamps cannot be exhaustively recovered. The ledger establishes
the collector's observable selection and pagination, not omniscient historical
coverage.

## Publication gate: BLOCKED

**Automatic wiki delivery is BLOCKED** until an operator approves and provisions
either a durable Tau publisher or a narrowly scoped wiki publisher. This workflow
has only `contents`, `issues`, `pull-requests`, `checks`, and `actions` **read**
permissions, a fixed-repository job guard, SHA-pinned actions, and checkout with
`persist-credentials: false`. Actions read access obtains the original run
timestamp; checks read access retrieves current-head checks. The ephemeral token
is used only for read-only collection. No PAT, bot credential, wiki checkout,
GitHub write permission, or publication step is added.

A future authorized publisher must preserve all manually maintained wiki content,
use the separate dated dev-call archive on `Dev-call.md` linked from `Home.md`,
and avoid overwriting the weekly development summary. Provisioning that publisher,
approving its identity/permissions, and defining idempotent archive updates are
separate operator work, not actions this collector performs. Until then,
maintainers can inspect artifacts and agree on the discussion agenda without any
automatic wiki mutation.
