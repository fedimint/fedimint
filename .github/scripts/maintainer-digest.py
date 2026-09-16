#!/usr/bin/env python3
"""Collect and render a read-only Fedimint maintainer triage digest."""

from __future__ import annotations

import argparse
import html
import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path


SCHEMA_VERSION = 1
NEW_ISSUE_DAYS = 7
STALE_READY_PR_DAYS = 14
STALE_DRAFT_DAYS = 30
OLD_UNTRIAGED_ISSUE_DAYS = 90
STALE_ISSUE_DAYS = 365
RECENT_FAILED_RUN_DAYS = 14

FAILED_CHECK_STATES = {
    "ACTION_REQUIRED",
    "ERROR",
    "FAILURE",
    "STALE",
    "STARTUP_FAILURE",
    "TIMED_OUT",
}
PENDING_CHECK_STATES = {"EXPECTED", "PENDING", "QUEUED", "IN_PROGRESS", "WAITING"}


def parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def age_days(now: datetime, value: str) -> int:
    return max(0, int((now - parse_time(value)).total_seconds() // 86400))


def label_names(item: dict) -> list[str]:
    return sorted(
        label.get("name", "") for label in item.get("labels") or [] if label.get("name")
    )


def author_login(item: dict) -> str:
    return (item.get("author") or {}).get("login") or "unknown"


def run_gh_json(arguments: list[str]) -> list[dict]:
    process = subprocess.run(
        ["gh", *arguments],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    value = json.loads(process.stdout)
    if not isinstance(value, list):
        raise ValueError(f"Expected a JSON list from gh {' '.join(arguments)}")
    return value


def collect_live(repo: str) -> tuple[list[dict], list[dict], list[dict]]:
    prs = run_gh_json(
        [
            "pr",
            "list",
            "--repo",
            repo,
            "--state",
            "open",
            "--limit",
            "200",
            "--json",
            (
                "number,title,author,createdAt,updatedAt,isDraft,reviewDecision,"
                "mergeStateStatus,statusCheckRollup,labels"
            ),
        ]
    )
    issues = run_gh_json(
        [
            "issue",
            "list",
            "--repo",
            repo,
            "--state",
            "open",
            "--limit",
            "1000",
            "--json",
            "number,title,author,createdAt,updatedAt,labels,assignees",
        ]
    )
    failed_runs = run_gh_json(
        [
            "run",
            "list",
            "--repo",
            repo,
            "--status",
            "failure",
            "--limit",
            "100",
            "--json",
            (
                "databaseId,workflowName,displayTitle,event,headBranch,headSha,"
                "createdAt,updatedAt,conclusion"
            ),
        ]
    )
    return prs, issues, failed_runs


def collect_fixtures(directory: Path) -> tuple[list[dict], list[dict], list[dict]]:
    return tuple(
        json.loads((directory / name).read_text(encoding="utf-8"))
        for name in ("prs.json", "issues.json", "runs.json")
    )


def check_states(pr: dict) -> tuple[list[str], list[str]]:
    failing = []
    pending = []
    for check in pr.get("statusCheckRollup") or []:
        name = check.get("name") or check.get("context") or "unnamed check"
        conclusion = str(check.get("conclusion") or "").upper()
        status = str(check.get("status") or "").upper()
        state = str(check.get("state") or "").upper()
        if conclusion in FAILED_CHECK_STATES or state in FAILED_CHECK_STATES:
            failing.append(name)
        elif status in PENDING_CHECK_STATES or state in PENDING_CHECK_STATES:
            pending.append(name)
    return sorted(set(failing)), sorted(set(pending))


def pr_record(repo: str, pr: dict, now: datetime) -> dict:
    failing, pending = check_states(pr)
    return {
        "number": pr["number"],
        "title": pr.get("title") or "",
        "url": f"https://github.com/{repo}/pull/{pr['number']}",
        "author": author_login(pr),
        "created_at": pr["createdAt"],
        "updated_at": pr["updatedAt"],
        "age_days": age_days(now, pr["createdAt"]),
        "days_since_update": age_days(now, pr["updatedAt"]),
        "is_draft": bool(pr.get("isDraft")),
        "review_decision": pr.get("reviewDecision") or "REVIEW_REQUIRED",
        "merge_state": pr.get("mergeStateStatus") or "UNKNOWN",
        "labels": label_names(pr),
        "failing_checks": failing,
        "pending_checks": pending,
    }


def issue_record(repo: str, issue: dict, now: datetime) -> dict:
    return {
        "number": issue["number"],
        "title": issue.get("title") or "",
        "url": f"https://github.com/{repo}/issues/{issue['number']}",
        "author": author_login(issue),
        "created_at": issue["createdAt"],
        "updated_at": issue["updatedAt"],
        "age_days": age_days(now, issue["createdAt"]),
        "days_since_update": age_days(now, issue["updatedAt"]),
        "labels": label_names(issue),
        "assignees": sorted(
            assignee.get("login", "")
            for assignee in issue.get("assignees") or []
            if assignee.get("login")
        ),
    }


def failed_run_record(repo: str, run: dict, now: datetime) -> dict:
    run_id = run["databaseId"]
    return {
        "run_id": run_id,
        "url": f"https://github.com/{repo}/actions/runs/{run_id}",
        "workflow": run.get("workflowName") or "unknown workflow",
        "title": run.get("displayTitle") or "",
        "event": run.get("event") or "",
        "head_branch": run.get("headBranch") or "",
        "head_sha": run.get("headSha") or "",
        "created_at": run["createdAt"],
        "days_since_created": age_days(now, run["createdAt"]),
        "conclusion": run.get("conclusion") or "failure",
    }


def build_state(
    repo: str,
    prs: list[dict],
    issues: list[dict],
    failed_runs: list[dict],
    now: datetime,
) -> dict:
    normalized_prs = [pr_record(repo, pr, now) for pr in prs]
    normalized_issues = [issue_record(repo, issue, now) for issue in issues]
    normalized_runs = [failed_run_record(repo, run, now) for run in failed_runs]

    ready_needing_review = [
        pr
        for pr in normalized_prs
        if not pr["is_draft"] and pr["review_decision"] != "APPROVED"
    ]
    stale_ready = [
        pr
        for pr in ready_needing_review
        if pr["days_since_update"] >= STALE_READY_PR_DAYS
    ]
    stale_drafts = [
        pr
        for pr in normalized_prs
        if pr["is_draft"] and pr["days_since_update"] >= STALE_DRAFT_DAYS
    ]
    failing_ci = [pr for pr in normalized_prs if pr["failing_checks"]]
    pending_ci = [pr for pr in normalized_prs if pr["pending_checks"]]
    merge_conflicts = [
        pr for pr in normalized_prs if pr["merge_state"] in {"CONFLICTING", "DIRTY"}
    ]
    needs_rebase = [pr for pr in normalized_prs if pr["merge_state"] == "BEHIND"]

    def is_dependency(pr: dict) -> bool:
        lowered_labels = {label.lower() for label in pr["labels"]}
        title = pr["title"].lower()
        return (
            pr["author"].lower() in {"app/dependabot", "dependabot[bot]"}
            or bool(lowered_labels & {"dependencies", "github_actions", "nix", "rust"})
            or "flake.lock update" in title
        )

    dependency_prs = [pr for pr in normalized_prs if is_dependency(pr)]
    backports = [
        pr
        for pr in normalized_prs
        if pr["title"].lower().startswith("[backport")
        or any(label.lower().startswith("backport") for label in pr["labels"])
    ]
    releases = [
        pr
        for pr in normalized_prs
        if re.search(
            r"\b(release|version bump|bump version)\b", pr["title"], re.IGNORECASE
        )
    ]

    new_unlabeled = [
        issue
        for issue in normalized_issues
        if not issue["labels"] and issue["age_days"] <= NEW_ISSUE_DAYS
    ]
    old_unlabeled_unassigned = [
        issue
        for issue in normalized_issues
        if not issue["labels"]
        and not issue["assignees"]
        and issue["days_since_update"] >= OLD_UNTRIAGED_ISSUE_DAYS
    ]
    stale_issues = [
        issue
        for issue in normalized_issues
        if issue["days_since_update"] >= STALE_ISSUE_DAYS
    ]
    ci_flaky_issues = [
        issue
        for issue in normalized_issues
        if any(
            label.lower() in {"ci", "flaky test", "testing"}
            for label in issue["labels"]
        )
        or re.search(r"\b(ci|flaky|flake)\b", issue["title"], re.IGNORECASE)
    ]
    recent_failed_runs = [
        run
        for run in normalized_runs
        if run["days_since_created"] <= RECENT_FAILED_RUN_DAYS
        and (
            run["event"] in {"merge_group", "schedule", "workflow_dispatch"}
            or (run["event"] == "push" and run["head_branch"] in {"master", "main"})
            or run["workflow"] == "Backport merged pull request"
        )
    ]

    def oldest_first(item: dict) -> tuple[int, int]:
        return (-item.get("days_since_update", 0), item.get("number", 0))

    pr_categories = {
        "ready_needing_review": sorted(ready_needing_review, key=oldest_first),
        "stale_ready": sorted(stale_ready, key=oldest_first),
        "stale_drafts": sorted(stale_drafts, key=oldest_first),
        "failing_ci": sorted(failing_ci, key=oldest_first),
        "pending_ci": sorted(pending_ci, key=oldest_first),
        "merge_conflicts": sorted(merge_conflicts, key=oldest_first),
        "needs_rebase": sorted(needs_rebase, key=oldest_first),
        "dependencies": sorted(dependency_prs, key=oldest_first),
        "backports": sorted(backports, key=oldest_first),
        "releases": sorted(releases, key=oldest_first),
    }
    issue_categories = {
        "new_unlabeled": sorted(new_unlabeled, key=oldest_first),
        "old_unlabeled_unassigned": sorted(old_unlabeled_unassigned, key=oldest_first),
        "stale": sorted(stale_issues, key=oldest_first),
        "ci_flaky": sorted(ci_flaky_issues, key=oldest_first),
    }

    return {
        "schema_version": SCHEMA_VERSION,
        "repository": repo,
        "generated_at": now.isoformat().replace("+00:00", "Z"),
        "read_only": True,
        "thresholds_days": {
            "new_issue": NEW_ISSUE_DAYS,
            "stale_ready_pr": STALE_READY_PR_DAYS,
            "stale_draft": STALE_DRAFT_DAYS,
            "old_untriaged_issue": OLD_UNTRIAGED_ISSUE_DAYS,
            "stale_issue": STALE_ISSUE_DAYS,
            "recent_failed_run": RECENT_FAILED_RUN_DAYS,
        },
        "source_counts": {
            "open_prs": len(normalized_prs),
            "open_issues": len(normalized_issues),
            "failing_runs_considered": len(normalized_runs),
        },
        "category_counts": {
            **{f"prs.{name}": len(items) for name, items in pr_categories.items()},
            **{
                f"issues.{name}": len(items) for name, items in issue_categories.items()
            },
            "ci.recent_failed_runs": len(recent_failed_runs),
        },
        "pull_requests": pr_categories,
        "issues": issue_categories,
        "ci": {
            "recent_failed_runs": sorted(
                recent_failed_runs,
                key=lambda item: (
                    item["days_since_created"],
                    item["workflow"],
                    item["run_id"],
                ),
            )
        },
    }


def markdown_text(value: str) -> str:
    compact = " ".join(value.replace("\r", " ").replace("\n", " ").split())
    escaped = html.escape(compact, quote=False)
    escaped = re.sub(r"(?i)\b(https?)://", r"\1&#58;//", escaped)
    return re.sub(r"([\\`*_[\]{}])", r"\\\1", escaped)


def render_numbered_items(items: list[dict], kind: str, limit: int = 10) -> list[str]:
    if not items:
        return ["- None."]
    lines = []
    for item in items[:limit]:
        title = markdown_text(item["title"])
        if kind == "pr":
            details = [f"updated {item['days_since_update']}d ago"]
            if item.get("review_decision"):
                details.append(item["review_decision"].lower().replace("_", " "))
            if item.get("failing_checks"):
                details.append(
                    "failing: " + ", ".join(map(markdown_text, item["failing_checks"]))
                )
        else:
            details = [f"updated {item['days_since_update']}d ago"]
            if item.get("labels"):
                details.append(
                    "labels: " + ", ".join(map(markdown_text, item["labels"]))
                )
        lines.append(
            f"- [#{item['number']} — {title}]({item['url']}) ({'; '.join(details)})"
        )
    if len(items) > limit:
        lines.append(f"- …and {len(items) - limit} more in the attached state JSON.")
    return lines


def render_run_items(items: list[dict], limit: int = 10) -> list[str]:
    if not items:
        return ["- None."]
    lines = []
    for item in items[:limit]:
        workflow = markdown_text(item["workflow"])
        title = markdown_text(item["title"])
        lines.append(
            f"- [{workflow}: {title}]({item['url']}) "
            f"({item['event']}; {item['days_since_created']}d ago)"
        )
    if len(items) > limit:
        lines.append(f"- …and {len(items) - limit} more in the attached state JSON.")
    return lines


def render_markdown(state: dict) -> str:
    prs = state["pull_requests"]
    issues = state["issues"]
    runs = state["ci"]["recent_failed_runs"]
    counts = state["source_counts"]

    lines = [
        "# Fedimint maintainer digest",
        "",
        f"Generated: {state['generated_at']}. Read-only advisory output.",
        "",
        "## Snapshot",
        "",
        f"- Open PRs: {counts['open_prs']}",
        f"- Open issues: {counts['open_issues']}",
        f"- Recent failed workflow runs: {len(runs)}",
        "",
        "## Pull requests needing attention",
        "",
        f"Ready and not approved: {len(prs['ready_needing_review'])}; stale ready: {len(prs['stale_ready'])}.",
        "",
        *render_numbered_items(prs["ready_needing_review"], "pr"),
        "",
        "### Failing CI",
        "",
        *render_numbered_items(prs["failing_ci"], "pr"),
        "",
        "### Merge conflicts or rebase needed",
        "",
        *render_numbered_items(prs["merge_conflicts"] + prs["needs_rebase"], "pr"),
        "",
        "### Stale drafts",
        "",
        *render_numbered_items(prs["stale_drafts"], "pr"),
        "",
        "## Issue triage",
        "",
        f"New unlabeled: {len(issues['new_unlabeled'])}; old unlabeled and unassigned: {len(issues['old_unlabeled_unassigned'])}; stale: {len(issues['stale'])}.",
        "",
        "### New unlabeled",
        "",
        *render_numbered_items(issues["new_unlabeled"], "issue"),
        "",
        "### Old unlabeled and unassigned",
        "",
        *render_numbered_items(issues["old_unlabeled_unassigned"], "issue"),
        "",
        "## Maintenance queues",
        "",
        f"- Dependency updates: {len(prs['dependencies'])}",
        f"- Backports: {len(prs['backports'])}",
        f"- Release/version PRs: {len(prs['releases'])}",
        f"- Open CI/flaky-test issues: {len(issues['ci_flaky'])}",
        "",
        "## Recent failed workflow runs",
        "",
        *render_run_items(runs),
        "",
        "## Safety",
        "",
        "This digest does not comment, label, assign, close, open, approve, merge, or modify GitHub state.",
        "",
    ]
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--fixture-dir", type=Path)
    parser.add_argument("--now", help="ISO-8601 time; defaults to current UTC")
    args = parser.parse_args()

    now = parse_time(args.now) if args.now else datetime.now(timezone.utc)
    if args.fixture_dir:
        prs, issues, failed_runs = collect_fixtures(args.fixture_dir)
    else:
        prs, issues, failed_runs = collect_live(args.repo)

    state = build_state(args.repo, prs, issues, failed_runs, now)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "state.json").write_text(
        json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (args.output_dir / "deterministic.md").write_text(
        render_markdown(state), encoding="utf-8"
    )


if __name__ == "__main__":
    main()
