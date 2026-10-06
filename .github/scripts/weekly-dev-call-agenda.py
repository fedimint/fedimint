#!/usr/bin/env python3
"""Read-only, bounded GitHub evidence collection; never publishes to the wiki."""

from __future__ import annotations

import argparse
import html
import json
import os
import re
import selectors
import subprocess
import time
import unicodedata
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit
from zoneinfo import ZoneInfo

REPO = "fedimint/fedimint"
ROOT = f"repos/{REPO}"
WEB = f"https://github.com/{REPO}"
MAX_PAGE_BYTES = 8 * 1024 * 1024
MAX_TOTAL_BYTES = 256 * 1024 * 1024
MAX_REQUESTS = 4000
MAX_PAGES = 1000
MAX_SECONDS = 45 * 60


class IncompleteEvidence(Exception):
    """No agenda may be emitted from an incomplete collection."""


def utc(value: str) -> datetime:
    if not isinstance(value, str) or not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value
    ):
        raise IncompleteEvidence("Expected a whole-second UTC timestamp")
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def stamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def scheduled_endpoint(value: str) -> datetime:
    """Use original workflow run creation, not retry/start/current time."""
    created = utc(value)
    monday = (created - timedelta(days=created.weekday())).replace(
        hour=14, minute=0, second=0
    )
    return monday if monday <= created else monday - timedelta(days=7)


def positive(value: object) -> int:
    if type(value) is not int or value <= 0:
        raise IncompleteEvidence("Invalid GitHub numeric identifier")
    return value


def text(value: object) -> str:
    if not isinstance(value, str):
        raise IncompleteEvidence("Missing text field")
    return value


def markdown(value: str) -> str:
    # Escape *all* ASCII punctuation, including @, backticks, HTML, and links.
    # Flatten newlines and remove invisible formatting/control characters.
    value = " ".join(
        "".join(
            c if unicodedata.category(c) not in {"Cc", "Cf"} else " " for c in value
        ).split()
    )
    return "".join(
        f"&#{ord(c)};" if not c.isalnum() and not c.isspace() else html.escape(c)
        for c in value
    )


def gh_page(endpoint: str) -> bytes:
    """One GET, bounded while reading; never execute GitHub-provided text."""
    command = [
        "gh", "api", "--hostname", "github.com", "--method", "GET", "--include",
        "-H", "Accept: application/vnd.github+json",
        "-H", "X-GitHub-Api-Version: 2022-11-28", endpoint,
    ]
    with subprocess.Popen(
        command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
    ) as process:
        output = bytearray()
        deadline = time.monotonic() + 60
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            try:
                while selector.get_map():
                    if time.monotonic() >= deadline:
                        raise IncompleteEvidence("GitHub request timed out")
                    for key, _ in selector.select(timeout=0.2):
                        chunk = os.read(key.fileobj.fileno(), 65536)
                        if not chunk:
                            selector.unregister(key.fileobj)
                        else:
                            output.extend(chunk)
                            if len(output) > MAX_PAGE_BYTES:
                                raise IncompleteEvidence("GitHub page byte limit exceeded")
                if process.wait(timeout=max(0.1, deadline - time.monotonic())):
                    raise IncompleteEvidence("GitHub GET failed (possibly rate limited)")
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()
        return bytes(output)


def decode_page(raw: bytes) -> tuple[dict, object]:
    raw = raw.replace(b"\r\n", b"\n")
    header, separator, body = raw.partition(b"\n\n")
    if not separator or len(header) > 65536:
        raise IncompleteEvidence("Missing or oversized HTTP headers")
    lines = header.decode("utf-8").splitlines()
    if not lines or not re.fullmatch(r"HTTP/[\d.]+ 200(?: OK)?", lines[0]):
        raise IncompleteEvidence("Unexpected GitHub HTTP status")
    headers = {}
    for line in lines[1:]:
        name, colon, value = line.partition(":")
        if not colon or name.lower() in headers:
            raise IncompleteEvidence("Malformed or duplicate HTTP header")
        headers[name.lower()] = value.strip()
    if "application/json" not in headers.get("content-type", ""):
        raise IncompleteEvidence("Expected JSON response")
    return headers, json.loads(body)


class Client:
    def __init__(self, transport=gh_page):
        self.transport = transport
        self.started = time.monotonic()
        self.bytes = 0
        self.requests = 0
        self.ledger = []

    def get(self, endpoint: str) -> tuple[dict, object]:
        if not endpoint.startswith(ROOT + "/"):
            raise IncompleteEvidence("Repository boundary violation")
        if self.requests >= MAX_REQUESTS or time.monotonic() - self.started > MAX_SECONDS:
            raise IncompleteEvidence("Collection request/time budget exhausted")
        self.requests += 1
        raw = self.transport(endpoint)
        self.bytes += len(raw)
        if len(raw) > MAX_PAGE_BYTES or self.bytes > MAX_TOTAL_BYTES:
            raise IncompleteEvidence("Collection byte budget exhausted")
        return decode_page(raw)

    def single(self, path: str) -> dict:
        headers, value = self.get(path)
        if not isinstance(value, dict) or "link" in headers:
            raise IncompleteEvidence("Expected an unpaginated object")
        self.ledger.append({"endpoint": path, "pages": 1, "count": 1, "complete": True})
        return value

    def collection(self, path: str, parameters=None, key=None) -> list:
        parameters = {**(parameters or {}), "per_page": "100"}
        result = []
        seen = set()
        for page in range(1, MAX_PAGES + 1):
            endpoint = path + "?" + urlencode({**parameters, "page": str(page)})
            headers, value = self.get(endpoint)
            total = None
            if key:
                if not isinstance(value, dict):
                    raise IncompleteEvidence("Expected collection envelope")
                total = value.get("total_count")
                value = value.get(key)
            if not isinstance(value, list) or len(value) > 100:
                raise IncompleteEvidence("Expected a bounded collection page")
            for item in value:
                if not isinstance(item, dict):
                    raise IncompleteEvidence("Malformed collection item")
                identifier = item.get("id", item.get("sha"))
                # Timeline nodes can have no id (e.g. committed events).
                if identifier is not None:
                    if identifier in seen:
                        raise IncompleteEvidence("Duplicate entry: pagination changed")
                    seen.add(identifier)
            result.extend(value)
            links = {}
            if headers.get("link"):
                for link in headers["link"].split(","):
                    match = re.fullmatch(r'\s*<([^>]+)>;\s*rel="([^"]+)"\s*', link)
                    if not match or match[2] in links:
                        raise IncompleteEvidence("Malformed pagination link")
                    links[match[2]] = match[1]
            if "next" not in links:
                if total is not None and total != len(result):
                    raise IncompleteEvidence("Collection total does not match pages")
                self.ledger.append({
                    "endpoint": path, "pages": page, "count": len(result), "complete": True
                })
                return result
            following = urlsplit(links["next"])
            expected_query = {k: [v] for k, v in {**parameters, "page": str(page + 1)}.items()}
            # GitHub sometimes canonicalizes repos/OWNER/NAME to repositories/ID.
            # Do not follow that URL: validate same query, then request our fixed path.
            valid_path = following.path == "/" + path or re.fullmatch(
                r"/repositories/[1-9][0-9]*/" + re.escape(path[len(ROOT) + 1:]),
                following.path,
            )
            if (
                following.scheme != "https" or following.netloc != "api.github.com"
                or not valid_path or following.fragment
                or parse_qs(following.query) != expected_query or not value
            ):
                raise IncompleteEvidence("Discontinuous or unsafe pagination")
        raise IncompleteEvidence("Collection page limit exhausted")


def evidence_events(item: dict, sources: dict, start: datetime, end: datetime) -> list:
    number = positive(item["number"])
    base = f"{WEB}/{'pull' if 'pull_request' in item else 'issues'}/{number}"
    events = []

    def add(kind, timestamp, link):
        if timestamp and start <= utc(timestamp) < end:
            events.append({"kind": kind, "at": timestamp, "url": link})

    add("created", item["created_at"], base)
    add("closed", item.get("closed_at"), base)
    for source, rows in sources.items():
        for row in rows:
            if source == "commits":
                # Author/committer dates do not prove when a PR received commits.
                continue
            link = base
            if source in {"comments", "review_comments", "reviews"}:
                if source != "reviews":
                    utc(row["created_at"])
                    utc(row["updated_at"])
                elif row.get("submitted_at") is None and row.get("state") != "PENDING":
                    raise IncompleteEvidence("Review lacks submission timestamp")
                anchor = {
                    "comments": "issuecomment",
                    "review_comments": "discussion_r",
                    "reviews": "pullrequestreview",
                }[source]
                identifier = positive(row["id"])
                link = base + f"#{anchor}{'' if source == 'review_comments' else '-'}{identifier}"
            if source == "timeline" and row.get("event") == "committed":
                continue
            if source == "timeline" and not (row.get("created_at") or row.get("submitted_at")):
                raise IncompleteEvidence("Timeline event lacks activity timestamp")
            kind = f"timeline:{text(row.get('event'))}" if source == "timeline" else source
            add(kind, row.get("created_at") or row.get("submitted_at"), link)
            if row.get("updated_at") != row.get("created_at"):
                add(kind + ":edited", row.get("updated_at"), link)
    return sorted(
        {tuple(event.items()): event for event in events}.values(),
        key=lambda event: (event["at"], event["kind"], event["url"]),
    )


def collect(client: Client, end: datetime) -> dict:
    start = end - timedelta(hours=184)
    inventory = client.collection(ROOT + "/issues", {"state": "all", "sort": "created", "direction": "asc"})
    numbers = [positive(item["number"]) for item in inventory]
    if len(set(numbers)) != len(numbers):
        raise IncompleteEvidence("Duplicate inventory number")
    included = []
    excluded = []
    for item in sorted(inventory, key=lambda row: row["number"]):
        number = item["number"]
        created = utc(item["created_at"])
        updated = utc(item["updated_at"])
        if updated < created:
            raise IncompleteEvidence(f"#{number}: update precedes creation")
        inventory_evidence = {
            "number": number, "created_at": item["created_at"],
            "updated_at": item["updated_at"],
        }
        if created >= end or updated < start:
            excluded.append({
                **inventory_evidence,
                "reason": "created at/after endpoint" if created >= end else "inventory updated before start",
            })
            continue
        issue_path = f"{ROOT}/issues/{number}"
        sources = {
            name: client.collection(issue_path + "/" + name)
            for name in ("timeline", "comments")
        }
        detail = None
        initial_detail = None
        if "pull_request" in item:
            pr_path = f"{ROOT}/pulls/{number}"
            detail = client.single(pr_path)
            initial_detail = detail
            for name, suffix in (
                ("reviews", "reviews"), ("review_comments", "comments"), ("commits", "commits")
            ):
                sources[name] = client.collection(pr_path + "/" + suffix)
            if detail.get("commits") != len(sources["commits"]):
                raise IncompleteEvidence(f"PR #{number}: incomplete commits (REST caps at 250)")
        events = evidence_events(item, sources, start, end)
        if not events:
            if start <= utc(item["updated_at"]) < end:
                raise IncompleteEvidence(f"#{number}: update lacks timestamped activity evidence")
            excluded.append({**inventory_evidence, "reason": "no observable in-window events"})
            continue
        # Re-read discussion and state, retaining later discussion separately from
        # historical events. API collection is sequential, not an atomic snapshot.
        current_comments = client.collection(issue_path + "/comments")
        current = client.single(issue_path)
        utc(current["updated_at"])
        state = {
            "state": text(current["state"]),
            "state_reason": current.get("state_reason"),
            "updated_at": current["updated_at"],
            "labels": [text(label["name"]) for label in current["labels"]],
            "milestone": current.get("milestone"),
        }
        if detail is not None:
            detail = client.single(pr_path)
            sha = detail["head"]["sha"]
            if not re.fullmatch(r"[0-9a-f]{40}", sha):
                raise IncompleteEvidence("Malformed head SHA")
            if initial_detail["head"]["sha"] != sha:
                raise IncompleteEvidence(f"PR #{number}: head changed since evidence collection")
            if type(detail["draft"]) is not bool:
                raise IncompleteEvidence("Invalid PR draft flag")
            if detail["merged_at"] is not None:
                utc(detail["merged_at"])
            state.update({
                "draft": detail["draft"], "merged_at": detail["merged_at"],
                "head": sha, "mergeable": detail["mergeable"],
                "mergeable_state": detail["mergeable_state"],
                "reviews": client.collection(pr_path + "/reviews"),
                "checks": client.collection(ROOT + f"/commits/{sha}/check-runs", key="check_runs"),
                "statuses": client.collection(ROOT + f"/commits/{sha}/statuses"),
            })
            # Detect head churn across evidence/status collection rather than
            # associate old commits with new checks.
            if client.single(pr_path)["head"]["sha"] != sha:
                raise IncompleteEvidence(f"PR #{number}: head changed during refresh")
        included.append({
            "number": number, "kind": "PR" if detail is not None else "Issue",
            "title": text(current["title"]), "events": events,
            "current": state, "checked_at": stamp(datetime.now(timezone.utc)),
            "sources": sources, "latest_comments": current_comments,
            "inventory": item, "current_issue": current,
            "initial_pr": initial_detail, "current_pr": detail,
        })
    return {
        "schema_version": 1, "repository": REPO, "complete": True,
        "start": stamp(start), "end": stamp(end), "lookback_hours": 184,
        "generated_at": stamp(datetime.now(timezone.utc)),
        "intended_wiki_page": f"Dev-call-{end.date().isoformat()}.md",
        "inventory_count": len(inventory), "included_count": len(included),
        "excluded": excluded, "items": included, "pagination": client.ledger,
        "requests": client.requests, "bytes": client.bytes,
        "limitations": [
            "Sequential observations, not an atomic historical snapshot.",
            "Deleted/inaccessible activity and previous edit/force-push history cannot be recovered.",
            "Candidate discovery uses inventory updated_at >= start; activity not reflected in that timestamp may be unavailable.",
            "Commit author/committer dates are not push times; no commit-only activity is inferred.",
            "Current reviews are evidence, not a merge-readiness decision; CI/conflicts may be unknown.",
        ],
    }


def render(report: dict) -> str:
    end = utc(report["end"])
    date = end.date().isoformat()
    california = end.astimezone(ZoneInfo("America/Los_Angeles"))
    summary_slug = f"Week-summary-{california.day}-{california.strftime('%B')},-{california.year}"
    lines = [
        f"# Dev call agenda: {date}", "",
        "**Draft only — Suggested—needs maintainer agreement. No wiki publication.**", "",
        f"- Window (UTC): {report['start']} <= activity < {report['end']} (184 hours).",
        f"- Generated: {report['generated_at']}. Current statuses checked per item below.",
        f"- Inventory: {report['inventory_count']}; included: {report['included_count']}; "
        f"excluded with ledger reasons: {len(report['excluded'])}.",
        f"- [Weekly summary for this endpoint date]({WEB}/wiki/{summary_slug}) "
        "(link target not verified by this collector).",
        f"- Intended separate page: `{report['intended_wiki_page']}`; archive: `Dev-call.md`.",
        "- Preserve all manual wiki content. Neither page nor archive is written by this collector.",
        "- Complete pagination evidence and source records: `evidence.json`.", "",
        "## Pull requests with observed activity", "",
    ]
    for kind in ("PR", "Issue"):
        if kind == "Issue":
            lines.extend(["## Issues with observed activity", ""])
        rows = [item for item in report["items"] if item["kind"] == kind]
        if not rows:
            lines.extend(["None.", ""])
        for item in rows:
            current = item["current"]
            url = f"{WEB}/{'pull' if kind == 'PR' else 'issues'}/{item['number']}"
            lines.extend([
                f"### [#{item['number']}]({url}) — {markdown(item['title'])}",
                f"- Current state: {markdown(current['state'])}; checked {item['checked_at']}.",
                "- Labels: " + (", ".join(markdown(label) for label in current["labels"]) or "none") + ".",
            ])
            if kind == "PR":
                lines.append(
                    f"- Draft: {current['draft']}; merged: {current['merged_at'] or 'no'}; "
                    f"head: `{current['head']}`; "
                    f"mergeability: {markdown(str(current['mergeable_state']))}. "
                    "Reviews and current-head checks retained in evidence; readiness not inferred."
                )
                checks = current["checks"]
                statuses = current["statuses"]
                check_states = sorted({
                    text(check.get("conclusion") or check.get("status")) for check in checks
                })
                status_states = sorted({text(status["state"]) for status in statuses})
                current_head_reviews = sorted({
                    text(review["state"]) for review in current["reviews"]
                    if review.get("commit_id") == current["head"]
                })
                lines.append(
                    "- Current-head check observations: "
                    + (", ".join(markdown(s) for s in check_states) or "none / unknown")
                    + "; status observations (may include superseded statuses): "
                    + (", ".join(markdown(s) for s in status_states) or "none / unknown")
                    + "; current-head review observations (not an approval decision): "
                    + (", ".join(markdown(s) for s in current_head_reviews) or "none / unknown")
                    + "."
                )
            lines.extend(
                f"- {event['at']}: [{markdown(event['kind'])}]({event['url']})."
                for event in item["events"]
            )
            lines.append("")
    lines.extend(["## Proposed week / month / release discussion", "",
                  "**Suggested—needs maintainer agreement. Not a committed roadmap.**", ""])
    candidates = [item for item in report["items"] if item["current"]["state"] == "open"]
    for horizon, predicate, reason in (
        ("Week: triage explicitly labeled blockers", lambda s: set(s["labels"]) & {"bug", "regression", "blocker", "priority: high"}, "current priority/bug label"),
        ("Month: confirm milestone scope", lambda s: s["milestone"], "current public milestone"),
        ("Release: confirm release/backport scope", lambda s: set(s["labels"]) & {"release", "backport"}, "current release/backport label"),
    ):
        lines.extend([f"### {horizon}", ""])
        selected = [item for item in candidates if predicate(item["current"])]
        if not selected:
            lines.append("No matching public metadata; needs maintainer clarification.")
        for item in selected:
            suffix = "pull" if item["kind"] == "PR" else "issues"
            basis = reason
            milestone = item["current"]["milestone"]
            if horizon.startswith("Month") and milestone:
                basis += ": " + text(milestone["title"])
            lines.append(
                f"- [#{item['number']}]({WEB}/{suffix}/{item['number']}): "
                f"{markdown(item['title'])} — {markdown(basis)}."
            )
        lines.append("")
    lines.extend(["## Limitations and publication gate", ""])
    lines.extend("- " + limitation for limitation in report["limitations"])
    lines.extend([
        "- No owners, deadlines, release dates, or consensus are inferred.",
        "- Automatic wiki delivery is blocked pending an operator-approved durable Tau "
        "publisher or a narrowly provisioned wiki publisher. This workflow cannot write the wiki.",
        "",
    ])
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    endpoint = parser.add_mutually_exclusive_group(required=True)
    endpoint.add_argument("--end", help="Explicit whole-second UTC endpoint for a manual rerun")
    endpoint.add_argument("--scheduled-at", help="Original scheduled workflow run created_at")
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    # New directory required: a failed rerun must never upload stale success files.
    args.output_dir.mkdir(parents=True, exist_ok=False)
    client = Client()
    try:
        if os.environ.get("GITHUB_REPOSITORY", REPO) != REPO:
            raise IncompleteEvidence("Only fedimint/fedimint is supported")
        end = utc(args.end) if args.end else scheduled_endpoint(args.scheduled_at)
        if end > datetime.now(timezone.utc):
            raise IncompleteEvidence("Reporting endpoint is in the future")
        report = collect(client, end)
        agenda = render(report)
        (args.output_dir / "evidence.json").write_text(
            json.dumps(report, indent=2, ensure_ascii=True) + "\n", encoding="utf-8"
        )
        (args.output_dir / "agenda.md").write_text(agenda, encoding="utf-8")
        return 0
    except (IncompleteEvidence, ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError) as error:
        failure = {
            "complete": False, "error": str(error), "pagination": client.ledger,
            "requests": client.requests, "bytes": client.bytes,
            "notice": "No agenda produced. Do not treat this run as a weekly report.",
        }
        (args.output_dir / "failure.json").write_text(json.dumps(failure, indent=2) + "\n", encoding="utf-8")
        print("Incomplete evidence; see failure.json. No agenda produced.")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
