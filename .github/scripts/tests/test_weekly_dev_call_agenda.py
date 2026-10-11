"""Offline fixtures; no tests invoke GitHub or execute repository content."""

import importlib.util
import json
import os
import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "weekly-dev-call-agenda.py"
if not SCRIPT.exists():  # Also runnable as a standalone review artifact.
    SCRIPT = Path(__file__).with_name("weekly-dev-call-agenda.py")
SPEC = importlib.util.spec_from_file_location("agenda", SCRIPT)
agenda = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(agenda)

END = agenda.utc("2026-10-05T14:00:00Z")
START = END - agenda.timedelta(hours=184)
OLD = "2025-01-01T00:00:00Z"
DURING = "2026-10-01T14:00:00Z"
AFTER = "2026-10-06T14:00:00Z"
SHA = "a" * 40


def wire(body, link=None, status="200 OK"):
    headers = f"HTTP/2.0 {status}\r\nContent-Type: application/json\r\n"
    if link is not None:
        headers += f"Link: {link}\r\n"
    return (headers + "\r\n" + json.dumps(body)).encode()


def item(number, *, updated=DURING, created=OLD, pr=False):
    row = {
        "number": number, "id": number, "created_at": created,
        "updated_at": updated, "closed_at": None, "state": "open",
        "state_reason": None, "title": "Ordinary title", "body": "Evidence only",
        "labels": [{"name": "bug"}], "milestone": None,
    }
    if pr:
        row["pull_request"] = {}
    return row


class FixtureClient:
    def __init__(self, inventory, change_head=False):
        self.inventory = inventory
        self.ledger = []
        self.requests = 0
        self.bytes = 0
        self.paths = []
        self.detail_reads = 0
        self.change_head = change_head

    def collection(self, path, parameters=None, key=None):
        self.paths.append(path)
        if path == agenda.ROOT + "/issues":
            assert parameters["state"] == "all"
            return self.inventory
        if path.endswith("/timeline"):
            return [{"id": 99, "event": "labeled", "created_at": DURING}]
        if path.endswith("/reviews"):
            return [{"id": 8, "state": "APPROVED", "submitted_at": DURING, "commit_id": SHA}]
        if path.endswith("/commits"):
            return [{"sha": SHA, "commit": {"author": {"date": OLD}}}]
        return []

    def single(self, path):
        self.paths.append(path)
        number = int(path.rsplit("/", 1)[-1])
        source = next(row for row in self.inventory if row["number"] == number)
        if "/pulls/" not in path:
            return source
        self.detail_reads += 1
        return {
            "head": {"sha": "b" * 40 if self.change_head and self.detail_reads > 1 else SHA},
            "draft": False, "merged_at": DURING, "mergeable": None,
            "mergeable_state": "unknown", "commits": 1, "body": "PR detail",
        }


class AgendaTests(unittest.TestCase):
    def test_window_schedule_and_rerun_endpoint(self):
        self.assertEqual((END - START).total_seconds(), 184 * 3600)
        self.assertEqual(agenda.scheduled_endpoint("2026-10-05T14:15:01Z"), END)
        self.assertEqual(agenda.scheduled_endpoint("2026-10-08T23:15:01Z"), END)
        self.assertEqual(
            agenda.scheduled_endpoint("2026-10-05T13:59:59Z"),
            END - agenda.timedelta(days=7),
        )
        for bad in ("", "2026-10-05", "2026-10-05T14:00:00+00:00", "2026-10-05T14:00:00.0Z"):
            with self.assertRaises(agenda.IncompleteEvidence):
                agenda.utc(bad)

    def test_half_open_and_edited_comment(self):
        row = item(1, created=agenda.stamp(START))
        sources = {"comments": [
            {"id": 7, "created_at": OLD, "updated_at": DURING},
            {"id": 8, "created_at": agenda.stamp(END), "updated_at": agenda.stamp(END)},
        ]}
        events = agenda.evidence_events(row, sources, START, END)
        self.assertEqual([e["kind"] for e in events], ["created", "comments:edited"])
        self.assertTrue(events[1]["url"].endswith("#issuecomment-7"))

    def test_commit_dates_are_not_push_times(self):
        events = agenda.evidence_events(item(1), {
            "commits": [{"commit": {"author": {"date": DURING}}}],
            "timeline": [{"event": "committed", "committer": {"date": DURING}}],
        }, START, END)
        self.assertEqual(events, [])

    def test_missing_comment_time_fails(self):
        with self.assertRaises(KeyError):
            agenda.evidence_events(item(1), {"comments": [{"id": 3}]}, START, END)

    def test_inventory_lower_bound_but_no_upper_updated_cutoff(self):
        old = item(1, updated=OLD)
        later = item(2, updated=AFTER)
        future = item(3, created=AFTER, updated=AFTER)
        merged = item(4, pr=True)
        merged["state"] = "closed"
        client = FixtureClient([old, later, future, merged])
        report = agenda.collect(client, END)
        self.assertEqual(report["inventory_count"], 4)
        self.assertEqual([row["number"] for row in report["items"]], [2, 4])
        self.assertEqual(len(report["excluded"]), 2)
        self.assertEqual(report["excluded"][0]["updated_at"], OLD)
        self.assertFalse(any("/issues/1/" in path for path in client.paths))
        pr = report["items"][1]
        self.assertEqual(pr["current"]["merged_at"], DURING)
        self.assertEqual(pr["initial_pr"]["body"], "PR detail")
        self.assertEqual(pr["current_issue"]["body"], "Evidence only")
        self.assertTrue(report["complete"])

    def test_changed_head_since_initial_evidence_fails(self):
        with self.assertRaisesRegex(agenda.IncompleteEvidence, "since evidence"):
            agenda.collect(FixtureClient([item(1, pr=True)], change_head=True), END)

    def test_inventory_missing_timestamp_fails(self):
        broken = item(1)
        del broken["updated_at"]
        with self.assertRaises(KeyError):
            agenda.collect(FixtureClient([broken]), END)

    def test_complete_pagination(self):
        path = agenda.ROOT + "/issues"
        first = path + "?state=all&per_page=100&page=1"
        second = path + "?state=all&per_page=100&page=2"
        responses = {
            first: wire([{"id": 1}], f'<https://api.github.com/{second}>; rel="next"'),
            second: wire([{"id": 2}]),
        }
        client = agenda.Client(responses.__getitem__)
        self.assertEqual(client.collection(path, {"state": "all"}), [{"id": 1}, {"id": 2}])
        self.assertEqual(client.ledger[0]["pages"], 2)
        self.assertTrue(client.ledger[0]["complete"])

    def test_bad_page_next_links_and_resource_bounds_fail(self):
        path = agenda.ROOT + "/issues"
        for next_link in (
            "https://evil.invalid/repos/fedimint/fedimint/issues?per_page=100&page=2",
            f"https://api.github.com/{path}?per_page=100&page=1",
            f"https://api.github.com/{path}?per_page=100&page=3",
        ):
            client = agenda.Client(lambda _: wire([{"id": 1}], f'<{next_link}>; rel="next"'))
            with self.assertRaises(agenda.IncompleteEvidence):
                client.collection(path)
            self.assertEqual(client.ledger, [])
        for raw in (wire([], status="403 Forbidden"), b"[]", b"HTTP/2.0 200 OK\n\n[]"):
            with self.assertRaises(agenda.IncompleteEvidence):
                agenda.decode_page(raw)
        client = agenda.Client(lambda _: wire([]))
        client.requests = agenda.MAX_REQUESTS
        with self.assertRaises(agenda.IncompleteEvidence):
            client.collection(path)
        with patch.object(agenda, "MAX_PAGE_BYTES", 5):
            with self.assertRaises(agenda.IncompleteEvidence):
                agenda.Client(lambda _: wire([])).collection(path)

    def test_missing_later_page_duplicate_and_total_mismatch_fail(self):
        path = agenda.ROOT + "/issues"
        calls = 0

        def unavailable(_):
            nonlocal calls
            calls += 1
            if calls > 1:
                raise agenda.IncompleteEvidence("page unavailable")
            return wire([{"id": 1}], f'<https://api.github.com/{path}?per_page=100&page=2>; rel="next"')

        with self.assertRaisesRegex(agenda.IncompleteEvidence, "unavailable"):
            agenda.Client(unavailable).collection(path)
        with self.assertRaises(agenda.IncompleteEvidence):
            agenda.Client(lambda _: wire([{"id": 1}, {"id": 1}])).collection(path)
        with self.assertRaises(agenda.IncompleteEvidence):
            agenda.Client(lambda _: wire({"total_count": 2, "check_runs": []})).collection(path, key="check_runs")

    def test_markdown_injection_determinism_and_metadata_only_proposals(self):
        row = item(1)
        row["title"] = '<script>\n# injected [x](javascript:bad) @everyone `$(bad)`'
        row["milestone"] = {"title": "Release [x](evil)", "number": 2}
        report = agenda.collect(FixtureClient([row]), END)
        rendered = agenda.render(report)
        self.assertEqual(rendered, agenda.render(report))
        for forbidden in ("<script>", "\n# injected", "@everyone", "$(bad)", "(javascript:"):
            self.assertNotIn(forbidden, rendered)
        self.assertIn("Suggested—needs maintainer agreement", rendered)
        self.assertIn("current public milestone", rendered)
        self.assertIn("Dev-call-2026-10-05.md", rendered)
        self.assertIn("Week-summary-5-October,-2026", rendered)
        row["labels"] = []
        row["milestone"] = None
        row["title"] = "release blocker with no metadata"
        rendered = agenda.render(agenda.collect(FixtureClient([row]), END))
        self.assertEqual(rendered.count("No matching public metadata"), 3)

    def test_failure_does_not_emit_success_artifacts(self):
        with tempfile.TemporaryDirectory() as parent:
            output = Path(parent) / "out"
            with patch("sys.argv", ["agenda", "--end", agenda.stamp(END), "--output-dir", str(output)]):
                with patch.object(agenda, "collect", side_effect=agenda.IncompleteEvidence("gap")):
                    self.assertEqual(agenda.main(), 1)
            self.assertEqual([file.name for file in output.iterdir()], ["failure.json"])
            self.assertFalse(json.loads((output / "failure.json").read_text())["complete"])

    def test_wrong_repository_fails_before_collection(self):
        with tempfile.TemporaryDirectory() as parent:
            with patch("sys.argv", ["agenda", "--end", agenda.stamp(END), "--output-dir", str(Path(parent) / "out")]):
                with patch.dict(os.environ, {"GITHUB_REPOSITORY": "other/repo"}):
                    with patch.object(agenda, "collect") as collect:
                        self.assertEqual(agenda.main(), 1)
                        collect.assert_not_called()

    def test_workflow_is_read_only_and_pinned(self):
        workflow = SCRIPT.parents[1] / "workflows" / "weekly-dev-call-agenda.yml"
        if not workflow.exists():
            workflow = SCRIPT.with_name("weekly-dev-call-agenda.yml")
        source = workflow.read_text()
        self.assertIn("cron: '0 14 * * 1'", source)
        self.assertIn("github.repository == 'fedimint/fedimint'", source)
        self.assertIn("persist-credentials: false", source)
        self.assertNotIn(": write", source)
        self.assertNotIn("secrets.", source)
        permissions = source.split("permissions:\n", 1)[1].split("\njobs:", 1)[0]
        self.assertEqual(
            set(re.findall(r"^  ([a-z-]+): read$", permissions, re.M)),
            {"contents", "issues", "pull-requests", "checks", "actions"},
        )
        actions = re.findall(r"uses: (\S+)", source)
        self.assertEqual(len(actions), 2)
        self.assertTrue(all(re.fullmatch(r"actions/[a-z-]+@[0-9a-f]{40}", action) for action in actions))
        self.assertIn("--end \"$MANUAL_END\"", source)
        self.assertIn("--scheduled-at \"$scheduled_at\"", source)


if __name__ == "__main__":
    unittest.main()
