#!/usr/bin/env python3
"""Offline integration checks for Codex workflow API steps (requires bash and jq)."""

import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest


WORKFLOW = Path(__file__).resolve().parents[2] / ".github/workflows/codex-review.yml"
MARKER = "<!-- fedimint-codex-review -->"
MOCK_GH = """#!/usr/bin/env python3
import json, os, pathlib, sys
args = sys.argv[1:]
root = pathlib.Path(os.environ["FIXTURE_DIR"])
with (root / "calls.jsonl").open("a") as f:
    f.write(json.dumps(args) + "\\n")
if args[:2] == ["api", "user"]:
    sys.exit("installation tokens cannot call /user")
if "--method" in args or args[:2] == ["pr", "review"]:
    if "--input" in args:
        body = json.load(sys.stdin)
    elif "--body-file" in args:
        body = {"body": pathlib.Path(args[args.index("--body-file") + 1]).read_text()}
    else:
        body = {}
    (root / "submitted.json").write_text(json.dumps(body))
    if os.environ.get("REJECT_REVIEW") == "1":
        sys.exit("Resource not accessible by integration")
    print("{}")
else:
    endpoint = args[1].split("/")[-1]
    if endpoint in ("reviews", "comments"):
        assert "--paginate" in args and "--slurp" in args
        print((root / (endpoint + ".json")).read_text())
    elif endpoint == "9518":
        print(json.dumps({"base": {"ref": "master", "sha": "a" * 40},
                          "head": {"sha": "b" * 40},
                          "user": {"login": "contributor"}, "title": "Example PR"}))
    else:
        sys.exit("unexpected endpoint: " + endpoint)
"""


class WorkflowTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        gh = self.root / "gh"
        gh.write_text(MOCK_GH)
        gh.chmod(0o755)
        self.workflow = WORKFLOW.read_text()
        self.env = dict(os.environ, PATH=f"{self.root}:{os.environ['PATH']}",
                        FIXTURE_DIR=str(self.root), GITHUB_OUTPUT=str(self.root / "output"),
                        GH_TOKEN="offline-installation-token")
        self.values = {
            "github.repository": "fedimint/fedimint",
            "github.event_name": "pull_request_target",
            "github.event.issue.number": "9518",
            "github.event.pull_request.number": "9518",
            "github.event.comment.id": "123",
            "steps.pr.outputs.number": "9518",
            "steps.pr.outputs.head_sha": "b" * 40,
            "steps.codex-review.outputs.verdict": "COMMENT",
            "steps.codex-review.outputs.has_inline": "false",
        }

    def run_step(self, name, success=True):
        # Extract a named run block without adding a YAML dependency. Fail if
        # the workflow layout changes instead of accidentally testing a copy.
        step = self.workflow.split(f"      - name: {name}\n", 1)[1]
        step = step.split("\n      - ", 1)[0]
        script = step.split("        run: |\n", 1)[1]
        script = "\n".join(line[10:] if line else "" for line in script.splitlines())
        script = re.sub(r"\$\{\{\s*(.*?)\s*\}\}",
                        lambda m: self.values[m[1]], script)
        script = script.replace("/tmp/", f"{self.root}/")
        result = subprocess.run(["bash", "-euo", "pipefail", "-c", script],
                                env=self.env, capture_output=True, text=True)
        self.assertEqual(result.returncode == 0, success, result.stdout + result.stderr)
        return result

    def calls(self):
        return [json.loads(line) for line in (self.root / "calls.jsonl").read_text().splitlines()]

    def test_token_and_permissions(self):
        self.assertNotIn("BACKPORT_TOKEN", self.workflow)
        self.assertEqual(self.workflow.count("GH_TOKEN: ${{ github.token }}"), 4)
        self.assertIn("      contents: read\n", self.workflow)
        self.assertIn("      issues: write # Acknowledge /review issue comments", self.workflow)
        self.assertIn("      pull-requests: write\n", self.workflow)

    def test_metadata_and_acknowledgement(self):
        for event in ("pull_request_target", "issue_comment"):
            self.values["github.event_name"] = event
            self.run_step("Resolve PR metadata")
        output = (self.root / "output").read_text()
        self.assertEqual(output.count("number=9518\n"), 2)
        self.assertIn("head_sha=" + "b" * 40, output)
        self.run_step("Acknowledge review request")
        self.assertIn("repos/fedimint/fedimint/issues/comments/123/reactions", self.calls()[-1])

    def test_prior_reviews_across_migration(self):
        def review(id_, login, body):
            return {"id": id_, "user": {"login": login}, "body": body,
                    "submitted_at": f"2026-11-{id_:02}T00:00:00Z", "state": "COMMENTED"}

        reviews = [[review(1, "fedimint-bot", "legacy")],
                   [review(2, "github-actions[bot]", MARKER + "\nnew"),
                    review(3, "github-actions[bot]", "other workflow"),
                    review(4, "human", MARKER)]]
        comments = [[{"pull_request_review_id": i, "user": r["user"],
                      "body": f"inline-{i}", "created_at": r["submitted_at"]}
                     for page in reviews for r in page for i in [r["id"]]]]
        (self.root / "reviews.json").write_text(json.dumps(reviews))
        (self.root / "comments.json").write_text(json.dumps(comments))
        self.run_step("Fetch prior AI reviews")
        prior = (self.root / "prior_reviews.txt").read_text()
        for expected in ("legacy", "new", "inline-1", "inline-2"):
            self.assertIn(expected, prior)
        for excluded in ("other workflow", "inline-3", "inline-4"):
            self.assertNotIn(excluded, prior)
        self.assertIn("has_prior=true", (self.root / "output").read_text())

    def test_no_prior_reviews(self):
        (self.root / "reviews.json").write_text("[[]]")
        self.run_step("Fetch prior AI reviews")
        self.assertIn("has_prior=false", (self.root / "output").read_text())
        self.assertEqual(len(self.calls()), 1)

    def test_submission_and_policy_failure(self):
        for verdict in ("COMMENT", "APPROVE"):
            for inline in ("false", "true"):
                with self.subTest(verdict=verdict, inline=inline):
                    self.values["steps.codex-review.outputs.verdict"] = verdict
                    self.values["steps.codex-review.outputs.has_inline"] = inline
                    (self.root / "review_body.txt").write_text("Review explanation\n")
                    (self.root / "review.json").write_text(json.dumps({
                        "inline_comments": [{"path": "example.rs", "line": 1,
                                             "severity": "warning", "body": "Finding"}]}))
                    self.run_step("Submit review with inline comments")
                    submitted = json.loads((self.root / "submitted.json").read_text())
                    self.assertTrue(submitted["body"].startswith(MARKER))
                    self.assertIn("Review explanation", submitted["body"])
                    if inline == "true":
                        self.assertEqual(submitted["event"], verdict)
                        self.assertEqual(submitted["commit_id"], "b" * 40)
                        self.assertEqual(len(submitted["comments"]), 1)
                    self.env["REJECT_REVIEW"] = "1"
                    result = self.run_step("Submit review with inline comments", success=False)
                    self.assertIn("administrator must resolve", result.stdout)
                    del self.env["REJECT_REVIEW"]


if __name__ == "__main__":
    unittest.main()
