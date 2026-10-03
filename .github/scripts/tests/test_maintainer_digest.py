#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "maintainer-digest.py"
SPEC = importlib.util.spec_from_file_location("maintainer_digest", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)

NOW = datetime(2026, 7, 15, 12, 0, tzinfo=timezone.utc)


def pr(
    number: int,
    *,
    title: str = "A change",
    created: str = "2026-06-01T12:00:00Z",
    updated: str = "2026-06-20T12:00:00Z",
    draft: bool = False,
    decision: str = "",
    merge_state: str = "CLEAN",
    checks: list[dict] | None = None,
    labels: list[str] | None = None,
    author: str = "alice",
) -> dict:
    return {
        "number": number,
        "title": title,
        "author": {"login": author},
        "createdAt": created,
        "updatedAt": updated,
        "isDraft": draft,
        "reviewDecision": decision,
        "mergeStateStatus": merge_state,
        "statusCheckRollup": checks or [],
        "labels": [{"name": label} for label in labels or []],
    }


def issue(
    number: int,
    *,
    title: str = "An issue",
    created: str = "2024-01-01T12:00:00Z",
    updated: str = "2024-01-02T12:00:00Z",
    labels: list[str] | None = None,
    assignees: list[str] | None = None,
) -> dict:
    return {
        "number": number,
        "title": title,
        "author": {"login": "bob"},
        "createdAt": created,
        "updatedAt": updated,
        "labels": [{"name": label} for label in labels or []],
        "assignees": [{"login": login} for login in assignees or []],
    }


class MaintainerDigestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.prs = [
            pr(
                1,
                title="Needs review",
                merge_state="DIRTY",
                checks=[
                    {"name": "tests", "status": "COMPLETED", "conclusion": "FAILURE"}
                ],
            ),
            pr(2, title="Old draft", draft=True, updated="2026-05-01T12:00:00Z"),
            pr(
                3,
                title="Bump crate",
                decision="APPROVED",
                labels=["dependencies"],
                author="dependabot[bot]",
            ),
            pr(4, title="chore(nix): flake.lock update"),
            pr(5, title="[Backport releases/v0.11] fix payment"),
        ]
        self.issues = [
            issue(
                10,
                title="New untrusted ](https://evil.example)\n<script>",
                created="2026-07-14T12:00:00Z",
                updated="2026-07-14T12:00:00Z",
            ),
            issue(11, title="Old untriaged"),
            issue(
                12,
                title="Tracked flaky test",
                labels=["flaky test"],
                assignees=["alice"],
            ),
            issue(
                13,
                title="Fresh labeled",
                created="2026-07-14T12:00:00Z",
                updated="2026-07-14T12:00:00Z",
                labels=["client"],
            ),
        ]
        self.runs = [
            {
                "databaseId": 100,
                "workflowName": "CI (nix)",
                "displayTitle": "A failed run",
                "event": "merge_group",
                "headBranch": "queue",
                "headSha": "abc",
                "createdAt": "2026-07-14T12:00:00Z",
                "updatedAt": "2026-07-14T12:00:00Z",
                "conclusion": "failure",
            },
            {
                "databaseId": 101,
                "workflowName": "Old CI",
                "displayTitle": "Too old",
                "event": "push",
                "headBranch": "master",
                "headSha": "def",
                "createdAt": "2026-01-01T12:00:00Z",
                "updatedAt": "2026-01-01T12:00:00Z",
                "conclusion": "failure",
            },
        ]

    def test_build_state_classifies_queues(self) -> None:
        state = MODULE.build_state(
            "fedimint/fedimint", self.prs, self.issues, self.runs, NOW
        )

        self.assertEqual(state["source_counts"]["open_prs"], 5)
        self.assertEqual(len(state["pull_requests"]["ready_needing_review"]), 3)
        self.assertEqual(
            [item["number"] for item in state["pull_requests"]["stale_drafts"]], [2]
        )
        self.assertEqual(
            [item["number"] for item in state["pull_requests"]["failing_ci"]], [1]
        )
        self.assertEqual(
            [item["number"] for item in state["pull_requests"]["merge_conflicts"]], [1]
        )
        self.assertEqual(len(state["pull_requests"]["dependencies"]), 2)
        self.assertEqual(
            [item["number"] for item in state["pull_requests"]["backports"]], [5]
        )
        self.assertEqual(
            [item["number"] for item in state["issues"]["new_unlabeled"]], [10]
        )
        self.assertEqual([item["number"] for item in state["issues"]["ci_flaky"]], [12])
        self.assertEqual(
            [run["run_id"] for run in state["ci"]["recent_failed_runs"]], [100]
        )
        self.assertTrue(state["read_only"])

    def test_workflow_permissions_are_read_only(self) -> None:
        workflow_path = (
            Path(__file__).parents[3]
            / ".github"
            / "workflows"
            / "maintainer-digest.yml"
        )
        workflow = workflow_path.read_text(encoding="utf-8")
        permissions = workflow.split("\npermissions:\n", maxsplit=1)[1].split(
            "\n\njobs:", maxsplit=1
        )[0]
        self.assertEqual(
            permissions,
            "  actions: read\n  contents: read\n  issues: read\n  pull-requests: read",
        )
        self.assertNotIn(
            "\n    permissions:", workflow.split("\n\njobs:", maxsplit=1)[1]
        )

    def test_ai_wrapper_uses_read_only_sandbox_and_empty_tool_environment(self) -> None:
        wrapper = (Path(__file__).parents[1] / "run-maintainer-digest-ai.sh").read_text(
            encoding="utf-8"
        )

        self.assertIn("unset GH_TOKEN GITHUB_TOKEN", wrapper)
        self.assertIn('sandbox_mode = "read-only"', wrapper)
        self.assertIn('inherit = "none"', wrapper)

    def test_markdown_escapes_untrusted_titles_and_uses_constructed_urls(self) -> None:
        state = MODULE.build_state(
            "fedimint/fedimint", self.prs, self.issues, self.runs, NOW
        )
        rendered = MODULE.render_markdown(state)

        self.assertIn("https://github.com/fedimint/fedimint/issues/10", rendered)
        self.assertNotIn("https://evil.example", rendered)
        self.assertNotIn("<script>", rendered)
        self.assertIn("Read-only advisory output", rendered)

    def test_fixture_collection_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            for name, value in (
                ("prs.json", self.prs),
                ("issues.json", self.issues),
                ("runs.json", self.runs),
            ):
                (directory / name).write_text(json.dumps(value), encoding="utf-8")

            prs, issues, runs = MODULE.collect_fixtures(directory)

        self.assertEqual(prs, self.prs)
        self.assertEqual(issues, self.issues)
        self.assertEqual(runs, self.runs)

    def test_check_state_handles_status_contexts(self) -> None:
        failing, pending = MODULE.check_states(
            {
                "statusCheckRollup": [
                    {"context": "legacy", "state": "ERROR"},
                    {"name": "build", "status": "IN_PROGRESS"},
                    {"name": "done", "status": "COMPLETED", "conclusion": "SUCCESS"},
                ]
            }
        )

        self.assertEqual(failing, ["legacy"])
        self.assertEqual(pending, ["build"])

    def test_ai_wrapper_falls_back_without_provider_key(self) -> None:
        wrapper = Path(__file__).parents[1] / "run-maintainer-digest-ai.sh"
        workspace = Path(__file__).parents[3]
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            digest_dir = root / "digest"
            digest_dir.mkdir()
            deterministic = "# Deterministic\n\nRead-only.\n"
            (digest_dir / "deterministic.md").write_text(
                deterministic, encoding="utf-8"
            )
            (digest_dir / "state.json").write_text("{}\n", encoding="utf-8")
            environment = os.environ.copy()
            environment.update(
                {
                    "DIGEST_DIR": str(digest_dir),
                    "GITHUB_WORKSPACE": str(workspace),
                    "RUNNER_TEMP": str(root / "runner"),
                    "PPQ_KEY": "",
                }
            )

            subprocess.run(["bash", str(wrapper)], env=environment, check=True)

            self.assertEqual(
                (digest_dir / "digest.md").read_text(encoding="utf-8"), deterministic
            )

    def test_ai_wrapper_combines_mocked_summary_with_evidence(self) -> None:
        wrapper = Path(__file__).parents[1] / "run-maintainer-digest-ai.sh"
        workspace = Path(__file__).parents[3]
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            digest_dir = root / "digest"
            bin_dir = root / "bin"
            digest_dir.mkdir()
            bin_dir.mkdir()
            deterministic = "# Deterministic evidence\n"
            (digest_dir / "deterministic.md").write_text(
                deterministic, encoding="utf-8"
            )
            (digest_dir / "state.json").write_text(
                '{"read_only": true}\n', encoding="utf-8"
            )
            fake_codex = bin_dir / "codex"
            fake_codex.write_text(
                """#!/usr/bin/env bash
set -euo pipefail
if [ -n "${GH_TOKEN:-}" ] || [ -n "${GITHUB_TOKEN:-}" ]; then
  exit 9
fi
output=''
while [ "$#" -gt 0 ]; do
  if [ "$1" = '--output-last-message' ]; then
    output="$2"
    shift 2
  else
    shift
  fi
done
cat >/dev/null
printf '# Mocked AI priority\\n' > "$output"
""",
                encoding="utf-8",
            )
            fake_codex.chmod(0o755)
            environment = os.environ.copy()
            environment.update(
                {
                    "DIGEST_DIR": str(digest_dir),
                    "GITHUB_WORKSPACE": str(workspace),
                    "RUNNER_TEMP": str(root / "runner"),
                    "PPQ_KEY": "test-provider-key",
                    "GH_TOKEN": "must-not-reach-agent-tools",
                    "PATH": f"{bin_dir}:{environment['PATH']}",
                }
            )

            subprocess.run(["bash", str(wrapper)], env=environment, check=True)

            rendered = (digest_dir / "digest.md").read_text(encoding="utf-8")
            config = (
                root / "runner" / "maintainer-digest-ai" / "codex-home" / "config.toml"
            ).read_text(encoding="utf-8")
            self.assertIn("# Mocked AI priority", rendered)
            self.assertIn("# Deterministic evidence", rendered)
            self.assertNotIn("test-provider-key", config)
            self.assertNotIn("GH_TOKEN", config)


if __name__ == "__main__":
    unittest.main()
