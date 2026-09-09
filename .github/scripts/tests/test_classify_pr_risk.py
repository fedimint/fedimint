#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "classify-pr-risk.py"
ROOT = Path(__file__).parents[3]
SPEC = importlib.util.spec_from_file_location("classify_pr_risk", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class ClassifyPrRiskTests(unittest.TestCase):
    def test_workflow_passes_context_and_risk_to_both_model_passes(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "codex-review.yml").read_text(
            encoding="utf-8"
        )

        self.assertGreaterEqual(workflow.count("/tmp/pr_context.json"), 3)
        self.assertGreaterEqual(workflow.count("/tmp/pr_risk.json"), 8)
        self.assertIn("steps.risk.outputs.requires_human_review", workflow)
        self.assertNotIn("steps.changed.outputs.consensus", workflow)
        self.assertIn("contributor-controlled, untrusted", workflow)

    def test_documentation_change_is_low_risk(self) -> None:
        result = MODULE.classify(["docs/architecture.md"])

        self.assertEqual(result["active_routes"], [])
        self.assertFalse(result["requires_human_review"])
        self.assertEqual(result["guardrails"], [])

    def test_consensus_change_requires_human_review(self) -> None:
        result = MODULE.classify(["fedimint-server/src/consensus/engine.rs"])

        self.assertTrue(result["routes"]["consensus"]["active"])
        self.assertTrue(result["requires_human_review"])
        self.assertIn("consensus", result["human_review_reasons"])

    def test_multiple_routes_are_preserved(self) -> None:
        result = MODULE.classify(
            [
                "modules/fedimint-ln-server/src/db.rs",
                "fedimint-wasm-tests/src/lib.rs",
                ".github/workflows/ci-nix.yml",
            ]
        )

        self.assertIn("consensus", result["active_routes"])
        self.assertIn("database_persistence", result["active_routes"])
        self.assertIn("wasm_portability", result["active_routes"])
        self.assertIn("infra_release_supply_chain", result["active_routes"])

    def test_database_change_without_evidence_is_advisory(self) -> None:
        diff = """diff --git a/fedimint-core/src/db.rs b/fedimint-core/src/db.rs
--- a/fedimint-core/src/db.rs
+++ b/fedimint-core/src/db.rs
@@ -1 +1,2 @@
+struct StoredRecord { value: u64 }
"""
        result = MODULE.classify(["fedimint-core/src/db.rs"], diff)

        ids = [guardrail["id"] for guardrail in result["guardrails"]]
        self.assertIn("database-migration-evidence", ids)

    def test_migration_file_satisfies_database_evidence(self) -> None:
        result = MODULE.classify(
            [
                "fedimint-core/src/db.rs",
                "fedimint-core/src/db/migrations/v4.rs",
            ]
        )

        ids = [guardrail["id"] for guardrail in result["guardrails"]]
        self.assertNotIn("database-migration-evidence", ids)

    def test_new_raw_reqwest_client_without_timeout_is_advisory(self) -> None:
        diff = """diff --git a/src/http.rs b/src/http.rs
--- a/src/http.rs
+++ b/src/http.rs
@@ -1 +1,2 @@
+let client = reqwest::Client::new();
"""
        result = MODULE.classify(["src/http.rs"], diff)

        guardrail = next(
            item
            for item in result["guardrails"]
            if item["id"] == "outbound-http-timeout"
        )
        self.assertEqual(guardrail["matched_files"], ["src/http.rs"])

    def test_reqwest_builder_with_timeout_has_no_advisory(self) -> None:
        diff = """diff --git a/src/http.rs b/src/http.rs
--- a/src/http.rs
+++ b/src/http.rs
@@ -1 +1,4 @@
+let client = reqwest::Client::builder()
+    .connect_timeout(CONNECT_TIMEOUT)
+    .timeout(REQUEST_TIMEOUT)
+    .build()?;
"""
        result = MODULE.classify(["src/http.rs"], diff)

        ids = [guardrail["id"] for guardrail in result["guardrails"]]
        self.assertNotIn("outbound-http-timeout", ids)

    def test_deleted_reqwest_client_is_not_reported(self) -> None:
        diff = """diff --git a/src/http.rs b/src/http.rs
--- a/src/http.rs
+++ b/src/http.rs
@@ -1 +0,0 @@
-let client = reqwest::Client::new();
"""
        result = MODULE.classify(["src/http.rs"], diff)

        self.assertEqual(result["guardrails"], [])


if __name__ == "__main__":
    unittest.main()
