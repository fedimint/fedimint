#!/usr/bin/env python3

from __future__ import annotations

import tomllib
import unittest
from pathlib import Path


ROOT = Path(__file__).parents[3]


class RepositoryGuardrailTests(unittest.TestCase):
    def test_every_workspace_member_inherits_workspace_lints(self) -> None:
        workspace = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))
        missing = []

        for member_pattern in workspace["workspace"]["members"]:
            manifests = sorted(ROOT.glob(f"{member_pattern}/Cargo.toml"))
            self.assertTrue(
                manifests, f"workspace member did not resolve: {member_pattern}"
            )
            for manifest in manifests:
                package = tomllib.loads(manifest.read_text(encoding="utf-8"))
                if package.get("lints", {}).get("workspace") is not True:
                    missing.append(str(manifest.relative_to(ROOT)))

        self.assertEqual(missing, [])

    def test_disallowed_methods_are_denied_workspace_wide(self) -> None:
        workspace = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))

        self.assertEqual(
            workspace["workspace"]["lints"]["clippy"]["disallowed_methods"],
            "deny",
        )


if __name__ == "__main__":
    unittest.main()
