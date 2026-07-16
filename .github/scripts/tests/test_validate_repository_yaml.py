#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path

from yaml.constructor import ConstructorError


SCRIPT = Path(__file__).parents[1] / "validate-repository-yaml.py"
SPEC = importlib.util.spec_from_file_location("validate_repository_yaml", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class ValidateRepositoryYamlTests(unittest.TestCase):
    def validate_text(self, value: str) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "test.yaml"
            path.write_text(value, encoding="utf-8")
            MODULE.validate_file(path)

    def test_valid_mapping(self) -> None:
        self.validate_text("name: test\nitems:\n  - one\n  - two\n")

    def test_duplicate_key_is_rejected(self) -> None:
        with self.assertRaises(ConstructorError):
            self.validate_text("name: first\nname: second\n")

    def test_malformed_yaml_is_rejected(self) -> None:
        with self.assertRaises(Exception):
            self.validate_text("name: [unterminated\n")

    def test_non_mapping_document_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self.validate_text("- one\n- two\n")


if __name__ == "__main__":
    unittest.main()
