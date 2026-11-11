#!/usr/bin/env python3
"""Exercise the image-size guard against synthetic Docker archives."""

import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("check-container-size.py")


class ContainerSizeGuardTest(unittest.TestCase):
    def run_guard(self, layer_sizes, baseline=80, architecture="amd64", **kwargs):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive_path = root / "image.tar.gz"
            layers = [f"{number}/layer.tar" for number in range(len(layer_sizes))]
            members = {
                "manifest.json": json.dumps(
                    [{"Config": "config.json", "Layers": layers}]
                ).encode(),
                "config.json": json.dumps(
                    {"os": "linux", "architecture": architecture}
                ).encode(),
                # Neither archive metadata nor unrelated contents count as layers.
                "unrelated": b"x" * 10000,
            }
            members.update(
                (name, b"x" * size) for name, size in zip(layers, layer_sizes)
            )
            with tarfile.open(archive_path, "w:gz") as archive:
                for name, content in members.items():
                    member = tarfile.TarInfo(name)
                    member.size = len(content)
                    archive.addfile(member, io.BytesIO(content))
            baselines = root / "baselines.json"
            baselines.write_text(
                json.dumps(
                    {
                        "images": {
                            "test": {
                                kwargs.get("platform", "x86_64-linux"): {
                                    "uncompressed_bytes": baseline
                                }
                            }
                        }
                    }
                )
            )
            return subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    kwargs.get("image", "test"),
                    kwargs.get("platform", "x86_64-linux"),
                    str(archive_path),
                    "--baselines",
                    str(baselines),
                ],
                capture_output=True,
                text=True,
                check=False,
            )

    def test_exact_budget_passes_and_one_byte_over_fails(self):
        result = self.run_guard([40, 60])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("100 uncompressed layer bytes", result.stdout)
        result = self.run_guard([40, 61])
        self.assertEqual(result.returncode, 1)
        self.assertIn("exceeds its size budget", result.stderr)

    def test_fractional_byte_budget_is_not_rounded_up(self):
        self.assertEqual(self.run_guard([101], baseline=81).returncode, 0)
        self.assertEqual(self.run_guard([102], baseline=81).returncode, 1)

    def test_wrong_architecture_cannot_use_another_platforms_budget(self):
        result = self.run_guard([1], architecture="arm64")
        self.assertEqual(result.returncode, 1)
        self.assertIn("platform does not match", result.stderr)

    def test_arm64_archive_uses_its_platform_budget(self):
        result = self.run_guard([100], architecture="arm64", platform="aarch64-linux")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_missing_or_invalid_baseline_fails_closed(self):
        for arguments in [{"image": "new-image"}, {"baseline": 0}, {"baseline": True}]:
            with self.subTest(arguments=arguments):
                result = self.run_guard([1], **arguments)
                self.assertEqual(result.returncode, 1)
                self.assertIn("Cannot check", result.stderr)


if __name__ == "__main__":
    unittest.main()
