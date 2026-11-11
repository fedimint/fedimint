#!/usr/bin/env python3
"""Guard the sum of uncompressed layer tar sizes in a Docker image archive."""

import argparse
import json
from pathlib import Path
import sys
import tarfile


ARCHITECTURES = {"x86_64-linux": "amd64", "aarch64-linux": "arm64"}


def measure_archive(path, platform):
    sizes = {}
    documents = {}
    # Nix produces a gzip-compressed Docker archive whose layers are plain tar
    # members. Stream it: do not extract files or retain layer contents in memory.
    with tarfile.open(path, mode="r|*") as archive:
        for member in archive:
            if member.name in sizes:
                raise ValueError(f"Duplicate archive member: {member.name}")
            if not member.isfile():
                continue
            sizes[member.name] = member.size
            if member.name.endswith(".json"):
                if member.size > 1024 * 1024:
                    raise ValueError(f"Oversized JSON member: {member.name}")
                documents[member.name] = json.load(archive.extractfile(member))

    manifest = documents["manifest.json"]
    if len(manifest) != 1:
        raise ValueError("Expected exactly one image in the Docker archive")
    image = manifest[0]
    config = documents[image["Config"]]
    if config["os"] != "linux" or config["architecture"] != ARCHITECTURES[platform]:
        raise ValueError(f"Archive platform does not match {platform}")
    layers = image["Layers"]
    if not layers or len(set(layers)) != len(layers):
        raise ValueError("Expected a nonempty list of unique layers")
    return sum(sizes[layer] for layer in layers)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image")
    parser.add_argument("platform", choices=ARCHITECTURES)
    parser.add_argument("archive", type=Path)
    parser.add_argument(
        "--baselines",
        type=Path,
        default=Path(__file__).with_name("container-image-sizes.json"),
    )
    args = parser.parse_args()
    try:
        baselines = json.loads(args.baselines.read_text())
        baseline = baselines["images"][args.image][args.platform]["uncompressed_bytes"]
        if type(baseline) is not int or baseline <= 0:
            raise ValueError("Baseline must be a positive integer byte count")
        actual = measure_archive(args.archive, args.platform)
        # Integer arithmetic keeps the boundary exactly at 125% of the baseline.
        maximum = baseline * 125 // 100
        message = (
            f"{args.image} ({args.platform}): {actual} uncompressed layer bytes; "
            f"baseline {baseline}, maximum {maximum} (+25%)"
        )
        print(message, flush=True)
        if actual > maximum:
            print(
                "::error::Container image exceeds its size budget. "
                "Investigate unexpected runtime dependencies or debuginfo before "
                "deliberately updating the measured baseline.",
                file=sys.stderr,
            )
            return 1
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError) as error:
        print(f"::error::Cannot check container image size: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
