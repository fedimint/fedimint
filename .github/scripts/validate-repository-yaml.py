#!/usr/bin/env python3
"""Parse tracked YAML files and reject duplicate mapping keys."""

from __future__ import annotations

import argparse
import subprocess
from pathlib import Path

import yaml
from yaml.constructor import ConstructorError


class UniqueKeyLoader(yaml.SafeLoader):
    """Safe YAML loader that treats duplicate keys as errors."""


def construct_unique_mapping(
    loader: UniqueKeyLoader, node: yaml.MappingNode, deep: bool = False
) -> dict:
    loader.flatten_mapping(node)
    mapping = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in mapping
        except TypeError as error:
            raise ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "found an unhashable mapping key",
                key_node.start_mark,
            ) from error
        if duplicate:
            raise ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"found duplicate key {key!r}",
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, construct_unique_mapping
)


def tracked_yaml_files() -> list[Path]:
    process = subprocess.run(
        ["git", "ls-files", "-z", "--", "*.yml", "*.yaml"],
        check=True,
        stdout=subprocess.PIPE,
    )
    return sorted(
        Path(value.decode("utf-8", errors="surrogateescape"))
        for value in process.stdout.split(b"\0")
        if value
    )


def validate_file(path: Path) -> None:
    with path.open(encoding="utf-8") as stream:
        documents = list(yaml.load_all(stream, Loader=UniqueKeyLoader))
    if not documents:
        raise ValueError(f"{path}: YAML file is empty")
    for index, document in enumerate(documents, start=1):
        if not isinstance(document, dict):
            raise ValueError(f"{path}: YAML document {index} must be a mapping")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("paths", nargs="*", type=Path)
    args = parser.parse_args()

    paths = args.paths or tracked_yaml_files()
    for path in paths:
        validate_file(path)
    print(f"Validated {len(paths)} YAML files")


if __name__ == "__main__":
    main()
