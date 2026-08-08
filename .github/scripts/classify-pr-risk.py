#!/usr/bin/env python3
"""Classify Fedimint pull-request paths and emit advisory guardrail signals."""

from __future__ import annotations

import argparse
import fnmatch
import json
import re
from pathlib import Path


ROUTES = {
    "consensus": {
        "patterns": (
            "fedimint-server/src/consensus/*",
            "fedimint-core/src/encoding/*",
            "fedimint-core/src/core.rs",
            "fedimint-core/src/epoch.rs",
            "fedimint-core/src/session_outcome.rs",
            "fedimint-core/src/transaction.rs",
            "fedimint-core/src/module/mod.rs",
            "fedimint-core/src/module/registry.rs",
            "fedimint-server-core/src/lib.rs",
            "fedimint-server-core/src/migration.rs",
            "modules/fedimint-*-server/src/*",
            "fedimint-server/src/config/dkg*",
            "crypto/*",
        ),
        "human_review_required": True,
        "rationale": (
            "Review determinism, mixed-version behavior, encoding compatibility, "
            "untrusted inputs, and peer state divergence."
        ),
    },
    "database_persistence": {
        "patterns": (
            "db/*",
            "*/db/*",
            "*/db.rs",
            "*/*/db/*",
            "*/*/db.rs",
            "*/*/*/db/*",
            "*/*/*/db.rs",
            "*-db/*",
            "*/*-db/*",
            "*/migration.rs",
            "*/*/migration.rs",
            "*/*/*/migration.rs",
            "*/migration_tests.rs",
            "*/*/migration_tests.rs",
            "*/*/*/migration_tests.rs",
            "*/migrations/*",
            "*/*/migrations/*",
            "*/*/*/migrations/*",
        ),
        "human_review_required": True,
        "rationale": (
            "Review transaction boundaries, crash/cancellation atomicity, migration "
            "versions, snapshots, and upgrade compatibility."
        ),
    },
    "gateway_funds": {
        "patterns": (
            "gateway/fedimint-lightning/*",
            "gateway/fedimint-gateway-server/*",
            "gateway/fedimint-gateway-client/*",
            "gateway/ln-gateway/*",
            "modules/fedimint-gw-client/*",
            "modules/fedimint-ln-client/*",
            "modules/fedimint-lnv2-client/*",
            "modules/fedimint-ln-server/*",
            "modules/fedimint-lnv2-server/*",
        ),
        "human_review_required": True,
        "rationale": (
            "Trace authentication, payment uniqueness scope, fees, retries, refunds, "
            "and every success/failure fund movement."
        ),
    },
    "client_state_machine": {
        "patterns": (
            "fedimint-client/src/sm/*",
            "fedimint-client-module/src/transaction/*",
            "modules/*-client/src/*_sm.rs",
            "modules/*-client/src/*sm/*",
            "modules/*-client/src/state_machine*",
        ),
        "human_review_required": False,
        "rationale": (
            "Review persisted transitions, cancellation safety, retry classification, "
            "idempotency, and finite terminal states."
        ),
    },
    "api_or_persisted_format": {
        "patterns": (
            "fedimint-api-client/*",
            "fedimint-client-rpc/*",
            "fedimint-core/src/api.rs",
            "fedimint-core/src/module/*",
            "modules/*-common/*",
            "*/src/api.rs",
            "*/src/api/*",
        ),
        "human_review_required": False,
        "rationale": (
            "Review public consumers, persisted JSON, wire formats, defaults, version "
            "negotiation, and rolling upgrades."
        ),
    },
    "wasm_portability": {
        "patterns": (
            "fedimint-wasm*",
            "fedimint-wasm*/*",
            "bindings/*",
            "*/wasm/*",
            "*/*wasm*",
        ),
        "human_review_required": False,
        "rationale": (
            "Review WASM-compatible time, task, filesystem, networking, and test behavior."
        ),
    },
    "infra_release_supply_chain": {
        "patterns": (
            ".github/*",
            "flake.nix",
            "flake.lock",
            "nix/*",
            "docker/*",
            "scripts/*",
            "misc/*",
            "fedimint-startos/*",
            "gatewayd-startos/*",
            "Cargo.toml",
            "Cargo.lock",
        ),
        "human_review_required": False,
        "rationale": (
            "Review permissions, untrusted inputs, supply-chain provenance, release "
            "artifacts, portability, and whether CI exercises the changed configuration."
        ),
    },
}

RAW_REQWEST_RE = re.compile(
    r"\breqwest::(?:Client::new|Client::builder|ClientBuilder::new)\s*\("
)
TIMEOUT_RE = re.compile(r"\.(?:connect_)?timeout\s*\(")
MIGRATION_EVIDENCE_RE = re.compile(
    r"\b(migrat(?:e|ion)s?|db[_ ]?version|snapshots?|upgrade[_ -]?tests?)\b",
    re.IGNORECASE,
)


def read_changed_files(path: Path) -> list[str]:
    files = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        value = raw.strip().removeprefix("./")
        if value and "\0" not in value:
            files.append(value)
    return sorted(set(files))


def path_matches(path: str, patterns: tuple[str, ...]) -> bool:
    return any(fnmatch.fnmatchcase(path, pattern) for pattern in patterns)


def added_lines_by_file(diff: str) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    current_file: str | None = None

    for line in diff.splitlines():
        if line.startswith("+++ "):
            marker = line[4:].split("\t", 1)[0]
            if marker == "/dev/null":
                current_file = None
            else:
                current_file = marker.removeprefix("b/")
                result.setdefault(current_file, [])
        elif (
            current_file is not None
            and line.startswith("+")
            and not line.startswith("+++")
        ):
            result[current_file].append(line[1:])

    return result


def classify(files: list[str], diff: str = "") -> dict:
    routes = {}
    human_review_reasons = []

    for name, config in ROUTES.items():
        matched = [path for path in files if path_matches(path, config["patterns"])]
        active = bool(matched)
        route = {
            "active": active,
            "human_review_required": bool(config["human_review_required"] and active),
            "matched_files": matched,
            "rationale": config["rationale"],
        }
        routes[name] = route
        if route["human_review_required"]:
            human_review_reasons.append(name)

    added = added_lines_by_file(diff)
    guardrails = []

    raw_reqwest_files = []
    for path, lines in added.items():
        joined = "\n".join(lines)
        if RAW_REQWEST_RE.search(joined) and not TIMEOUT_RE.search(joined):
            raw_reqwest_files.append(path)
    if raw_reqwest_files:
        guardrails.append(
            {
                "id": "outbound-http-timeout",
                "severity": "advisory",
                "matched_files": sorted(raw_reqwest_files),
                "message": (
                    "New raw reqwest client construction has no timeout in the added "
                    "lines. Verify finite connect and operation deadlines, or document "
                    "why a streaming client needs an exception."
                ),
            }
        )

    if routes["database_persistence"]["active"]:
        evidence_paths = [
            path
            for path in files
            if MIGRATION_EVIDENCE_RE.search(path)
            or "/tests/" in f"/{path}"
            or path.endswith("/tests.rs")
        ]
        evidence_text = "\n".join(line for lines in added.values() for line in lines)
        if not evidence_paths and not MIGRATION_EVIDENCE_RE.search(evidence_text):
            guardrails.append(
                {
                    "id": "database-migration-evidence",
                    "severity": "advisory",
                    "matched_files": routes["database_persistence"]["matched_files"],
                    "message": (
                        "Database/persistence paths changed without obvious migration, "
                        "snapshot, or upgrade-test evidence. Verify whether persisted "
                        "data changes and require the corresponding compatibility proof."
                    ),
                }
            )

    active_routes = [name for name, route in routes.items() if route["active"]]
    return {
        "schema_version": 1,
        "changed_files": files,
        "active_routes": active_routes,
        "routes": routes,
        "requires_human_review": bool(human_review_reasons),
        "human_review_reasons": human_review_reasons,
        "guardrails": guardrails,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--files", type=Path, required=True)
    parser.add_argument("--diff", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    files = read_changed_files(args.files)
    diff = args.diff.read_text(encoding="utf-8") if args.diff else ""
    encoded = json.dumps(classify(files, diff), indent=2, sort_keys=True) + "\n"

    if args.output:
        args.output.write_text(encoded, encoding="utf-8")
    else:
        print(encoded, end="")


if __name__ == "__main__":
    main()
