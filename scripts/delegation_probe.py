#!/usr/bin/env python3
"""Execute bounded capability delegation scenarios and emit a content-hashed receipt."""
from __future__ import annotations

import argparse
from dataclasses import replace
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.delegation_authority import DelegationAuthority  # noqa: E402


def execute() -> dict[str, object]:
    authority = DelegationAuthority(b"portfolio-proof-key-32-bytes-long!!", max_depth=2)
    root = authority.mint_root(
        token_id="root-deploy",
        issuer="operator",
        subject="orchestrator",
        tool="deploy",
        scope="prod",
        allowed_fields=("artifact", "region"),
        max_uses=2,
        expires_at=200.0,
    )
    child = authority.delegate(
        root,
        token_id="child-deploy",
        subject="release-agent",
        scope="prod",
        allowed_fields=("artifact",),
        max_uses=1,
        expires_at=150.0,
    )

    allowed = authority.authorize(
        child,
        request_id="release-001",
        tool="deploy",
        scope="prod",
        args={"artifact": "candidate.tar"},
        now=100.0,
    )
    replay = authority.authorize(
        child,
        request_id="release-001",
        tool="deploy",
        scope="prod",
        args={"artifact": "candidate.tar"},
        now=100.0,
    )
    exhausted = authority.authorize(
        child,
        request_id="release-002",
        tool="deploy",
        scope="prod",
        args={"artifact": "candidate-2.tar"},
        now=101.0,
    )
    tampered = authority.authorize(
        replace(root, allowed_fields=("artifact", "region", "secret")),
        request_id="tampered-001",
        tool="deploy",
        scope="prod",
        args={"artifact": "candidate.tar"},
        now=100.0,
    )

    amplification = {}
    for label, kwargs in {
        "field": {
            "scope": "prod",
            "allowed_fields": ("artifact", "secret"),
            "max_uses": 1,
            "expires_at": 140.0,
        },
        "scope": {
            "scope": "staging",
            "allowed_fields": ("artifact",),
            "max_uses": 1,
            "expires_at": 140.0,
        },
        "uses": {
            "scope": "prod",
            "allowed_fields": ("artifact",),
            "max_uses": 3,
            "expires_at": 140.0,
        },
        "expiry": {
            "scope": "prod",
            "allowed_fields": ("artifact",),
            "max_uses": 1,
            "expires_at": 250.0,
        },
    }.items():
        try:
            authority.delegate(
                root,
                token_id=f"bad-{label}",
                subject="bad-agent",
                **kwargs,
            )
        except ValueError as exc:
            amplification[label] = str(exc)
        else:
            amplification[label] = "UNEXPECTED_ALLOW"

    return {
        "schema": "glaciereq.openai-delegation-authority-scenario.v1",
        "evidence_state": "EXECUTABLE_LOCAL_DELEGATION_AUTHORITY",
        "root": root.unsigned_dict(),
        "child": child.unsigned_dict(),
        "decisions": {
            "allowed": allowed.as_dict(),
            "replay": replay.as_dict(),
            "use_limit": exhausted.as_dict(),
            "tamper": tampered.as_dict(),
        },
        "receipt_fingerprints": {
            "allowed": allowed.fingerprint,
            "replay": replay.fingerprint,
            "use_limit": exhausted.fingerprint,
            "tamper": tampered.fingerprint,
        },
        "amplification_refusals": amplification,
        "claims_not_established": [
            "OpenAI affiliation or internal architecture",
            "OpenAI or ChatGPT tool execution",
            "production identity-provider integration",
            "production key management",
            "external side-effect execution",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args()

    payload = execute()
    decisions = payload["decisions"]
    expected = {
        "allowed": ("ALLOW", None),
        "replay": ("REFUSE", "REPLAY"),
        "use_limit": ("REFUSE", "USE_LIMIT_EXCEEDED"),
        "tamper": ("REFUSE", "INVALID_SIGNATURE"),
    }
    actual = {
        name: (row["status"], row["reason"])
        for name, row in decisions.items()
    }
    if actual != expected:
        raise SystemExit(f"unexpected delegation decisions: {actual}")
    if payload["amplification_refusals"] != {
        "field": "FIELD_AMPLIFICATION",
        "scope": "SCOPE_AMPLIFICATION",
        "uses": "USE_AMPLIFICATION",
        "expiry": "EXPIRY_AMPLIFICATION",
    }:
        raise SystemExit(f"amplification check failed: {payload['amplification_refusals']}")

    encoded = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(encoded)
    digest = hashlib.sha256(encoded).hexdigest()

    receipt = {
        "schema": "glaciereq.openai-delegation-authority-receipt.v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "repository": os.environ.get(
            "GITHUB_REPOSITORY", "GlacierEQ/openai-tool-authority-matrix"
        ),
        "commit": os.environ.get("GITHUB_SHA", "local"),
        "artifact": str(args.output),
        "artifact_sha256": digest,
        "verified_state": "DELEGATION_ATTENUATION_EXECUTED",
        "decisions": actual,
    }
    args.receipt.parent.mkdir(parents=True, exist_ok=True)
    args.receipt.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
