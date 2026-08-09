"""Tool authority matrix — default-deny tool dispatch."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping


def digest(obj: object) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


class DispatchStatus(str, Enum):
    ALLOW = "ALLOW"
    REFUSE = "REFUSE"


@dataclass(frozen=True)
class ToolSchema:
    name: str
    required: tuple[str, ...]


@dataclass(frozen=True)
class DispatchReceipt:
    status: DispatchStatus
    reason: str | None
    fingerprint: str


class ToolAuthorityMatrix:
    def __init__(self, grants: set[tuple[str, str]], schemas: dict[str, ToolSchema]):
        """grants: (role, tool_name)"""
        self.grants = set(grants)
        self.schemas = schemas

    def dispatch(self, role: str, tool: str, args: Mapping[str, Any]) -> DispatchReceipt:
        if (role, tool) not in self.grants:
            body = {"s": "REFUSE", "r": "DEFAULT_DENY"}
            return DispatchReceipt(DispatchStatus.REFUSE, "DEFAULT_DENY", digest(body))
        schema = self.schemas.get(tool)
        if schema is None:
            body = {"s": "REFUSE", "r": "UNKNOWN_TOOL"}
            return DispatchReceipt(DispatchStatus.REFUSE, "UNKNOWN_TOOL", digest(body))
        missing = [f for f in schema.required if f not in args]
        if missing:
            body = {"s": "REFUSE", "r": "MISSING_ARGS", "m": missing}
            return DispatchReceipt(DispatchStatus.REFUSE, "MISSING_ARGS", digest(body))
        body = {"s": "ALLOW", "tool": tool, "role": role}
        return DispatchReceipt(DispatchStatus.ALLOW, None, digest(body))
