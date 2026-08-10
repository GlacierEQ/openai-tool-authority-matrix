"""Tool authority matrix — default-deny, scoped, replay-safe tool dispatch."""
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
    allowed: tuple[str, ...] = ()


@dataclass(frozen=True)
class Grant:
    role: str
    tool: str
    scope: str = "*"


@dataclass(frozen=True)
class DispatchReceipt:
    status: DispatchStatus
    reason: str | None
    fingerprint: str
    request_id: str


class ToolAuthorityMatrix:
    """Authorize tool dispatch without executing the tool itself.

    Security invariants:
    * default deny;
    * known schema required before authorization;
    * required and unexpected arguments are checked;
    * grants may be scope-bound;
    * request IDs are one-shot to prevent replay;
    * receipts bind role, tool, scope and normalized arguments.
    """

    def __init__(self, grants: set[tuple[str, str]] | set[Grant], schemas: dict[str, ToolSchema]):
        normalized: set[Grant] = set()
        for grant in grants:
            if isinstance(grant, Grant):
                normalized.add(grant)
            else:
                normalized.add(Grant(grant[0], grant[1]))
        self.grants = normalized
        self.schemas = schemas
        self._seen_request_ids: set[str] = set()

    def _receipt(self, status: DispatchStatus, reason: str | None, request_id: str,
                 role: str, tool: str, scope: str, args: Mapping[str, Any]) -> DispatchReceipt:
        body = {
            "status": status.value,
            "reason": reason,
            "request_id": request_id,
            "role": role,
            "tool": tool,
            "scope": scope,
            "args": dict(args),
        }
        return DispatchReceipt(status, reason, digest(body), request_id)

    def dispatch(self, role: str, tool: str, args: Mapping[str, Any], *,
                 request_id: str = "legacy", scope: str = "*") -> DispatchReceipt:
        if request_id in self._seen_request_ids:
            return self._receipt(DispatchStatus.REFUSE, "REPLAY", request_id, role, tool, scope, args)

        schema = self.schemas.get(tool)
        if schema is None:
            return self._receipt(DispatchStatus.REFUSE, "UNKNOWN_TOOL", request_id, role, tool, scope, args)

        authorized = Grant(role, tool, scope) in self.grants or Grant(role, tool, "*") in self.grants
        if not authorized:
            return self._receipt(DispatchStatus.REFUSE, "DEFAULT_DENY", request_id, role, tool, scope, args)

        missing = sorted(f for f in schema.required if f not in args)
        if missing:
            return self._receipt(DispatchStatus.REFUSE, "MISSING_ARGS", request_id, role, tool, scope, {"missing": missing})

        if schema.allowed:
            allowed = set(schema.allowed) | set(schema.required)
            unexpected = sorted(k for k in args if k not in allowed)
            if unexpected:
                return self._receipt(DispatchStatus.REFUSE, "UNEXPECTED_ARGS", request_id, role, tool, scope, {"unexpected": unexpected})

        self._seen_request_ids.add(request_id)
        return self._receipt(DispatchStatus.ALLOW, None, request_id, role, tool, scope, args)
