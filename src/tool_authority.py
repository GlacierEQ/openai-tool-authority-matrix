"""Tool authority matrix — default-deny, scoped, replay-safe tool dispatch."""
from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping


def digest(obj: object) -> str:
    return hashlib.sha256(
        json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str).encode()
    ).hexdigest()


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
    * every supplied argument must be explicitly allowed;
    * grants may be scope-bound;
    * explicit request IDs are one-shot across allow and refuse decisions;
    * request-ID reservation is synchronized for concurrent callers;
    * receipts bind role, tool, scope, normalized arguments and decision details.
    """

    def __init__(
        self,
        grants: set[tuple[str, str]] | set[Grant],
        schemas: dict[str, ToolSchema],
    ) -> None:
        normalized: set[Grant] = set()
        for grant in grants:
            if isinstance(grant, Grant):
                normalized.add(grant)
            else:
                normalized.add(Grant(grant[0], grant[1]))
        self.grants = normalized
        self.schemas = schemas
        self._seen_request_ids: set[str] = set()
        self._request_lock = threading.Lock()

    def _receipt(
        self,
        status: DispatchStatus,
        reason: str | None,
        request_id: str,
        role: str,
        tool: str,
        scope: str,
        args: Mapping[str, Any],
        *,
        details: Mapping[str, Any] | None = None,
    ) -> DispatchReceipt:
        body = {
            "status": status.value,
            "reason": reason,
            "request_id": request_id,
            "role": role,
            "tool": tool,
            "scope": scope,
            "args": dict(args),
            "details": dict(details or {}),
        }
        return DispatchReceipt(status, reason, digest(body), request_id)

    def dispatch(
        self,
        role: str,
        tool: str,
        args: Mapping[str, Any],
        *,
        request_id: str | None = None,
        scope: str = "*",
    ) -> DispatchReceipt:
        normalized_request_id = request_id.strip() if isinstance(request_id, str) else ""
        if not normalized_request_id:
            return self._receipt(
                DispatchStatus.REFUSE,
                "REQUEST_ID_REQUIRED",
                "",
                role,
                tool,
                scope,
                args,
            )

        with self._request_lock:
            if normalized_request_id in self._seen_request_ids:
                return self._receipt(
                    DispatchStatus.REFUSE,
                    "REPLAY",
                    normalized_request_id,
                    role,
                    tool,
                    scope,
                    args,
                )
            # A request ID is consumed on first use regardless of decision. This prevents
            # retrying a refused identifier with changed arguments until it becomes allowed.
            self._seen_request_ids.add(normalized_request_id)

        schema = self.schemas.get(tool)
        if schema is None:
            return self._receipt(
                DispatchStatus.REFUSE,
                "UNKNOWN_TOOL",
                normalized_request_id,
                role,
                tool,
                scope,
                args,
            )

        authorized = Grant(role, tool, scope) in self.grants or Grant(
            role, tool, "*"
        ) in self.grants
        if not authorized:
            return self._receipt(
                DispatchStatus.REFUSE,
                "DEFAULT_DENY",
                normalized_request_id,
                role,
                tool,
                scope,
                args,
            )

        missing = sorted(field for field in schema.required if field not in args)
        if missing:
            return self._receipt(
                DispatchStatus.REFUSE,
                "MISSING_ARGS",
                normalized_request_id,
                role,
                tool,
                scope,
                args,
                details={"missing": missing},
            )

        allowed = set(schema.required) | set(schema.allowed)
        unexpected = sorted(key for key in args if key not in allowed)
        if unexpected:
            return self._receipt(
                DispatchStatus.REFUSE,
                "UNEXPECTED_ARGS",
                normalized_request_id,
                role,
                tool,
                scope,
                args,
                details={"unexpected": unexpected},
            )

        return self._receipt(
            DispatchStatus.ALLOW,
            None,
            normalized_request_id,
            role,
            tool,
            scope,
            args,
        )
