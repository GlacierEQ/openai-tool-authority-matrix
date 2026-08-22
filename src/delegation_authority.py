"""Capability-scoped delegation authority with attenuation and replay protection.

This module authorizes local capability delegation. It does not execute tools or
claim OpenAI infrastructure behavior. Tokens are tamper-evident HMAC envelopes
bound to explicit tool, scope, argument fields, expiry, use ceilings, and depth.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from enum import Enum
import hashlib
import hmac
import json
from math import isfinite
import threading
from typing import Iterable, Mapping, Any

EVIDENCE_STATE = "EXECUTABLE_LOCAL_DELEGATION_AUTHORITY"


class AuthorityStatus(str, Enum):
    ALLOW = "ALLOW"
    REFUSE = "REFUSE"


@dataclass(frozen=True)
class CapabilityToken:
    token_id: str
    issuer: str
    subject: str
    tool: str
    scope: str
    allowed_fields: tuple[str, ...]
    max_uses: int
    expires_at: float
    depth: int = 0
    parent_token_id: str | None = None
    signature: str = ""

    def unsigned_dict(self) -> dict[str, object]:
        row = asdict(self)
        row.pop("signature", None)
        row["allowed_fields"] = list(self.allowed_fields)
        return row


@dataclass(frozen=True)
class AuthorityReceipt:
    status: AuthorityStatus
    reason: str | None
    request_id: str
    token_id: str
    subject: str
    tool: str
    scope: str
    use_number: int | None
    evidence_state: str = EVIDENCE_STATE

    def as_dict(self) -> dict[str, object]:
        row = asdict(self)
        row["status"] = self.status.value
        return row

    @property
    def fingerprint(self) -> str:
        body = json.dumps(self.as_dict(), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(body.encode()).hexdigest()


class DelegationAuthority:
    """Mint and attenuate capability tokens without privilege amplification."""

    def __init__(self, secret: bytes, *, max_depth: int = 4) -> None:
        if not isinstance(secret, bytes) or len(secret) < 16:
            raise ValueError("secret must contain at least 16 bytes")
        if max_depth < 0:
            raise ValueError("max_depth must be non-negative")
        self._secret = secret
        self.max_depth = max_depth
        self._revoked: set[str] = set()
        self._seen_request_ids: set[str] = set()
        self._uses: dict[str, int] = {}
        self._lock = threading.RLock()

    @staticmethod
    def _normalize_fields(fields: Iterable[str]) -> tuple[str, ...]:
        normalized = tuple(sorted({str(field).strip() for field in fields if str(field).strip()}))
        if not normalized:
            raise ValueError("allowed_fields must not be empty")
        return normalized

    @staticmethod
    def _validate_common(
        *,
        token_id: str,
        issuer: str,
        subject: str,
        tool: str,
        scope: str,
        max_uses: int,
        expires_at: float,
    ) -> None:
        for name, value in {
            "token_id": token_id,
            "issuer": issuer,
            "subject": subject,
            "tool": tool,
            "scope": scope,
        }.items():
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must be non-empty")
        if max_uses <= 0:
            raise ValueError("max_uses must be positive")
        if not isfinite(expires_at) or expires_at <= 0:
            raise ValueError("expires_at must be finite and positive")

    def _sign(self, token: CapabilityToken) -> str:
        encoded = json.dumps(
            token.unsigned_dict(), sort_keys=True, separators=(",", ":")
        ).encode()
        return hmac.new(self._secret, encoded, hashlib.sha256).hexdigest()

    def _seal(self, token: CapabilityToken) -> CapabilityToken:
        return replace(token, signature=self._sign(token))

    def verify_signature(self, token: CapabilityToken) -> bool:
        expected = self._sign(replace(token, signature=""))
        return hmac.compare_digest(expected, token.signature)

    def mint_root(
        self,
        *,
        token_id: str,
        issuer: str,
        subject: str,
        tool: str,
        scope: str,
        allowed_fields: Iterable[str],
        max_uses: int,
        expires_at: float,
    ) -> CapabilityToken:
        self._validate_common(
            token_id=token_id,
            issuer=issuer,
            subject=subject,
            tool=tool,
            scope=scope,
            max_uses=max_uses,
            expires_at=expires_at,
        )
        return self._seal(
            CapabilityToken(
                token_id=token_id.strip(),
                issuer=issuer.strip(),
                subject=subject.strip(),
                tool=tool.strip(),
                scope=scope.strip(),
                allowed_fields=self._normalize_fields(allowed_fields),
                max_uses=max_uses,
                expires_at=float(expires_at),
            )
        )

    def delegate(
        self,
        parent: CapabilityToken,
        *,
        token_id: str,
        subject: str,
        scope: str,
        allowed_fields: Iterable[str],
        max_uses: int,
        expires_at: float,
    ) -> CapabilityToken:
        if not self.verify_signature(parent):
            raise ValueError("INVALID_PARENT_SIGNATURE")
        if parent.token_id in self._revoked:
            raise ValueError("PARENT_REVOKED")
        child_fields = self._normalize_fields(allowed_fields)
        self._validate_common(
            token_id=token_id,
            issuer=parent.subject,
            subject=subject,
            tool=parent.tool,
            scope=scope,
            max_uses=max_uses,
            expires_at=expires_at,
        )
        if parent.depth >= self.max_depth:
            raise ValueError("DELEGATION_DEPTH_EXCEEDED")
        if parent.scope != "*" and scope != parent.scope:
            raise ValueError("SCOPE_AMPLIFICATION")
        if not set(child_fields).issubset(parent.allowed_fields):
            raise ValueError("FIELD_AMPLIFICATION")
        if max_uses > parent.max_uses:
            raise ValueError("USE_AMPLIFICATION")
        if expires_at > parent.expires_at:
            raise ValueError("EXPIRY_AMPLIFICATION")

        return self._seal(
            CapabilityToken(
                token_id=token_id.strip(),
                issuer=parent.subject,
                subject=subject.strip(),
                tool=parent.tool,
                scope=scope.strip(),
                allowed_fields=child_fields,
                max_uses=max_uses,
                expires_at=float(expires_at),
                depth=parent.depth + 1,
                parent_token_id=parent.token_id,
            )
        )

    def revoke(self, token_id: str) -> None:
        if not token_id.strip():
            raise ValueError("token_id must be non-empty")
        with self._lock:
            self._revoked.add(token_id.strip())

    @staticmethod
    def _scope_allows(token_scope: str, requested_scope: str) -> bool:
        return token_scope == "*" or token_scope == requested_scope

    def _receipt(
        self,
        status: AuthorityStatus,
        reason: str | None,
        *,
        request_id: str,
        token: CapabilityToken,
        tool: str,
        scope: str,
        use_number: int | None = None,
    ) -> AuthorityReceipt:
        return AuthorityReceipt(
            status=status,
            reason=reason,
            request_id=request_id,
            token_id=token.token_id,
            subject=token.subject,
            tool=tool,
            scope=scope,
            use_number=use_number,
        )

    def authorize(
        self,
        token: CapabilityToken,
        *,
        request_id: str,
        tool: str,
        scope: str,
        args: Mapping[str, Any],
        now: float,
    ) -> AuthorityReceipt:
        normalized_request = request_id.strip() if isinstance(request_id, str) else ""
        if not normalized_request:
            return self._receipt(
                AuthorityStatus.REFUSE,
                "REQUEST_ID_REQUIRED",
                request_id="",
                token=token,
                tool=tool,
                scope=scope,
            )
        if not isfinite(now):
            return self._receipt(
                AuthorityStatus.REFUSE,
                "INVALID_TIME",
                request_id=normalized_request,
                token=token,
                tool=tool,
                scope=scope,
            )

        with self._lock:
            if normalized_request in self._seen_request_ids:
                return self._receipt(
                    AuthorityStatus.REFUSE,
                    "REPLAY",
                    request_id=normalized_request,
                    token=token,
                    tool=tool,
                    scope=scope,
                )
            self._seen_request_ids.add(normalized_request)

            if not self.verify_signature(token):
                return self._receipt(
                    AuthorityStatus.REFUSE,
                    "INVALID_SIGNATURE",
                    request_id=normalized_request,
                    token=token,
                    tool=tool,
                    scope=scope,
                )
            if token.token_id in self._revoked:
                return self._receipt(
                    AuthorityStatus.REFUSE,
                    "REVOKED",
                    request_id=normalized_request,
                    token=token,
                    tool=tool,
                    scope=scope,
                )
            if now >= token.expires_at:
                return self._receipt(
                    AuthorityStatus.REFUSE,
                    "EXPIRED",
                    request_id=normalized_request,
                    token=token,
                    tool=tool,
                    scope=scope,
                )
            if tool != token.tool:
                return self._receipt(
                    AuthorityStatus.REFUSE,
                    "TOOL_DENIED",
                    request_id=normalized_request,
                    token=token,
                    tool=tool,
                    scope=scope,
                )
            if not self._scope_allows(token.scope, scope):
                return self._receipt(
                    AuthorityStatus.REFUSE,
                    "SCOPE_DENIED",
                    request_id=normalized_request,
                    token=token,
                    tool=tool,
                    scope=scope,
                )
            unexpected = sorted(set(args) - set(token.allowed_fields))
            if unexpected:
                return self._receipt(
                    AuthorityStatus.REFUSE,
                    "ARGUMENT_DENIED",
                    request_id=normalized_request,
                    token=token,
                    tool=tool,
                    scope=scope,
                )

            used = self._uses.get(token.token_id, 0)
            if used >= token.max_uses:
                return self._receipt(
                    AuthorityStatus.REFUSE,
                    "USE_LIMIT_EXCEEDED",
                    request_id=normalized_request,
                    token=token,
                    tool=tool,
                    scope=scope,
                    use_number=used,
                )
            use_number = used + 1
            self._uses[token.token_id] = use_number
            return self._receipt(
                AuthorityStatus.ALLOW,
                None,
                request_id=normalized_request,
                token=token,
                tool=tool,
                scope=scope,
                use_number=use_number,
            )
