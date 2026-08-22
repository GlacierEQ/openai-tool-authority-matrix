from dataclasses import replace
import unittest

from src.delegation_authority import (
    AuthorityStatus,
    DelegationAuthority,
)


SECRET = b"0123456789abcdef0123456789abcdef"


class DelegationAuthorityTests(unittest.TestCase):
    def authority(self, **kwargs):
        return DelegationAuthority(SECRET, **kwargs)

    def root(self, auth, **kwargs):
        defaults = dict(
            token_id="root-1",
            issuer="operator",
            subject="agent-a",
            tool="deploy",
            scope="prod",
            allowed_fields=("artifact", "region"),
            max_uses=4,
            expires_at=200.0,
        )
        defaults.update(kwargs)
        return auth.mint_root(**defaults)

    def test_bounded_narrow_delegation_allows(self):
        auth = self.authority()
        parent = self.root(auth)
        child = auth.delegate(
            parent,
            token_id="child-1",
            subject="agent-b",
            scope="prod",
            allowed_fields=("artifact",),
            max_uses=1,
            expires_at=150,
        )
        receipt = auth.authorize(
            child,
            request_id="req-1",
            tool="deploy",
            scope="prod",
            args={"artifact": "bundle.tar"},
            now=100,
        )
        self.assertEqual(receipt.status, AuthorityStatus.ALLOW)
        self.assertEqual(receipt.use_number, 1)
        self.assertEqual(child.parent_token_id, parent.token_id)
        self.assertEqual(child.depth, 1)
        self.assertEqual(len(receipt.fingerprint), 64)

    def test_delegation_cannot_amplify_scope_or_fields(self):
        auth = self.authority()
        parent = self.root(auth)
        with self.assertRaisesRegex(ValueError, "SCOPE_AMPLIFICATION"):
            auth.delegate(
                parent,
                token_id="bad-scope",
                subject="agent-b",
                scope="staging",
                allowed_fields=("artifact",),
                max_uses=1,
                expires_at=150,
            )
        with self.assertRaisesRegex(ValueError, "FIELD_AMPLIFICATION"):
            auth.delegate(
                parent,
                token_id="bad-field",
                subject="agent-b",
                scope="prod",
                allowed_fields=("artifact", "secret"),
                max_uses=1,
                expires_at=150,
            )

    def test_tampered_token_is_refused(self):
        auth = self.authority()
        token = self.root(auth)
        tampered = replace(token, max_uses=999)
        receipt = auth.authorize(
            tampered,
            request_id="req-tamper",
            tool="deploy",
            scope="prod",
            args={"artifact": "bundle.tar"},
            now=100,
        )
        self.assertEqual(receipt.status, AuthorityStatus.REFUSE)
        self.assertEqual(receipt.reason, "INVALID_SIGNATURE")

    def test_request_replay_is_refused(self):
        auth = self.authority()
        token = self.root(auth)
        first = auth.authorize(
            token,
            request_id="same",
            tool="deploy",
            scope="prod",
            args={"artifact": "bundle.tar"},
            now=100,
        )
        replay = auth.authorize(
            token,
            request_id="same",
            tool="deploy",
            scope="prod",
            args={"artifact": "bundle.tar"},
            now=100,
        )
        self.assertEqual(first.status, AuthorityStatus.ALLOW)
        self.assertEqual(replay.reason, "REPLAY")

    def test_expiry_use_limit_and_revocation(self):
        auth = self.authority()
        token = self.root(auth, max_uses=1, expires_at=120)
        allowed = auth.authorize(
            token,
            request_id="use-1",
            tool="deploy",
            scope="prod",
            args={"artifact": "one"},
            now=100,
        )
        limited = auth.authorize(
            token,
            request_id="use-2",
            tool="deploy",
            scope="prod",
            args={"artifact": "two"},
            now=101,
        )
        expired = auth.authorize(
            self.root(auth, token_id="expires", expires_at=110),
            request_id="expired",
            tool="deploy",
            scope="prod",
            args={"artifact": "x"},
            now=110,
        )
        revoked_token = self.root(auth, token_id="revoked")
        auth.revoke(revoked_token.token_id)
        revoked = auth.authorize(
            revoked_token,
            request_id="revoked-request",
            tool="deploy",
            scope="prod",
            args={"artifact": "x"},
            now=100,
        )
        self.assertEqual(allowed.status, AuthorityStatus.ALLOW)
        self.assertEqual(limited.reason, "USE_LIMIT_EXCEEDED")
        self.assertEqual(expired.reason, "EXPIRED")
        self.assertEqual(revoked.reason, "REVOKED")

    def test_request_cannot_broaden_tool_scope_or_arguments(self):
        auth = self.authority()
        token = self.root(auth)
        denied = []
        denied.append(
            auth.authorize(
                token,
                request_id="wrong-tool",
                tool="delete",
                scope="prod",
                args={"artifact": "x"},
                now=100,
            ).reason
        )
        denied.append(
            auth.authorize(
                token,
                request_id="wrong-scope",
                tool="deploy",
                scope="staging",
                args={"artifact": "x"},
                now=100,
            ).reason
        )
        denied.append(
            auth.authorize(
                token,
                request_id="wrong-field",
                tool="deploy",
                scope="prod",
                args={"artifact": "x", "admin": True},
                now=100,
            ).reason
        )
        self.assertEqual(denied, ["TOOL_DENIED", "SCOPE_DENIED", "ARGUMENT_DENIED"])

    def test_delegation_depth_is_bounded(self):
        auth = self.authority(max_depth=1)
        root = self.root(auth)
        child = auth.delegate(
            root,
            token_id="child",
            subject="agent-b",
            scope="prod",
            allowed_fields=("artifact",),
            max_uses=1,
            expires_at=150,
        )
        with self.assertRaisesRegex(ValueError, "DELEGATION_DEPTH_EXCEEDED"):
            auth.delegate(
                child,
                token_id="grandchild",
                subject="agent-c",
                scope="prod",
                allowed_fields=("artifact",),
                max_uses=1,
                expires_at=140,
            )


if __name__ == "__main__":
    unittest.main()
