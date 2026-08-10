from __future__ import annotations
import unittest
from src.tool_authority import DispatchStatus, Grant, ToolAuthorityMatrix, ToolSchema


class ToolTests(unittest.TestCase):
    def setUp(self):
        self.m = ToolAuthorityMatrix(
            {Grant("agent", "search", "public"), Grant("agent", "read", "*")},
            {
                "search": ToolSchema("search", ("q",), ("limit",)),
                "read": ToolSchema("read", ("path",)),
            },
        )

    def test_default_deny(self):
        r = self.m.dispatch("agent", "search", {"q": "x"}, request_id="1", scope="private")
        self.assertEqual(r.reason, "DEFAULT_DENY")

    def test_unknown_tool_is_explicit(self):
        r = self.m.dispatch("agent", "shell", {}, request_id="2")
        self.assertEqual(r.reason, "UNKNOWN_TOOL")

    def test_missing_args(self):
        r = self.m.dispatch("agent", "search", {}, request_id="3", scope="public")
        self.assertEqual(r.reason, "MISSING_ARGS")

    def test_argument_smuggling_refused(self):
        r = self.m.dispatch("agent", "search", {"q": "x", "shell": "rm -rf /"}, request_id="4", scope="public")
        self.assertEqual(r.reason, "UNEXPECTED_ARGS")

    def test_scoped_allow(self):
        r = self.m.dispatch("agent", "search", {"q": "x", "limit": 5}, request_id="5", scope="public")
        self.assertEqual(r.status, DispatchStatus.ALLOW)
        self.assertEqual(len(r.fingerprint), 64)

    def test_wildcard_grant(self):
        r = self.m.dispatch("agent", "read", {"path": "/safe"}, request_id="6", scope="repo:a")
        self.assertEqual(r.status, DispatchStatus.ALLOW)

    def test_replay_refused_after_allow(self):
        first = self.m.dispatch("agent", "search", {"q": "x"}, request_id="7", scope="public")
        second = self.m.dispatch("agent", "search", {"q": "x"}, request_id="7", scope="public")
        self.assertEqual(first.status, DispatchStatus.ALLOW)
        self.assertEqual(second.reason, "REPLAY")

    def test_receipt_binds_arguments(self):
        a = ToolAuthorityMatrix({Grant("agent", "search", "public")}, {"search": ToolSchema("search", ("q",))})
        b = ToolAuthorityMatrix({Grant("agent", "search", "public")}, {"search": ToolSchema("search", ("q",))})
        r1 = a.dispatch("agent", "search", {"q": "alpha"}, request_id="same", scope="public")
        r2 = b.dispatch("agent", "search", {"q": "beta"}, request_id="same", scope="public")
        self.assertNotEqual(r1.fingerprint, r2.fingerprint)


if __name__ == "__main__":
    unittest.main()
