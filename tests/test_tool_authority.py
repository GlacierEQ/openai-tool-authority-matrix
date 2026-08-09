from __future__ import annotations
import unittest
from src.tool_authority import DispatchStatus, ToolAuthorityMatrix, ToolSchema

class ToolTests(unittest.TestCase):
    def setUp(self):
        self.m = ToolAuthorityMatrix(
            {("agent", "search")},
            {"search": ToolSchema("search", ("q",))},
        )

    def test_deny(self):
        r = self.m.dispatch("agent", "shell", {})
        self.assertEqual(r.reason, "DEFAULT_DENY")

    def test_missing_args(self):
        r = self.m.dispatch("agent", "search", {})
        self.assertEqual(r.reason, "MISSING_ARGS")

    def test_allow(self):
        r = self.m.dispatch("agent", "search", {"q": "x"})
        self.assertEqual(r.status, DispatchStatus.ALLOW)

if __name__ == "__main__":
    unittest.main()
