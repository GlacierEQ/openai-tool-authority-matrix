import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STATE = json.loads((ROOT / "machine" / "excellence-state.json").read_text(encoding="utf-8"))
POSITION = json.loads((ROOT / "machine" / "apex-position.json").read_text(encoding="utf-8"))
CAPABILITIES = json.loads((ROOT / "machine" / "capabilities.json").read_text(encoding="utf-8"))


class ApexPositionContractTests(unittest.TestCase):
    def test_state_points_to_evolving_apex_position(self):
        self.assertEqual(STATE["principal_state"], "EVOLVING")
        self.assertEqual(STATE["position_ref"], "machine/apex-position.json")
        self.assertEqual(STATE["gates"]["APEX_POSITION_ACTIVE"]["status"], "PASS")
        self.assertEqual(
            STATE["gates"]["DELEGATION_ATTENUATION_IMPLEMENTED"]["status"],
            "PASS",
        )

    def test_position_names_current_authority_plane(self):
        self.assertEqual(POSITION["identity"], "delegable-tool-authority-plane")
        capabilities = set(POSITION["capabilities"])
        self.assertIn("HMAC-bound capability tokens", capabilities)
        self.assertIn("capability attenuation across delegated scope and arguments", capabilities)
        self.assertIn("revocation", capabilities)
        self.assertIn("tamper refusal", capabilities)

    def test_capability_manifest_matches_implemented_delegation(self):
        self.assertEqual(
            CAPABILITIES["capability_family"],
            "delegable_replay_safe_tool_authority",
        )
        capabilities = set(CAPABILITIES["capabilities"])
        for expected in (
            "hmac-bound-capability-tokens",
            "delegated-scope-attenuation",
            "delegated-argument-attenuation",
            "delegated-expiry-attenuation",
            "delegated-use-attenuation",
            "bounded-delegation-depth",
            "token-revocation",
            "tamper-refusal",
        ):
            self.assertIn(expected, capabilities)

    def test_reasoning_budget_sibling_remains_composable_not_absorbed(self):
        relation = POSITION["relationships"][0]
        self.assertEqual(
            relation["repository"],
            "GlacierEQ/openai-reasoning-budget-futures",
        )
        self.assertIn("complementary", relation["relationship"])
        self.assertTrue(relation["next_composition"])

    def test_truth_boundary_stops_before_external_execution(self):
        boundary = " ".join(POSITION["truth_boundary"])
        self.assertIn("no OpenAI affiliation", boundary)
        self.assertIn("does not itself execute external tools", boundary)
        self.assertIn("production KMS", boundary)


if __name__ == "__main__":
    unittest.main()
