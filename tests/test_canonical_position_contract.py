import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STATE = json.loads((ROOT / "machine" / "excellence-state.json").read_text(encoding="utf-8"))
POSITION = json.loads((ROOT / "machine" / "canonical-position.json").read_text(encoding="utf-8"))
CAPABILITIES = json.loads((ROOT / "machine" / "capabilities.json").read_text(encoding="utf-8"))


class CanonicalPositionContractTests(unittest.TestCase):
    def test_evolving_state_is_gate_complete(self):
        self.assertEqual(STATE["principal_state"], "EVOLVING")
        self.assertEqual(STATE["gates"]["CANONICAL_POSITION_RESOLVED"]["status"], "PASS")
        self.assertEqual(STATE["gates"]["EVOLUTION_CURSOR_DEFINED"]["status"], "PASS")
        self.assertEqual(STATE["canonical_position_ref"], "machine/canonical-position.json")

    def test_specialist_identity_and_lineage_are_preserved(self):
        self.assertEqual(POSITION["canonical_identity"], "tool-authority-matrix")
        policy = POSITION["integration_policy"]
        self.assertTrue(policy["preserve_repository_identity"])
        self.assertTrue(policy["preserve_lineage"])
        self.assertTrue(policy["absorption_requires_functional_equivalence"])
        self.assertTrue(policy["absorption_requires_proof_equivalence"])

    def test_capabilities_name_repository_native_authority_mechanisms(self):
        self.assertEqual(CAPABILITIES["capability_family"], "scoped_replay_safe_tool_authority")
        capabilities = set(CAPABILITIES["capabilities"])
        self.assertIn("default-deny-role-tool-authorization", capabilities)
        self.assertIn("unexpected-argument-refusal", capabilities)
        self.assertIn("single-use-request-identities", capabilities)
        self.assertIn("concurrent-request-reservation", capabilities)
        self.assertNotIn("hyper-scaling", capabilities)

    def test_budget_edge_is_complementary_not_integrated(self):
        self.assertEqual(POSITION["relationships"][0]["repository"], "GlacierEQ/openai-reasoning-budget-futures")
        self.assertEqual(POSITION["relationships"][0]["integration_state"], "NOT_CLAIMED")

    def test_execution_and_public_boundaries_are_explicit(self):
        self.assertIn("authorization kernel does not itself execute tools", POSITION["nonclaims"])
        self.assertIn("No OpenAI adoption", CAPABILITIES["truth_boundary"])
        self.assertIn("provider adapter", POSITION["next_evolution"])


if __name__ == "__main__":
    unittest.main()
