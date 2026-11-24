import copy
import datetime as dt
import tempfile
import unittest
from pathlib import Path

from threatmod import intake
from threatmod.cli import Ctx, load_yaml, validate

ROOT = Path(__file__).resolve().parent.parent
DEMO = ROOT / "examples/intake-demo"
T = dt.date(2026, 11, 24)


class IntakeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ctx = Ctx()
        cls.req = intake.load_request(DEMO / "intake-request.yaml", cls.ctx.policy)

    def test_tier2_incomplete_package_needs_info(self):
        r = intake.evaluate(self.ctx.policy, self.req, DEMO, T)
        self.assertEqual(r["tier"], 2)
        self.assertEqual(r["state"], "needs_info")
        self.assertEqual(sorted(r["missing_package"]), ["data_inventory", "identity_permissions"])
        self.assertIn("facilitator_assigned", r["due_working_days"])

    def test_complete_package_accepted_with_routing(self):
        req = copy.deepcopy(self.req)
        req["package"].update(identity_permissions="https://example/perm", data_inventory="https://example/data")
        r = intake.evaluate(self.ctx.policy, req, DEMO, T)
        self.assertEqual(r["state"], "accepted")
        self.assertIn("facilitator", r["routing"])
        self.assertTrue(r["lead_time_ok"])

    def test_missing_attachment_and_bad_type(self):
        req = copy.deepcopy(self.req)
        req["package"]["data_flow"] = "nope.png"
        r = intake.evaluate(self.ctx.policy, req, DEMO, T)
        self.assertTrue(any("data_flow" in m for m in r["missing_package"]))
        req["package"]["data_flow"] = "intake-request.yaml"
        r = intake.evaluate(self.ctx.policy, req, DEMO, T)
        self.assertTrue(any("unexpected type" in w for w in r["warnings"]))

    def test_lead_time_warning_and_emergency(self):
        req = copy.deepcopy(self.req)
        req["package"].update(identity_permissions="https://x", data_inventory="https://y")
        req["dev_start"] = "2026-11-25"
        r = intake.evaluate(self.ctx.policy, req, DEMO, T)
        self.assertFalse(r["lead_time_ok"])
        req["emergency"] = True
        r = intake.evaluate(self.ctx.policy, req, DEMO, T)
        self.assertTrue(r["lead_time_ok"]); self.assertTrue(r["emergency"])
        self.assertEqual(set(r["due_working_days"]), {"triage", "remodel"})

    def test_missing_required_field(self):
        req = copy.deepcopy(self.req)
        req["owner"] = ""
        r = intake.evaluate(self.ctx.policy, req, DEMO, T)
        self.assertEqual(r["state"], "needs_info")
        self.assertIn("missing field: owner", r["problems"])

    def test_issue_body_parses_to_tier0_and_valid_model(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = intake.intake(self.ctx, DEMO / "issue-body.md", "TM-NME-53002", Path(tmp) / "m", [], T,
                              issue_title="[Intake] Copy-to-clipboard on host pool settings")
            self.assertEqual((r["tier"], r["state"]), (0, "closed_tier0"))
            doc = load_yaml(Path(r["model_path"]))
            self.assertEqual(doc["feature"]["title"], "Copy-to-clipboard on host pool settings")
            self.assertEqual(doc["feature"]["repositories"], ["nerdio/nme-web"])
            self.assertEqual({f.rule for f in validate(self.ctx, doc, "design", T) if f.level == "error"}, set())

    def test_issue_body_yes_answers_raise_tier(self):
        body = (DEMO / "issue-body.md").read_text().replace(
            "### Triage 6 — Does the feature create, modify or grant privileged permissions in customer Azure / Entra ID tenants?\n\nNo",
            "### Triage 6 — Does the feature create, modify or grant privileged permissions in customer Azure / Entra ID tenants?\n\nYes")
        req = intake.parse_issue_body(body, self.ctx.policy)
        self.assertTrue(req["triage"]["privileged_azure_operation"])
        r = intake.evaluate(self.ctx.policy, req, DEMO, T)
        self.assertEqual(r["tier"], 2); self.assertEqual(r["state"], "needs_info")

    def test_intake_writes_model_and_copies_attachments(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "tm"
            r = intake.intake(self.ctx, DEMO / "intake-request.yaml", "TM-NMM-49870", out, [DEMO / "bulk-policy-dfd.png"], T)
            self.assertTrue((out / "inputs/bulk-policy-dfd.png").exists())
            self.assertTrue((out / "intake-request.yaml").exists())
            doc = load_yaml(out / "threat-model.yaml")
            self.assertEqual(doc["tier"], 2)
            self.assertTrue(doc["triage"]["cross_tenant_data"])
            self.assertEqual([f.rule for f in validate(self.ctx, doc, "design", T) if f.rule == "TM-SCHEMA"], [])
            self.assertIn("state needs_info", doc["references"][0])


if __name__ == "__main__":
    unittest.main()
