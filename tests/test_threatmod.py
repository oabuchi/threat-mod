import copy
import datetime as dt
import unittest
from pathlib import Path

from threatmod.cli import Ctx, check_pr, generate, load_yaml, report, required_tier, validate

ROOT = Path(__file__).resolve().parent.parent
EXAMPLE = ROOT / "examples/tm-nmm-48211/threat-model.yaml"
TODAY = dt.date(2026, 11, 5)


def rules(findings, level="error"):
    return {f.rule for f in findings if f.level == level}


def make_release_ready(doc):
    for t in doc["threats"]:
        if t["status"] == "mitigation_planned":
            t["status"] = "mitigated"
            for m in t["mitigations"]:
                m["status"] = "implemented"
                m["evidence"] = "https://dev.azure.com/nerdio/NMM/_git/nmm-core/pullrequest/9001"
    doc["status"] = "verified"
    doc["verification"] = {
        "verified_by": {"name": "Avery SecTeam", "role": "security_team"},
        "date": "2026-11-05", "attack_surface_delta_reviewed": True, "release": "NMM 7.4",
    }
    return doc


class ThreatModTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ctx = Ctx()
        cls.base = load_yaml(EXAMPLE)

    def doc(self):
        return copy.deepcopy(self.base)

    def test_example_passes_design_gate(self):
        self.assertEqual(rules(validate(self.ctx, self.doc(), "design", TODAY)), set())

    def test_example_blocks_release_until_implemented(self):
        self.assertIn("TM-IMPLEMENTED", rules(validate(self.ctx, self.doc(), "release", TODAY)))

    def test_release_ready_passes(self):
        self.assertEqual(rules(validate(self.ctx, make_release_ready(self.doc()), "release", TODAY)), set())

    def test_stale_verification_blocks_release(self):
        d = make_release_ready(self.doc())
        self.assertIn("TM-FRESH", rules(validate(self.ctx, d, "release", TODAY + dt.timedelta(days=45))))
        d["last_updated"] = "2026-11-06"
        self.assertIn("TM-FRESH", rules(validate(self.ctx, d, "release", dt.date(2026, 11, 6))))

    def test_verification_must_be_security_team(self):
        d = make_release_ready(self.doc())
        d["verification"]["verified_by"]["role"] = "development_team"
        self.assertIn("TM-VERIFIED", rules(validate(self.ctx, d, "release", TODAY)))

    def test_triage_computes_tier(self):
        self.assertEqual(required_tier(self.ctx.policy, self.base)[0], 2)
        d = self.doc()
        d["tier"] = 1
        self.assertIn("TM-TRIAGE", rules(validate(self.ctx, d, "design", TODAY)))

    def test_tier0_needs_only_triage(self):
        d = {"schema_version": "1.0", "id": "TM-NME-1", "status": "draft", "tier": 0,
             "data_classification": "public",
             "feature": {"title": "Copy change", "product": "NME", "work_item": "x",
                         "owner": {"name": "Dev One", "role": "development_team"}},
             "triage": {q: False for q in self.ctx.policy["triage"]["questions"]}}
        self.assertEqual(rules(validate(self.ctx, d, "design", TODAY)), set())
        d["triage"]["cross_tenant_data"] = True
        self.assertIn("TM-TRIAGE", rules(validate(self.ctx, d, "design", TODAY)))

    def test_stride_gap_detected(self):
        d = self.doc()
        d["threats"] = [t for t in d["threats"] if not (t["target"] == "P1" and t["stride"] == "E")]
        self.assertIn("TM-STRIDE", rules(validate(self.ctx, d, "design", TODAY)))

    def test_generate_is_idempotent_and_closes_gaps(self):
        d = self.doc()
        d["threats"] = [t for t in d["threats"] if not (t["target"] == "P1" and t["stride"] == "E")]
        added = generate(self.ctx, d)
        self.assertTrue(added and all(t["target"] == "P1" and t["stride"] == "E" for t in added))
        self.assertEqual(generate(self.ctx, d), [])
        self.assertNotIn("TM-STRIDE", rules(validate(self.ctx, d, "design", TODAY)))

    def test_untreated_medium_threat_blocks_design(self):
        d = self.doc()
        t = next(t for t in d["threats"] if t["status"] == "mitigation_planned")
        t["status"] = "identified"
        self.assertIn("TM-TREATED", rules(validate(self.ctx, d, "design", TODAY)))

    def test_planned_mitigation_requires_work_item(self):
        d = self.doc()
        m = next(t for t in d["threats"] if t["status"] == "mitigation_planned")["mitigations"][0]
        del m["work_item"]
        self.assertIn("TM-WORKITEM", rules(validate(self.ctx, d, "design", TODAY)))

    def _accepted(self, d):
        return next(t for t in d["threats"] if t["status"] == "accepted")

    def test_self_approval_prohibited(self):
        d = self.doc()
        self._accepted(d)["acceptance"]["approved_by"] = {"name": "Jordan Example", "role": "head_of_information_security"}
        self.assertIn("TM-ACCEPTANCE", rules(validate(self.ctx, d, "design", TODAY)))

    def test_high_risk_needs_cpto_with_recommendation(self):
        d = self.doc()
        t = self._accepted(d)
        t["residual"] = {"likelihood": 4, "impact": 4}
        self.assertIn("TM-ACCEPTANCE", rules(validate(self.ctx, d, "design", TODAY)))
        t["acceptance"]["approved_by"] = {"name": "C. Executive", "role": "cpto"}
        t["acceptance"]["recommended_by"] = {"name": "Head of InfoSec (example)", "role": "head_of_information_security"}
        self.assertNotIn("TM-ACCEPTANCE", rules(validate(self.ctx, d, "design", TODAY)))

    def test_expired_acceptance(self):
        self.assertIn("TM-ACCEPTANCE", rules(validate(self.ctx, self.doc(), "design", dt.date(2027, 6, 1))))

    def test_tier2_requires_security_approval_and_arch_review(self):
        d = self.doc()
        d["approvals"][0]["approver"] = {"name": "Peer Dev", "role": "development_team"}
        del d["architectural_review"]["consent_data_subject_rights"]
        self.assertTrue({"TM-APPROVAL", "TM-ARCH-REVIEW"} <= rules(validate(self.ctx, d, "design", TODAY)))

    def test_referential_integrity(self):
        d = self.doc()
        d["data_flows"][0]["to"] = "P99"
        self.assertIn("TM-SCHEMA", rules(validate(self.ctx, d, "design", TODAY)))

    def test_report_renders(self):
        md = report(self.ctx, self.doc(), "design", TODAY)
        self.assertIn("flowchart LR", md)
        self.assertIn("✅ PASS", md)

    def test_check_pr(self):
        models = ROOT / "examples"
        ok, _ = check_pr(self.ctx, ["README.md", "src/ui/Button.tsx"], "", models)
        self.assertTrue(ok)
        ok, _ = check_pr(self.ctx, ["src/Api/WebhookController.cs"], "Adds webhook", models)
        self.assertFalse(ok)
        ok, _ = check_pr(self.ctx, ["src/Api/WebhookController.cs"], "Threat-Model: TM-NMM-48211", models)
        self.assertTrue(ok)
        ok, _ = check_pr(self.ctx, ["infra/main.bicep"], "Threat-Model: TM-NMM-00000", models)
        self.assertFalse(ok)
        ok, _ = check_pr(self.ctx, ["infra/main.bicep"], "Threat-Model: N/A - tag-only change to resource metadata", models)
        self.assertTrue(ok)


if __name__ == "__main__":
    unittest.main()
