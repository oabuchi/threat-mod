"""Human validation (TM-VALIDATED), PR evidence (TM-PR-EVIDENCE), mark-implemented and coverage."""
import copy
import datetime as dt
import unittest
from pathlib import Path

from threatmod.cli import Ctx, check_pr, coverage, load_yaml, validate

ROOT = Path(__file__).resolve().parent.parent
DRAFT = ROOT / "examples/assess-demo/output/threat-model.yaml"
VALIDATED = ROOT / "examples/assess-demo/validated"
T = dt.date(2026, 11, 12)


def rules(findings):
    return {f.rule for f in findings if f.level == "error"}


class ValidationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ctx = Ctx()
        cls.draft = load_yaml(DRAFT)
        cls.valid = load_yaml(VALIDATED / "threat-model.yaml")

    def test_ai_draft_requires_validation(self):
        self.assertIn("TM-VALIDATED", rules(validate(self.ctx, self.draft, "design", T)))

    def test_validated_example_passes_design(self):
        self.assertEqual(rules(validate(self.ctx, self.valid, "design", T)), set())

    def test_validation_rules(self):
        d = copy.deepcopy(self.valid)
        d["validation"]["validated_by"] = {"name": "Priya Example", "role": "development_team"}  # owner + wrong role
        self.assertIn("TM-VALIDATED", rules(validate(self.ctx, d, "design", T)))
        d = copy.deepcopy(self.valid)
        d["validation"]["date"] = "2026-11-01"  # before generation
        self.assertIn("TM-VALIDATED", rules(validate(self.ctx, d, "design", T)))
        d = copy.deepcopy(self.valid)
        del d["validation"]["sia_rating_confirmed_by"]
        self.assertIn("TM-VALIDATED", rules(validate(self.ctx, d, "design", T)))
        d = copy.deepcopy(self.valid)
        d["validation"]["scope"] = ["extraction"]
        self.assertIn("TM-VALIDATED", rules(validate(self.ctx, d, "design", T)))

    def test_hand_written_model_needs_no_validation(self):
        d = copy.deepcopy(self.valid)
        del d["provenance"]; del d["validation"]
        self.assertNotIn("TM-VALIDATED", rules(validate(self.ctx, d, "design", T)))


class PrEvidenceTests(unittest.TestCase):
    ctx = Ctx()

    def test_claimed_mitigations_implemented(self):
        ok, msg = check_pr(self.ctx, ["src/Api/TeamsActivityController.cs"],
                           "Threat-Model: TM-NME-52310\nMitigates: M-P1-FEAT-004-1, M-P1-S-002-1", VALIDATED)
        self.assertTrue(ok, msg); self.assertIn("2 mitigation(s) implemented", msg)

    def test_claimed_mitigation_not_implemented_fails(self):
        ok, msg = check_pr(self.ctx, ["src/api/x.cs"], "Threat-Model: TM-NME-52310\nMitigates: M-P2-FEAT-001-1", VALIDATED)
        self.assertFalse(ok); self.assertIn("'planned'", msg)

    def test_unknown_mitigation_fails_even_without_security_paths(self):
        ok, msg = check_pr(self.ctx, ["docs/readme.md"], "Threat-Model: TM-NME-52310\nMitigates: M-NOPE-1", VALIDATED)
        self.assertFalse(ok); self.assertIn("not a mitigation", msg)

    def test_evidence_checked_when_model_file_changed(self):
        ok, msg = check_pr(self.ctx, ["src/Api/X.cs", str(VALIDATED / "threat-model.yaml")], "Mitigates: M-P2-FEAT-001-1", VALIDATED)
        self.assertFalse(ok)

    def test_warning_when_planned_but_none_claimed(self):
        ok, msg = check_pr(self.ctx, ["src/Api/X.cs"], "Threat-Model: TM-NME-52310", VALIDATED)
        self.assertTrue(ok); self.assertIn("names none", msg)

    def test_paths_case_insensitive(self):
        ok, _ = check_pr(self.ctx, ["Src/API/Thing.cs"], "", VALIDATED)
        self.assertFalse(ok)


class CoverageTests(unittest.TestCase):
    def test_scorecard(self):
        ctx = Ctx()
        r = coverage(ctx, load_yaml(VALIDATED / "threat-model.yaml"))
        self.assertEqual(r["mitigations_implemented"], 5)
        self.assertTrue(r["validated"] and r["design_approved"] and not r["verified"])
        self.assertEqual(r["by_domain"]["authentication_identity"]["implemented"], 3)
        self.assertIn("high", r["by_severity"])


if __name__ == "__main__":
    unittest.main()
