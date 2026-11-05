import copy
import datetime as dt
import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator

from threatmod import assess
from threatmod.cli import Ctx, generate, validate

ROOT = Path(__file__).resolve().parent.parent
FIX = ROOT / "examples/assess-demo/fixtures"
TODAY = dt.date(2026, 11, 5)


def strict(schema, path="$"):
    """Every object must be closed and fully required (structured-output rules)."""
    if schema.get("type") == "object":
        assert schema.get("additionalProperties") is False, path
        assert set(schema.get("required", [])) == set(schema["properties"]), path
        for k, v in schema["properties"].items():
            strict(v, f"{path}.{k}")
    if schema.get("type") == "object" and "additionalProperties" in schema and isinstance(schema["additionalProperties"], dict):
        strict(schema["additionalProperties"], path + ".*")
    if "items" in schema:
        strict(schema["items"], path + "[]")


class AssessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ctx = Ctx()
        cls.extraction = json.loads((FIX / "extraction.json").read_text())
        cls.sia = json.loads((FIX / "assessment.json").read_text())

    def test_schemas_are_strict_and_fixtures_conform(self):
        es, ss = assess.extraction_schema(self.ctx.policy), assess.assessment_schema(self.ctx.policy)
        strict(es); strict(ss)
        Draft202012Validator.check_schema(es); Draft202012Validator.check_schema(ss)
        self.assertEqual(list(Draft202012Validator(es).iter_errors(self.extraction)), [])
        self.assertEqual(list(Draft202012Validator(ss).iter_errors(self.sia)), [])

    def test_extraction_becomes_valid_tier2_model(self):
        doc = assess.build_model(copy.deepcopy(self.extraction), "TM-NME-52310", "Priya Example", "NME-52310", TODAY)
        self.assertEqual([f for f in validate(self.ctx, doc, "design", TODAY) if f.rule == "TM-SCHEMA"], [])
        from threatmod.cli import required_tier
        self.assertEqual(required_tier(self.ctx.policy, doc)[0], 2)
        self.assertEqual(sum(1 for t in doc["threats"] if t["source"] == "manual"), 4)
        added = generate(self.ctx, doc)
        self.assertGreater(len(added), 30)
        self.assertNotIn("TM-STRIDE", {f.rule for f in validate(self.ctx, doc, "design", TODAY)})

    def test_pipeline_offline(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            r = assess.assess(self.ctx, [ROOT / "examples/assess-demo/inputs/requirements.md"], out, "TM-NME-52310",
                              "Priya Example", "NME-52310", from_extraction=FIX / "extraction.json",
                              from_assessment=FIX / "assessment.json", today=TODAY)
            self.assertEqual(r["tier"], 2)
            for name in ("threat-model.yaml", "threat-model-report.md", "security-impact-assessment.md", "extraction.json", "assessment.json"):
                self.assertTrue((out / name).exists(), name)
            sia = (out / "security-impact-assessment.md").read_text()
            self.assertIn("proceed with conditions", sia)
            self.assertIn(f"{r['threats']} (C ", sia)
            self.assertNotIn("not in model", sia)

    def test_unknown_threat_id_is_flagged(self):
        doc = assess.build_model(copy.deepcopy(self.extraction), "TM-NME-52310", "P", "W", TODAY)
        generate(self.ctx, doc)
        sia = copy.deepcopy(self.sia)
        sia["key_risks"][0]["threat_ids"].append("T-NOPE-999")
        md = assess.render_sia(self.ctx.policy, doc, sia, self.extraction, [], TODAY, Path("."))
        self.assertIn("T-NOPE-999", md)
        self.assertIn("not present in the model", md)

    def test_inputs_loader(self):
        blocks = assess.load_inputs([ROOT / "examples/assess-demo/inputs/architecture.png", ROOT / "examples/assess-demo/inputs/requirements.md"])
        self.assertEqual([b["type"] for b in blocks], ["text", "image", "text"])
        self.assertEqual(blocks[1]["source"]["media_type"], "image/png")
        with self.assertRaises(SystemExit):
            assess.load_inputs([ROOT / "diagram.vsdx"])


if __name__ == "__main__":
    unittest.main()
