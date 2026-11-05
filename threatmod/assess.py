"""threatmod assess — feature diagram/requirements in, threat model + security impact assessment out.

Pipeline
  1. Extract   Claude reads the uploaded diagram(s)/requirements and returns a structured
               description of the feature (triage answers with evidence, assets, trust zones,
               elements, data flows, entry points, feature-specific threats, open questions).
  2. Model     The extraction becomes a threat-model.yaml; the deterministic policy engine
               computes the tier, enumerates STRIDE-per-element threats from the Nerdio
               library, scores them and runs the ISMS-DEV-004 design gate.
  3. Assess    Claude writes the Security Impact Assessment narrative, grounded only in the
               generated model and gate findings. Every number in the SIA comes from the
               engine, never from the model's memory.

All policy decisions (tier, threats, scores, gate verdict) are made by the engine, so the
LLM can draft but never approve. Run with --from-extraction to skip step 1 (offline/testing).
"""
from __future__ import annotations

import base64
import datetime as dt
import json
import mimetypes
import subprocess
import sys
from pathlib import Path

from . import cli as engine

MODEL = "claude-opus-5-5"
FALLBACK_BETA = "server-side-fallback-2026-07-01"
IMAGE_TYPES = {"image/png", "image/jpeg", "image/gif", "image/webp"}
TEXT_SUFFIXES = {".md", ".txt", ".yaml", ".yml", ".json", ".csv"}

# --------------------------------------------------------------------------- schema
_ID = {"type": "string", "pattern": "^[A-Za-z0-9][A-Za-z0-9_.-]*$"}
_CLASS = {"type": "string", "enum": ["public", "internal", "confidential", "restricted"]}


def _obj(props: dict, required=None) -> dict:
    return {"type": "object", "properties": props, "required": required or list(props), "additionalProperties": False}


def _arr(item: dict) -> dict:
    return {"type": "array", "items": item}


def extraction_schema(policy: dict) -> dict:
    """Structured-output schema for step 1, derived from the policy's triage questions."""
    triage = _obj({
        q: _obj({"answer": {"type": "boolean"},
                 "evidence": {"type": "string", "description": "Quote or diagram element that justifies the answer; empty if not determinable"}})
        for q in policy["triage"]["questions"]
    })
    return _obj({
        "feature": _obj({
            "title": {"type": "string"},
            "product": {"type": "string", "enum": ["NME", "NMM", "Platform", "Internal"]},
            "description": {"type": "string", "description": "2-4 sentences: what the feature does and for whom"},
        }),
        "data_classification": _CLASS,
        "triage": triage,
        "assets": _arr(_obj({"id": _ID, "name": {"type": "string"}, "classification": _CLASS, "description": {"type": "string"}})),
        "trust_zones": _arr(_obj({"id": _ID, "name": {"type": "string"},
                                  "trust": {"type": "integer", "minimum": 0, "maximum": 10}, "description": {"type": "string"}})),
        "elements": _arr(_obj({
            "id": _ID, "name": {"type": "string"},
            "type": {"type": "string", "enum": ["process", "data_store", "external_entity"]},
            "zone": _ID, "technology": {"type": "string"},
            "multi_tenant": {"type": "boolean"}, "internet_facing": {"type": "boolean"},
            "holds_assets": _arr(_ID), "description": {"type": "string"},
        })),
        "data_flows": _arr(_obj({
            "id": _ID, "from": _ID, "to": _ID, "protocol": {"type": "string"}, "assets": _arr(_ID),
            "authenticated": {"type": "boolean"}, "encrypted": {"type": "boolean"}, "description": {"type": "string"},
        })),
        "entry_points": _arr(_obj({"id": _ID, "element": _ID, "description": {"type": "string"},
                                   "authentication": {"type": "string"}, "internet_facing": {"type": "boolean"}})),
        "feature_specific_threats": _arr(_obj({
            "title": {"type": "string"}, "stride": {"type": "string", "enum": ["S", "T", "R", "I", "D", "E"]},
            "target": _ID, "description": {"type": "string"},
            "likelihood": {"type": "integer", "minimum": 1, "maximum": 5},
            "impact": {"type": "integer", "minimum": 1, "maximum": 5},
            "mitigation": {"type": "string"},
            "domain": {"type": "string", "enum": policy["control_domains"]},
        })),
        "assumptions": _arr({"type": "string"}),
        "open_questions": _arr({"type": "string"}),
    })


def assessment_schema(policy: dict) -> dict:
    """Structured-output schema for step 3 (the SIA narrative)."""
    return _obj({
        "executive_summary": {"type": "string", "description": "3-5 sentences for the CPTO / Head of Information Security"},
        "security_impact_rating": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
        "rating_rationale": {"type": "string"},
        "domain_impacts": _arr(_obj({
            "domain": {"type": "string", "enum": policy["control_domains"]},
            "impact": {"type": "string", "enum": ["none", "low", "medium", "high"]},
            "summary": {"type": "string"},
        })),
        "key_risks": _arr(_obj({
            "threat_ids": _arr({"type": "string"}),
            "headline": {"type": "string"},
            "why_it_matters": {"type": "string"},
            "required_controls": _arr({"type": "string"}),
        })),
        "design_conditions": _arr({"type": "string"}),
        "testing_requirements": _arr({"type": "string"}),
        "compliance_notes": _arr({"type": "string"}),
        "recommendation": {"type": "string", "enum": ["proceed", "proceed_with_conditions", "redesign_required"]},
        "recommendation_rationale": {"type": "string"},
    })


# --------------------------------------------------------------------------- inputs
def load_inputs(paths: list[Path]) -> list[dict]:
    """Turn uploaded files into Claude content blocks (images, PDFs, text)."""
    blocks = []
    for p in paths:
        mt, _ = mimetypes.guess_type(p.name)
        if mt in IMAGE_TYPES:
            data = base64.standard_b64encode(p.read_bytes()).decode()
            blocks.append({"type": "text", "text": f"[Diagram file: {p.name}]"})
            blocks.append({"type": "image", "source": {"type": "base64", "media_type": mt, "data": data}})
        elif p.suffix.lower() == ".pdf":
            data = base64.standard_b64encode(p.read_bytes()).decode()
            blocks.append({"type": "text", "text": f"[Document file: {p.name}]"})
            blocks.append({"type": "document", "source": {"type": "base64", "media_type": "application/pdf", "data": data}})
        elif p.suffix.lower() == ".docx":
            md = subprocess.run(["pandoc", "-t", "gfm", str(p)], capture_output=True, text=True, check=True).stdout
            blocks.append({"type": "text", "text": f"[Document file: {p.name}]\n\n{md}"})
        elif p.suffix.lower() in TEXT_SUFFIXES:
            blocks.append({"type": "text", "text": f"[Document file: {p.name}]\n\n{p.read_text(encoding='utf-8')}"})
        else:
            raise SystemExit(f"Unsupported input type: {p} (use png/jpg/webp/gif, pdf, docx, md or txt)")
    return blocks


# --------------------------------------------------------------------------- prompts
def _policy_brief(policy: dict) -> str:
    qs = "\n".join(f"  - {k}: {v['text']}" for k, v in policy["triage"]["questions"].items())
    lik = "\n".join(f"  {k}: {v}" for k, v in policy["risk"]["likelihood"].items())
    imp = "\n".join(f"  {k}: {v}" for k, v in policy["risk"]["impact"].items())
    return f"""You are the threat-modelling assistant for Nerdio's Security Team, applying policy {policy['policy']['id']}
(derived from ISMS-DEV-003 Secure Software Development Policy, §6.2 STRIDE threat modelling).
Nerdio builds Nerdio Manager for Enterprise (NME) and Nerdio Manager for MSPs (NMM): Azure-hosted products that
manage Azure Virtual Desktop and Windows 365 in customer tenants, using privileged Azure/Entra identities.
NMM is multi-tenant across MSPs and their customers.

Triage questions (answer each from evidence in the inputs):
{qs}

Data classification: public, internal, confidential (one customer's business data), restricted (credentials,
keys, tokens, personal data under GDPR/CCPA, anything spanning multiple tenants).

Likelihood anchors:
{lik}
Impact anchors:
{imp}

Trust zones are scored 0 (untrusted internet) to 10 (most trusted, e.g. private data plane).
Element types: process, data_store, external_entity. Data flows connect two element ids.
Entry points are the places untrusted input first reaches the feature."""


EXTRACT_INSTRUCTIONS = """Read the feature diagram(s) and/or requirements supplied and describe the feature in the
requested structure so the policy engine can enumerate STRIDE threats.

Rules:
- Extract only what the inputs show or state. If something is not determinable, say so in open_questions and
  choose the conservative option (e.g. assume unencrypted / unauthenticated / restricted data) and record it in
  assumptions. Never invent components that are not implied by the inputs.
- Use short stable ids: assets A1.., zones Z0.., elements E1/P1/D1.., flows F1.., entry points EP1...
  Every zone referenced by an element must exist; every element referenced by a flow or entry point must exist.
- Put every box or actor in the diagram into elements; put every arrow into data_flows with its protocol.
- feature_specific_threats are threats that depend on this feature's business logic (abuse of the workflow,
  logic flaws, misuse of a privilege). Do not list generic STRIDE threats here; the engine generates those.
- The extraction is reviewed by engineers; be precise and cite diagram labels in evidence fields."""


ASSESS_INSTRUCTIONS = """Write the Security Impact Assessment for this feature, grounded ONLY in the threat model JSON and
gate findings supplied. Do not introduce threats, components or numbers that are not in the supplied model.
Refer to threats by their ids. The audience is the Security Team, the engineering lead and the CPTO.
- key_risks: 3-6 items, highest inherent risk first, grouping related threat ids.
- design_conditions: concrete conditions that must be met before the design gate can pass.
- testing_requirements: what QA/Security must verify before release (ISMS-DEV-003 §8).
- compliance_notes: GDPR/CCPA, tenant isolation, ISO 27001 Annex A or SSDF implications, if any.
- recommendation: proceed / proceed_with_conditions / redesign_required, with rationale."""


# --------------------------------------------------------------------------- claude
def _client():
    try:
        import anthropic  # noqa: WPS433
    except ImportError:
        raise SystemExit("pip install anthropic (see requirements-assess.txt)")
    return anthropic, anthropic.Anthropic()


def _structured_call(system: str, content: list[dict], schema: dict, model: str, effort: str) -> dict:
    anthropic, client = _client()
    try:
        resp = client.beta.messages.create(
            model=model,
            max_tokens=16000,
            betas=[FALLBACK_BETA],
            fallbacks="default",
            system=[{"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}],
            messages=[{"role": "user", "content": content}],
            output_config={"effort": effort, "format": {"type": "json_schema", "schema": schema}},
        )
    except anthropic.AuthenticationError:
        raise SystemExit("No Claude credentials: set ANTHROPIC_API_KEY (or run `ant auth login`), "
                         "or use --from-extraction to run offline.")
    except anthropic.RateLimitError as e:
        raise SystemExit(f"Rate limited by the Claude API; retry after {e.response.headers.get('retry-after', '60')}s")
    except anthropic.APIStatusError as e:
        raise SystemExit(f"Claude API error {e.status_code}: {e.message}")
    except anthropic.APIConnectionError:
        raise SystemExit("Could not reach the Claude API (network).")
    if resp.stop_reason == "refusal":
        cat = resp.stop_details.category if resp.stop_details else "unknown"
        raise SystemExit(f"Claude declined this request (category: {cat}); run the assessment manually.")
    if resp.stop_reason == "max_tokens":
        raise SystemExit("Response truncated (max_tokens); split the inputs and retry.")
    text = next(b.text for b in resp.content if b.type == "text")
    return json.loads(text)


# --------------------------------------------------------------------------- pipeline
def build_model(extraction: dict, model_id: str, owner: str, work_item: str, today: dt.date) -> dict:
    """Turn a step-1 extraction into a threat-model.yaml document."""
    f = extraction["feature"]
    doc = {
        "schema_version": "1.0",
        "id": model_id,
        "feature": {"title": f["title"], "product": f["product"], "description": f["description"],
                    "owner": {"name": owner, "role": "development_team"}, "work_item": work_item},
        "status": "draft",
        "tier": 0,
        "last_updated": today.isoformat(),
        "data_classification": extraction["data_classification"],
        "triage": {k: v["answer"] for k, v in extraction["triage"].items()},
        "assets": [{k: v for k, v in a.items() if v != ""} for a in extraction["assets"]],
        "trust_zones": [{k: v for k, v in z.items() if v != ""} for z in extraction["trust_zones"]],
        "elements": [{k: v for k, v in e.items() if v not in ("", [], False)} for e in extraction["elements"]],
        "data_flows": [{k: v for k, v in fl.items() if v not in ("", [])} for fl in extraction["data_flows"]],
        "entry_points": [{k: v for k, v in ep.items() if v != ""} for ep in extraction["entry_points"]],
        "threats": [],
        "not_applicable": [],
        "architectural_review": {},
        "approvals": [],
        "references": ["Generated by threatmod assess from: " + ", ".join(extraction.get("_inputs", []))],
    }
    for el in doc["elements"]:  # keep explicit false flags out, but keep true ones (handled above)
        el.setdefault("zone", el.get("zone"))
    for i, t in enumerate(extraction.get("feature_specific_threats", []), 1):
        tid = f"T-{t['target']}-FEAT-{i:03d}"
        doc["threats"].append({
            "id": tid, "title": t["title"], "stride": t["stride"], "target": t["target"],
            "description": t["description"], "source": "manual",
            "likelihood": t["likelihood"], "impact": t["impact"], "status": "identified",
            "mitigations": [{"id": f"M-{tid[2:]}-1", "description": t["mitigation"], "domain": t["domain"], "status": "proposed"}],
        })
    return doc


def render_sia(policy: dict, doc: dict, sia: dict, extraction: dict, findings, today: dt.date, out_dir: Path) -> str:
    sev = lambda t: engine.severity(policy, t.get("likelihood"), t.get("impact")) or "unscored"
    by_id = {t["id"]: t for t in doc["threats"]}
    counts = {s: sum(1 for t in doc["threats"] if sev(t) == s) for s in ("critical", "high", "medium", "low")}
    tier = doc["tier"]
    need, reasons = engine.required_tier(policy, doc)
    errors = [x for x in findings if x.level == "error"]
    rating = sia["security_impact_rating"].upper()
    rec = sia["recommendation"].replace("_", " ")
    md = [
        f"# Security Impact Assessment: {doc['feature']['title']}",
        "",
        f"**Threat model:** {doc['id']} · **Product:** {doc['feature']['product']} · **Policy:** {policy['policy']['id']} v{policy['policy']['version']} · **Date:** {today.isoformat()}",
        "",
        f"| Security impact | Required tier | Threats enumerated | Design gate (as generated) | Recommendation |",
        f"|---|---|---|---|---|",
        f"| **{rating}** | **{tier}** ({policy['triage']['tiers'][tier]['name']}) | {len(doc['threats'])} "
        f"(C {counts['critical']} · H {counts['high']} · M {counts['medium']} · L {counts['low']}) | "
        f"{'PASS' if not errors else f'{len(errors)} open findings'} | **{rec}** |",
        "",
        "> Draft produced by `threatmod assess` from the uploaded inputs. The tier, threat list, scores and gate",
        "> verdict are computed by the policy engine; the narrative is AI-drafted and must be reviewed by the",
        "> Security Team before it is relied on (ISMS-DEV-004 §4.3).",
        "",
        "## 1. Executive summary", "", sia["executive_summary"], "",
        f"**Why {rating.lower()}:** {sia['rating_rationale']}", "",
        "## 2. Feature and scope", "", doc["feature"].get("description", ""), "",
        f"Required tier **{need}**" + (f" because: {'; '.join(reasons)}." if reasons else "."), "",
        "| Triage question | Answer | Evidence |", "|---|---|---|",
    ]
    for q, v in extraction["triage"].items():
        md.append(f"| {policy['triage']['questions'][q]['text']} | {'**Yes**' if v['answer'] else 'No'} | {v.get('evidence', '')} |")
    md += ["", "### Attack surface", "", "| Entry point | Element | Authentication | Internet-facing |", "|---|---|---|---|"]
    model = engine.Model(doc, policy)
    for ep in doc["entry_points"]:
        el = model.elements.get(ep["element"], {})
        md.append(f"| {ep['description']} | {el.get('name', ep['element'])} | {ep['authentication']} | "
                  f"{'yes' if ep.get('internet_facing') or model.element_internet_facing(el) else 'no'} |")
    md += ["", f"{len(model.boundary_crossings())} of {len(model.flows)} data flows cross a trust boundary.", "",
           "## 3. Impact by security requirement domain (ISMS-DEV-003 §6.1)", "",
           "| Domain | Impact | Summary |", "|---|---|---|"]
    for d in sia["domain_impacts"]:
        md.append(f"| {d['domain'].replace('_', ' ')} | {d['impact']} | {d['summary']} |")
    md += ["", "## 4. Key risks", ""]
    unknown = sorted({x for r in sia["key_risks"] for x in r["threat_ids"] if x not in by_id})
    if unknown:
        md += [f"> ⚠️ The narrative references threat ids not present in the model: {', '.join(unknown)}. Review before use.", ""]
        print(f"warning: SIA references unknown threat ids: {', '.join(unknown)}", file=sys.stderr)
    for i, r in enumerate(sia["key_risks"], 1):
        ids = ", ".join(f"`{x}`" + (f" ({sev(by_id[x])})" if x in by_id else " (not in model)") for x in r["threat_ids"])
        md += [f"### 4.{i} {r['headline']}", "", f"Threats: {ids}", "", r["why_it_matters"], "", "Required controls:", ""]
        md += [f"- {c}" for c in r["required_controls"]]
        md.append("")
    md += ["## 5. Conditions for design approval", ""] + [f"- [ ] {c}" for c in sia["design_conditions"]]
    md += ["", "## 6. Verification required before release", ""] + [f"- [ ] {c}" for c in sia["testing_requirements"]]
    if sia["compliance_notes"]:
        md += ["", "## 7. Compliance notes", ""] + [f"- {c}" for c in sia["compliance_notes"]]
    md += ["", "## 8. Recommendation", "", f"**{rec.capitalize()}.** {sia['recommendation_rationale']}", ""]
    if extraction.get("assumptions") or extraction.get("open_questions"):
        md += ["## 9. Assumptions and open questions", ""]
        md += [f"- Assumed: {a}" for a in extraction.get("assumptions", [])]
        md += [f"- Open: {q}" for q in extraction.get("open_questions", [])]
        md.append("")
    md += ["## 10. Design-gate findings on the generated model", ""]
    md += [f"- {'❌' if x.level == 'error' else '⚠️'} **{x.rule}** {x.message}" for x in findings] or ["No findings."]
    md += ["", f"_Full threat list: [threat-model-report.md](threat-model-report.md) · model: [threat-model.yaml](threat-model.yaml)_", ""]
    return "\n".join(md)


def assess(ctx: engine.Ctx, inputs: list[Path], out_dir: Path, model_id: str, owner: str, work_item: str,
           from_extraction: Path | None = None, narrative: bool = True, model: str = MODEL,
           from_assessment: Path | None = None,
           effort: str = "high", today: dt.date | None = None) -> dict:
    policy = ctx.policy
    today = today or dt.date.today()
    out_dir.mkdir(parents=True, exist_ok=True)

    # 1. extract
    if from_extraction:
        extraction = json.loads(Path(from_extraction).read_text(encoding="utf-8"))
    else:
        content = load_inputs(inputs) + [{"type": "text", "text": EXTRACT_INSTRUCTIONS}]
        extraction = _structured_call(_policy_brief(policy), content, extraction_schema(policy), model, effort)
    extraction["_inputs"] = [p.name for p in inputs] or extraction.get("_inputs", [])
    (out_dir / "extraction.json").write_text(json.dumps(extraction, indent=2, ensure_ascii=False), encoding="utf-8")

    # 2. model
    doc = build_model(extraction, model_id, owner, work_item, today)
    schema_errs = [f for f in engine.validate(ctx, doc, "design", today) if f.rule == "TM-SCHEMA"]
    if schema_errs:
        raise SystemExit("Extraction produced an invalid model:\n" + "\n".join(f"  {f.message}" for f in schema_errs))
    doc["tier"] = max(doc["tier"], engine.required_tier(policy, doc)[0])
    engine.generate(ctx, doc)
    findings = engine.validate(ctx, doc, "design", today)
    engine.dump_yaml(doc, out_dir / "threat-model.yaml")
    (out_dir / "threat-model-report.md").write_text(engine.report(ctx, doc, "design", today), encoding="utf-8")

    # 3. assess
    if narrative:
        grounded = {
            "feature": doc["feature"], "tier": doc["tier"], "data_classification": doc["data_classification"],
            "triage": extraction["triage"], "assets": doc["assets"], "trust_zones": doc["trust_zones"],
            "elements": doc["elements"], "data_flows": doc["data_flows"], "entry_points": doc["entry_points"],
            "threats": [{k: t[k] for k in ("id", "title", "stride", "target", "description", "likelihood", "impact", "source")}
                        | {"severity": engine.severity(policy, t["likelihood"], t["impact"]),
                           "suggested_mitigations": [m["description"] for m in t["mitigations"]]} for t in doc["threats"]],
            "design_gate_findings": [{"rule": f.rule, "level": f.level, "message": f.message} for f in findings],
            "assumptions": extraction.get("assumptions", []), "open_questions": extraction.get("open_questions", []),
        }
        content = [{"type": "text", "text": "Threat model and gate findings (JSON):\n\n" + json.dumps(grounded, ensure_ascii=False)},
                   {"type": "text", "text": ASSESS_INSTRUCTIONS}]
        if from_assessment:
            sia = json.loads(Path(from_assessment).read_text(encoding="utf-8"))
        else:
            sia = _structured_call(_policy_brief(policy), content, assessment_schema(policy), model, effort)
        (out_dir / "assessment.json").write_text(json.dumps(sia, indent=2, ensure_ascii=False), encoding="utf-8")
        (out_dir / "security-impact-assessment.md").write_text(
            render_sia(policy, doc, sia, extraction, findings, today, out_dir), encoding="utf-8")
    return {"tier": doc["tier"], "threats": len(doc["threats"]),
            "errors": sum(1 for f in findings if f.level == "error"), "out": str(out_dir)}


def cmd_assess(ctx: engine.Ctx, a):
    inputs = [Path(p) for p in a.inputs]
    for p in inputs:
        if not p.exists():
            raise SystemExit(f"input not found: {p}")
    if not inputs and not a.from_extraction:
        raise SystemExit("give at least one diagram/requirements file, or --from-extraction")
    out = Path(a.out or f"threat-models/{a.id.lower()}")
    r = assess(ctx, inputs, out, a.id, a.owner, a.work_item,
               from_extraction=Path(a.from_extraction) if a.from_extraction else None,
               narrative=not a.no_narrative, model=a.model, effort=a.effort,
               from_assessment=Path(a.from_assessment) if a.from_assessment else None,
               today=engine.parse_date(a.today) if a.today else None)
    print(f"Tier {r['tier']} · {r['threats']} threats · design gate: {'PASS' if not r['errors'] else str(r['errors']) + ' open findings'}")
    print(f"Outputs in {r['out']}/: threat-model.yaml, threat-model-report.md"
          + ("" if a.no_narrative else ", security-impact-assessment.md"))


def add_parser(sub):
    s = sub.add_parser("assess", help="diagram/requirements -> threat model + security impact assessment (uses Claude)")
    s.set_defaults(fn=cmd_assess)
    s.add_argument("inputs", nargs="*", help="diagram images (png/jpg/webp), PDFs, .docx, .md or .txt requirements")
    s.add_argument("--id", required=True, help="TM-<PRODUCT>-<WORKITEM>")
    s.add_argument("--owner", required=True)
    s.add_argument("--work-item", required=True)
    s.add_argument("--out", help="output directory (default threat-models/<id>)")
    s.add_argument("--from-extraction", help="reuse a saved extraction.json instead of calling Claude for step 1")
    s.add_argument("--from-assessment", help="reuse a saved assessment.json instead of calling Claude for step 3")
    s.add_argument("--no-narrative", action="store_true", help="skip the AI-written SIA; produce model + report only")
    s.add_argument("--model", default=MODEL)
    s.add_argument("--effort", default="high", choices=["low", "medium", "high", "xhigh", "max"])
    s.add_argument("--today")
