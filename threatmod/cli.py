"""threatmod — automation for the Nerdio Threat Modelling Policy (ISMS-DEV-004).

Commands
  init       scaffold a feature threat model
  triage     compute the required tier from triage answers + data classification
  generate   enumerate STRIDE-per-element threats from the threat library
  validate   evaluate a model against the design or release gate
  report     render the feature's threat landscape as Markdown (evidence)
  check-pr   fail a PR that touches security-relevant paths without a model reference
  workitems  export mitigations as an Azure DevOps CSV (security acceptance criteria)

All thresholds come from policy/threat-modeling-policy.yaml; nothing is hard-coded here.
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import os
import re
import sys
from dataclasses import dataclass, asdict
from pathlib import Path, PurePosixPath

import yaml
from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(os.environ.get("THREATMOD_HOME", Path(__file__).resolve().parent.parent))
STRIDE_NAMES = {
    "S": "Spoofing", "T": "Tampering", "R": "Repudiation",
    "I": "Information disclosure", "D": "Denial of service", "E": "Elevation of privilege",
}
CLASS_ORDER = ["public", "internal", "confidential", "restricted"]
SEVERITIES = ["low", "medium", "high", "critical"]
SECURITY_ROLES = {"security_team", "head_of_information_security"}


# --------------------------------------------------------------------------- io
def load_yaml(path: Path):
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def dump_yaml(data, path: Path):
    with open(path, "w", encoding="utf-8") as fh:
        yaml.safe_dump(data, fh, sort_keys=False, allow_unicode=True, width=110)


class Ctx:
    def __init__(self, policy_path=None, library_path=None, schema_path=None):
        self.policy = load_yaml(Path(policy_path or ROOT / "policy/threat-modeling-policy.yaml"))
        self.library = load_yaml(Path(library_path or ROOT / "catalog/stride-threat-library.yaml"))["threats"]
        self.schema = json.loads(Path(schema_path or ROOT / "schema/threat-model.schema.json").read_text())


# ---------------------------------------------------------------- risk helpers
def severity(policy, likelihood, impact) -> str | None:
    if not likelihood or not impact:
        return None
    score = likelihood * impact
    bands = policy["risk"]["bands"]
    for name in ("critical", "high", "medium", "low"):
        if score >= bands[name]:
            return name
    return "low"


def sev_ge(a: str | None, b: str) -> bool:
    return a is not None and SEVERITIES.index(a) >= SEVERITIES.index(b)


def max_class(*values):
    vals = [v for v in values if v]
    return max(vals, key=CLASS_ORDER.index) if vals else None


def parse_date(s):
    if isinstance(s, dt.date):
        return s
    return dt.date.fromisoformat(str(s)) if s else None


# --------------------------------------------------------------- model graph
class Model:
    """Derived view over a threat-model document (trust boundaries, targets...)."""

    def __init__(self, doc: dict, policy: dict):
        self.doc, self.policy = doc, policy
        self.zones = {z["id"]: z for z in doc.get("trust_zones", [])}
        self.assets = {a["id"]: a for a in doc.get("assets", [])}
        self.elements = {e["id"]: e for e in doc.get("elements", [])}
        self.flows = {f["id"]: f for f in doc.get("data_flows", [])}
        self.default_class = doc.get("data_classification", "internal")

    def element_internet_facing(self, el) -> bool:
        zone = self.zones.get(el.get("zone"), {})
        return bool(el.get("internet_facing")) or zone.get("trust") == 0

    def element_class(self, el) -> str:
        held = [self.assets[a]["classification"] for a in el.get("holds_assets", []) if a in self.assets]
        return max_class(el.get("classification"), *held) or self.default_class

    def flow_ends(self, fl):
        return self.elements.get(fl["from"], {}), self.elements.get(fl["to"], {})

    def flow_crosses(self, fl) -> bool:
        a, b = self.flow_ends(fl)
        return a.get("zone") != b.get("zone")

    def flow_class(self, fl) -> str:
        carried = [self.assets[a]["classification"] for a in fl.get("assets", []) if a in self.assets]
        if carried:
            return max_class(*carried)
        a, b = self.flow_ends(fl)
        return max_class(self.element_class(a) if a else None, self.element_class(b) if b else None) or self.default_class

    def flow_name(self, fl) -> str:
        a, b = self.flow_ends(fl)
        return f"{a.get('name', fl['from'])} → {b.get('name', fl['to'])} ({fl['protocol']})"

    def targets(self):
        """Yield (id, kind, name, facts) for every element and data flow."""
        for el in self.elements.values():
            yield el["id"], el["type"], el["name"], {
                "internet_facing": self.element_internet_facing(el),
                "multi_tenant": bool(el.get("multi_tenant")),
                "technology": (el.get("technology") or "").lower(),
                "classification": self.element_class(el),
                "crosses_boundary": False,
                "enters_higher_trust": False,
            }
        for fl in self.flows.values():
            a, b = self.flow_ends(fl)
            ta = self.zones.get(a.get("zone"), {}).get("trust", 0)
            tb = self.zones.get(b.get("zone"), {}).get("trust", 0)
            yield fl["id"], "data_flow", self.flow_name(fl), {
                "enters_higher_trust": tb > ta,
                "internet_facing": any(self.element_internet_facing(x) for x in (a, b) if x),
                "multi_tenant": any(x.get("multi_tenant") for x in (a, b) if x),
                "technology": fl["protocol"].lower(),
                "classification": self.flow_class(fl),
                "crosses_boundary": self.flow_crosses(fl),
                "encrypted": fl.get("encrypted"),
                "authenticated": fl.get("authenticated"),
            }

    def boundary_crossings(self):
        return [f for f in self.flows.values() if self.flow_crosses(f)]


# --------------------------------------------------------------------- triage
def required_tier(policy, doc) -> tuple[int, list[str]]:
    reasons, tier = [], 0
    for key, q in policy["triage"]["questions"].items():
        if doc.get("triage", {}).get(key):
            tier = max(tier, q["min_tier"])
            reasons.append(f"{key} → tier {q['min_tier']}")
    cls = doc.get("data_classification")
    if cls:
        ct = policy["triage"]["classification_min_tier"][cls]
        if ct:
            reasons.append(f"data_classification={cls} → tier {ct}")
        tier = max(tier, ct)
    return tier, reasons


# ------------------------------------------------------------------- generate
def _matches(entry, kind, facts) -> bool:
    if entry.get("generic"):
        return False
    if kind not in entry.get("applies_to", []):
        return False
    for cond, want in (entry.get("when") or {}).items():
        if cond == "technology_any":
            if not any(t.lower() in facts["technology"] for t in want):
                return False
        elif cond == "classification_in":
            if facts["classification"] not in want:
                return False
        elif facts.get(cond) != want:
            return False
    return True


def generate(ctx: Ctx, doc: dict) -> list[dict]:
    policy, model = ctx.policy, Model(doc, ctx.policy)
    risk = policy["risk"]
    threats = doc.setdefault("threats", [])
    existing = {(t["target"], t.get("library_ref")) for t in threats}
    covered = {(t["target"], t["stride"]) for t in threats}
    covered |= {(n["target"], n["stride"]) for n in doc.get("not_applicable", [])}
    generic = {e["stride"]: e for e in ctx.library if e.get("generic")}
    added = []

    for tid, kind, name, facts in model.targets():
        for cat in policy["stride_per_element"][kind]:
            if (tid, cat) in {(n["target"], n["stride"]) for n in doc.get("not_applicable", [])}:
                continue
            entries = [e for e in ctx.library if e["stride"] == cat and _matches(e, kind, facts)]
            if not entries and (tid, cat) not in covered:
                entries = [generic[cat]]
            for e in entries:
                if (tid, e["id"]) in existing:
                    continue
                lik = risk["default_likelihood"] + e.get("likelihood_delta", 0)
                if facts["crosses_boundary"] or facts["internet_facing"]:
                    lik += risk["trust_boundary_likelihood_uplift"]
                imp = risk["default_impact_by_classification"][facts["classification"]]
                if facts["multi_tenant"] and cat in ("I", "E"):
                    imp = risk["cross_tenant_impact"]
                thr_id = f"T-{tid}-{e['id'].removeprefix('LIB-')}"
                threat = {
                    "id": thr_id,
                    "title": e["title"].format(name=name),
                    "stride": cat,
                    "target": tid,
                    "description": e["description"].format(name=name),
                    "source": "generated",
                    "library_ref": e["id"],
                    "likelihood": max(1, min(5, lik)),
                    "impact": max(1, min(5, imp)),
                    "status": "identified",
                    "mitigations": [
                        {"id": f"M-{thr_id[2:]}-{i}", "description": m["text"].format(name=name),
                         "domain": m["domain"], "status": "proposed"}
                        for i, m in enumerate(e.get("mitigations", []), 1)
                    ],
                }
                threats.append(threat)
                existing.add((tid, e["id"]))
                covered.add((tid, cat))
                added.append(threat)
    return added


# ------------------------------------------------------------------- validate
@dataclass
class Finding:
    rule: str
    level: str  # error | warning
    message: str
    path: str = ""


def _ref_integrity(doc, model, policy, out):
    ids = {}
    for section in ("assets", "trust_zones", "elements", "data_flows", "entry_points", "threats"):
        for item in doc.get(section, []) or []:
            if item["id"] in ids:
                out.append(Finding("TM-SCHEMA", "error", f"duplicate id '{item['id']}' in {section} and {ids[item['id']]}"))
            ids[item["id"]] = section
    for el in model.elements.values():
        if el["zone"] not in model.zones:
            out.append(Finding("TM-SCHEMA", "error", f"element {el['id']} references unknown zone '{el['zone']}'"))
        for a in el.get("holds_assets", []):
            if a not in model.assets:
                out.append(Finding("TM-SCHEMA", "error", f"element {el['id']} references unknown asset '{a}'"))
    for fl in model.flows.values():
        for end in ("from", "to"):
            if fl[end] not in model.elements:
                out.append(Finding("TM-SCHEMA", "error", f"flow {fl['id']} '{end}' references unknown element '{fl[end]}'"))
        for a in fl.get("assets", []):
            if a not in model.assets:
                out.append(Finding("TM-SCHEMA", "error", f"flow {fl['id']} references unknown asset '{a}'"))
    for ep in doc.get("entry_points", []):
        if ep["element"] not in model.elements:
            out.append(Finding("TM-SCHEMA", "error", f"entry point {ep['id']} references unknown element '{ep['element']}'"))
    domains = set(policy["control_domains"])
    for t in doc.get("threats", []):
        if t["target"] not in model.elements and t["target"] not in model.flows:
            out.append(Finding("TM-SCHEMA", "error", f"threat {t['id']} targets unknown element/flow '{t['target']}'"))
        for m in t.get("mitigations", []):
            if m["domain"] not in domains:
                out.append(Finding("TM-SCHEMA", "error", f"mitigation {m['id']} has unknown control domain '{m['domain']}'"))


def _check_acceptance(policy, doc, t, sev, today, stage, out):
    acc = t.get("acceptance")
    if not acc:
        out.append(Finding("TM-ACCEPTANCE", "error", f"threat {t['id']} is 'accepted' but has no acceptance record (ISMS-DEV-003 §15)"))
        return
    rules = policy["risk_acceptance"]
    sev = sev or "low"
    approver = acc["approved_by"]
    if approver["role"] not in rules["approver_roles"][sev]:
        out.append(Finding("TM-ACCEPTANCE", "error",
                           f"threat {t['id']}: {sev} risk must be accepted by {rules['approver_roles'][sev]}, not '{approver['role']}'"))
    owner = doc["feature"]["owner"]["name"].strip().lower()
    if approver["name"].strip().lower() in {acc["requested_by"]["name"].strip().lower(), owner}:
        out.append(Finding("TM-ACCEPTANCE", "error", f"threat {t['id']}: self-approval of risk acceptance is prohibited"))
    rec_role = rules.get("recommendation_required", {}).get(sev)
    if rec_role and (acc.get("recommended_by") or {}).get("role") != rec_role:
        out.append(Finding("TM-ACCEPTANCE", "error", f"threat {t['id']}: {sev} acceptance requires a recommendation from {rec_role}"))
    if sev in rules.get("management_review_ratification_required", []) and not acc.get("management_review_ratified_on"):
        out.append(Finding("TM-ACCEPTANCE", "warning",
                           f"threat {t['id']}: critical acceptance must be ratified at the next ISMS Management Review"))
    if rules.get("require_compensating_controls") and not acc.get("compensating_controls"):
        out.append(Finding("TM-ACCEPTANCE", "error", f"threat {t['id']}: acceptance must list compensating controls"))
    approved, review = parse_date(acc["approved_on"]), parse_date(acc["review_date"])
    if (review - approved).days > rules["max_review_interval_days"]:
        out.append(Finding("TM-ACCEPTANCE", "error", f"threat {t['id']}: acceptance review date exceeds {rules['max_review_interval_days']} days"))
    if review < today:
        out.append(Finding("TM-ACCEPTANCE", "error", f"threat {t['id']}: risk acceptance expired on {review} — re-review required"))


def validate(ctx: Ctx, doc: dict, stage: str = "design", today: dt.date | None = None) -> list[Finding]:
    policy, out = ctx.policy, []
    today = today or dt.date.today()

    # TM-SCHEMA ---------------------------------------------------------------
    v = Draft202012Validator(ctx.schema, format_checker=FormatChecker())
    errs = sorted(v.iter_errors(doc), key=lambda e: list(e.path))
    for e in errs:
        out.append(Finding("TM-SCHEMA", "error", e.message, "/".join(str(p) for p in e.path)))
    if errs:
        return out  # structural problems make the remaining checks unreliable
    model = Model(doc, policy)
    _ref_integrity(doc, model, policy, out)
    tier = doc["tier"]

    # TM-TRIAGE ---------------------------------------------------------------
    missing = [q for q in policy["triage"]["questions"] if q not in doc["triage"]]
    if missing:
        out.append(Finding("TM-TRIAGE", "error", f"triage questions unanswered: {', '.join(missing)}"))
    need, reasons = required_tier(policy, doc)
    if tier < need:
        out.append(Finding("TM-TRIAGE", "error", f"declared tier {tier} is below required tier {need} ({'; '.join(reasons)})"))
    if tier == 0:
        return out  # Tier 0: triage record is the evidence

    # TM-SCOPE ----------------------------------------------------------------
    for section, minimum in (("assets", 1), ("trust_zones", 2), ("elements", 2), ("data_flows", 1), ("entry_points", 1)):
        if len(doc.get(section, []) or []) < minimum:
            out.append(Finding("TM-SCOPE", "error", f"'{section}' needs at least {minimum} item(s) (ISMS-DEV-003 §6.2 step 1)"))
    if doc.get("data_flows") and not model.boundary_crossings():
        out.append(Finding("TM-SCOPE", "warning", "no data flow crosses a trust boundary — confirm zones are modelled correctly"))

    # TM-STRIDE ---------------------------------------------------------------
    covered = {(t["target"], t["stride"]) for t in doc.get("threats", [])}
    covered |= {(n["target"], n["stride"]) for n in doc.get("not_applicable", [])}
    for tid, kind, name, _ in model.targets():
        gaps = [c for c in policy["stride_per_element"][kind] if (tid, c) not in covered]
        if gaps:
            out.append(Finding("TM-STRIDE", "error",
                               f"{tid} ({name}) has no threat or not_applicable entry for: {', '.join(gaps)} — run `threatmod generate`"))

    # per-threat rules ----------------------------------------------------------
    for t in doc.get("threats", []):
        sev = severity(policy, t.get("likelihood"), t.get("impact"))
        if t["status"] == "rejected":
            if not t.get("rejection_reason"):
                out.append(Finding("TM-TREATED", "error", f"threat {t['id']} rejected without rejection_reason"))
            continue
        if t["status"] == "transferred" and not t.get("rejection_reason"):
            out.append(Finding("TM-TREATED", "error", f"threat {t['id']} transferred without rationale (use rejection_reason)"))
        if sev is None:
            out.append(Finding("TM-SCORED", "error", f"threat {t['id']} is missing likelihood and/or impact"))
        if t["status"] == "identified":
            lvl = "error" if sev_ge(sev, "medium") else "warning"
            out.append(Finding("TM-TREATED", lvl, f"threat {t['id']} ({sev}) has no treatment decision"))
        if t["status"] in ("mitigation_planned", "mitigated"):
            committed = [m for m in t.get("mitigations", []) if m["status"] != "proposed"]
            if not committed:
                out.append(Finding("TM-TREATED", "error", f"threat {t['id']} is '{t['status']}' but no mitigation is planned (all 'proposed')"))
            for m in committed:
                if not m.get("work_item"):
                    out.append(Finding("TM-WORKITEM", "error",
                                       f"mitigation {m['id']} must link a work item carrying the security acceptance criterion (§6.1)"))
        if t["status"] == "accepted" or t.get("acceptance"):
            res = t.get("residual") or {}
            res_sev = severity(policy, res.get("likelihood"), res.get("impact")) or sev
            _check_acceptance(policy, doc, t, res_sev, today, stage, out)

    # Tier-specific approvals ------------------------------------------------
    tier_cfg = policy["triage"]["tiers"][tier]
    if tier_cfg["architectural_review_required"]:
        ar = doc.get("architectural_review", {}) or {}
        gaps = [d for d in policy["architectural_review_domains"] if d not in ar]
        if gaps:
            out.append(Finding("TM-ARCH-REVIEW", "error", f"architectural review (§6.3) missing domains: {', '.join(gaps)}"))
    design_approvals = [a for a in doc.get("approvals", []) if a["stage"] == "design"]
    owner = doc["feature"]["owner"]["name"].strip().lower()
    if tier_cfg["security_approval_required"]:
        if not any(a["approver"]["role"] in SECURITY_ROLES for a in design_approvals):
            out.append(Finding("TM-APPROVAL", "error", "Tier 2 requires Security Team design approval (SSDF PW.2)"))
    elif not any(a["approver"]["name"].strip().lower() != owner for a in design_approvals):
        out.append(Finding("TM-APPROVAL", "error", "design approval by a reviewer other than the feature owner is required"))

    if stage == "design":
        return out

    # ----------------------------------------------------------- release gate
    for t in doc.get("threats", []):
        if t["status"] == "rejected":
            continue
        sev = severity(policy, t.get("likelihood"), t.get("impact"))
        hi = sev_ge(sev, "high")
        if t["status"] in ("mitigation_planned", "mitigated"):
            pending = [m for m in t.get("mitigations", [])
                       if m["status"] in ("planned",) or (m["status"] in ("implemented", "verified") and not m.get("evidence"))]
            for m in pending:
                out.append(Finding("TM-IMPLEMENTED", "error" if hi else "warning",
                                   f"mitigation {m['id']} for {sev} threat {t['id']} is not implemented with evidence"))
            if hi and t["status"] != "mitigated":
                out.append(Finding("TM-IMPLEMENTED", "error", f"{sev} threat {t['id']} must be 'mitigated' or 'accepted' before release"))
        if hi and t["status"] not in ("accepted", "transferred"):
            res = t.get("residual")
            if not res:
                out.append(Finding("TM-RESIDUAL", "error", f"{sev} threat {t['id']}: record residual likelihood/impact before release"))
            elif sev_ge(severity(policy, res["likelihood"], res["impact"]), "high") and not t.get("acceptance"):
                out.append(Finding("TM-RESIDUAL", "error",
                                   f"threat {t['id']}: residual risk is {severity(policy, res['likelihood'], res['impact'])} and not accepted"))
        if t["status"] == "identified" and hi:
            out.append(Finding("TM-RESIDUAL", "error", f"{sev} threat {t['id']} is untreated"))

    ver = doc.get("verification")
    if doc["status"] not in ("approved", "verified"):
        out.append(Finding("TM-VERIFIED", "error", f"model status is '{doc['status']}'; must be approved/verified for release"))
    if not ver:
        out.append(Finding("TM-VERIFIED", "error", "no verification record — Security Team must verify model vs implementation (§8.1.4)"))
    else:
        if ver["verified_by"]["role"] not in SECURITY_ROLES:
            out.append(Finding("TM-VERIFIED", "error", "verification must be performed by the Security Team"))
        if not ver["attack_surface_delta_reviewed"]:
            out.append(Finding("TM-VERIFIED", "error", "attack-surface delta since design has not been reviewed"))
        for item in ver.get("new_attack_surface", []) or []:
            out.append(Finding("TM-VERIFIED", "warning", f"new attack surface recorded at verification: {item} — ensure it is modelled"))
        vdate = parse_date(ver["date"])
        fresh = policy["gates"]["verification_freshness_days"]
        if (today - vdate).days > fresh:
            out.append(Finding("TM-FRESH", "error", f"verification is {(today - vdate).days} days old (max {fresh})"))
        lu = parse_date(doc.get("last_updated"))
        if lu and lu > vdate:
            out.append(Finding("TM-FRESH", "error", f"model changed on {lu} after verification on {vdate} — re-verify"))
    return out


# --------------------------------------------------------------------- report
def summarize(ctx: Ctx, doc: dict) -> dict:
    policy = ctx.policy
    counts = {c: {s: 0 for s in SEVERITIES} for c in STRIDE_NAMES}
    residual = {s: 0 for s in SEVERITIES}
    for t in doc.get("threats", []):
        if t["status"] == "rejected":
            continue
        sev = severity(policy, t.get("likelihood"), t.get("impact"))
        if sev:
            counts[t["stride"]][sev] += 1
        r = t.get("residual")
        rs = severity(policy, r["likelihood"], r["impact"]) if r else (sev if t["status"] == "identified" else None)
        if rs:
            residual[rs] += 1
    return {"by_stride": counts, "residual": residual}


def _mermaid(model: Model) -> str:
    lines = ["flowchart LR"]
    shape = {"process": ('(("', '"))'), "data_store": ('[("', '")]'), "external_entity": ('["', '"]')}
    for z in model.zones.values():
        lines.append(f'  subgraph {z["id"]}["{z["name"]} (trust {z["trust"]})"]')
        for el in model.elements.values():
            if el["zone"] == z["id"]:
                o, c = shape[el["type"]]
                lines.append(f'    {el["id"]}{o}{el["name"]}{c}')
        lines.append("  end")
    for fl in model.flows.values():
        arrow = "-.->" if model.flow_crosses(fl) else "-->"
        lines.append(f'  {fl["from"]} {arrow}|"{fl["id"]}: {fl["protocol"]}"| {fl["to"]}')
    return "\n".join(lines)


def report(ctx: Ctx, doc: dict, stage: str, today=None) -> str:
    policy, model = ctx.policy, Model(doc, ctx.policy)
    f = doc["feature"]
    findings = validate(ctx, doc, stage, today)
    errors = [x for x in findings if x.level == "error"]
    s = summarize(ctx, doc)
    need, reasons = required_tier(policy, doc)
    md = [
        f"# Threat Model {doc['id']}: {f['title']}",
        "",
        f"**Product:** {f['product']} · **Owner:** {f['owner']['name']} · **Work item:** {f['work_item']} · "
        f"**Tier:** {doc['tier']} ({policy['triage']['tiers'][doc['tier']]['name']}) · **Status:** {doc['status']}",
        "",
        f"**{stage.title()} gate:** {'✅ PASS' if not errors else f'❌ FAIL ({len(errors)} blocking)'} — "
        f"policy {policy['policy']['id']} v{policy['policy']['version']}",
        "",
        "## 1. Triage",
        "",
        f"Required tier **{need}**" + (f" because: {'; '.join(reasons)}." if reasons else " (no triggers fired)."),
        "",
    ]
    if doc["tier"] > 0:
        md += ["## 2. Attack surface", "", "```mermaid", _mermaid(model), "```", "",
               "_Dashed arrows cross a trust boundary._", "",
               "| Entry point | Element | Authentication | Internet-facing |", "|---|---|---|---|"]
        for ep in doc.get("entry_points", []):
            el = model.elements.get(ep["element"], {})
            md.append(f"| {ep['id']}: {ep['description']} | {el.get('name', ep['element'])} | {ep['authentication']} | "
                      f"{'yes' if ep.get('internet_facing') or model.element_internet_facing(el) else 'no'} |")
        md += ["", f"Trust-boundary crossings: **{len(model.boundary_crossings())}** of {len(model.flows)} data flows.", "",
               "## 3. Threat landscape (inherent risk)", "",
               "| STRIDE | Critical | High | Medium | Low |", "|---|---|---|---|---|"]
        for c, name in STRIDE_NAMES.items():
            r = s["by_stride"][c]
            md.append(f"| {name} | {r['critical']} | {r['high']} | {r['medium']} | {r['low']} |")
        r = s["residual"]
        md += ["", f"**Residual / untreated:** Critical {r['critical']} · High {r['high']} · Medium {r['medium']} · Low {r['low']}", "",
               "## 4. Threats", "", "| ID | STRIDE | Target | Threat | Inherent | Status | Mitigations |", "|---|---|---|---|---|---|---|"]
        order = sorted(doc.get("threats", []),
                       key=lambda t: -(t.get("likelihood", 0) * t.get("impact", 0)))
        for t in order:
            sev = severity(policy, t.get("likelihood"), t.get("impact")) or "unscored"
            mits = "<br>".join(f"{m['id']} [{m['status']}] {m.get('work_item', '')}".strip() for m in t.get("mitigations", []))
            md.append(f"| {t['id']} | {t['stride']} | {t['target']} | {t['title']} | {sev} "
                      f"({t.get('likelihood', '?')}×{t.get('impact', '?')}) | {t['status']} | {mits} |")
        acc = [t for t in doc.get("threats", []) if t.get("acceptance")]
        if acc:
            md += ["", "## 5. Risk acceptances", "", "| Threat | Approved by | Risk Register | Review date |", "|---|---|---|---|"]
            for t in acc:
                a = t["acceptance"]
                md.append(f"| {t['id']} | {a['approved_by']['name']} ({a['approved_by']['role']}) | {a['risk_register_id']} | {a['review_date']} |")
    md += ["", "## Gate findings", ""]
    if not findings:
        md.append("No findings.")
    for x in findings:
        md.append(f"- {'❌' if x.level == 'error' else '⚠️'} **{x.rule}** {x.message}")
    md += ["", f"_Generated by threatmod on {(today or dt.date.today()).isoformat()} — retain as security evidence "
               f"({policy['policy']['evidence_retention_years']} years)._"]
    return "\n".join(md) + "\n"


# ------------------------------------------------------------------- check-pr
def check_pr(ctx: Ctx, changed: list[str], body: str, models_dir: Path) -> tuple[bool, str]:
    cfg = ctx.policy["ci_triggers"]
    def hit(path, globs):
        p = PurePosixPath(path)
        return any(p.full_match(g) or p.full_match(g.removeprefix("**/")) for g in globs)
    triggered = [c for c in changed if hit(c, cfg["path_globs"]) and not hit(c, cfg["ignore_globs"])]
    if not triggered:
        return True, "No security-relevant paths changed; threat model reference not required."
    model_changes = [c for c in changed if c.startswith(str(models_dir).rstrip("/") + "/")]
    m = re.search(cfg["reference_pattern"], body or "")
    head = "Security-relevant paths changed:\n  " + "\n  ".join(triggered[:20])
    if model_changes:
        return True, head + "\nThreat model updated in this PR: " + ", ".join(model_changes)
    if not m:
        return False, head + ("\n\nAdd 'Threat-Model: TM-<ID>' to the PR description (or 'Threat-Model: N/A - <reason ≥10 chars>' "
                              "reviewed by the Security Team), or update the model under " + str(models_dir) + ".")
    ref = m.group(1)
    if ref and ref.upper().startswith("TM-"):
        known = {}
        for p in models_dir.rglob("*.yaml") if models_dir.exists() else []:
            try:
                d = load_yaml(p)
                if isinstance(d, dict) and "id" in d:
                    known[d["id"]] = p
            except yaml.YAMLError:
                continue
        if ref not in known:
            return False, head + f"\n\nReferenced {ref} not found under {models_dir}."
        return True, head + f"\nReferenced threat model {ref} ({known[ref]})."
    return True, head + f"\nExemption claimed: '{m.group(0)}' — Security Team reviewer must confirm."


# --------------------------------------------------------------------- CLI
def find_models(paths):
    for p in map(Path, paths):
        if p.is_dir():
            yield from sorted(p.rglob("threat-model.yaml"))
        else:
            yield p


def cmd_init(ctx, a):
    out = Path(a.out or f"threat-models/{a.id.lower()}") / "threat-model.yaml"
    if out.exists():
        sys.exit(f"{out} already exists")
    out.parent.mkdir(parents=True, exist_ok=True)
    doc = load_yaml(ROOT / "templates/threat-model.template.yaml")
    doc["id"] = a.id
    doc["feature"].update(title=a.title, product=a.product, work_item=a.work_item)
    doc["feature"]["owner"].update(name=a.owner, email=a.owner_email or "")
    doc["last_updated"] = dt.date.today().isoformat()
    dump_yaml(doc, out)
    print(f"Created {out}. Next: answer `triage`, then run `threatmod triage {out} --write`.")


def cmd_triage(ctx, a):
    for path in find_models(a.paths):
        doc = load_yaml(path)
        need, reasons = required_tier(ctx.policy, doc)
        print(f"{path}: required tier {need} ({ctx.policy['triage']['tiers'][need]['name']})")
        for r in reasons:
            print(f"  - {r}")
        if a.write and doc.get("tier", 0) < need:
            doc["tier"] = need
            dump_yaml(doc, path)
            print(f"  tier raised to {need}")


def cmd_generate(ctx, a):
    for path in find_models(a.paths):
        doc = load_yaml(path)
        schema_errs = [f for f in validate(ctx, doc) if f.rule == "TM-SCHEMA"]
        if schema_errs:
            print(f"{path}: fix schema errors before generating threats")
            emit(schema_errs, path, "text")
            sys.exit(1)
        added = generate(ctx, doc)
        print(f"{path}: {len(added)} threat(s) generated")
        for t in added:
            print(f"  + {t['id']} [{t['stride']}] {t['title']}")
        if a.write and added:
            doc["last_updated"] = dt.date.today().isoformat()
            dump_yaml(doc, path)


def emit(findings, path, fmt):
    for x in findings:
        if fmt == "github":
            kind = "error" if x.level == "error" else "warning"
            print(f"::{kind} file={path},title={x.rule}::{x.message}")
        else:
            print(f"  {'ERROR' if x.level == 'error' else 'warn '} {x.rule:<15} {x.message}")


def cmd_validate(ctx, a):
    today = parse_date(a.today) if a.today else None
    failed, results = False, {}
    for path in find_models(a.paths):
        findings = validate(ctx, load_yaml(path), a.stage, today)
        errs = [f for f in findings if f.level == "error"]
        failed |= bool(errs)
        results[str(path)] = [asdict(f) for f in findings]
        if a.format != "json":
            print(f"{'FAIL' if errs else 'PASS'} {path} [{a.stage} gate] — {len(errs)} error(s), {len(findings) - len(errs)} warning(s)")
            emit(findings, path, a.format)
    if a.format == "json":
        print(json.dumps(results, indent=2))
    sys.exit(1 if failed else 0)


def cmd_report(ctx, a):
    today = parse_date(a.today) if a.today else None
    md = report(ctx, load_yaml(Path(a.path)), a.stage, today)
    if a.out:
        Path(a.out).write_text(md, encoding="utf-8")
        print(f"wrote {a.out}")
    else:
        print(md)


def cmd_check_pr(ctx, a):
    changed = [l.strip() for l in Path(a.changed_files).read_text().splitlines() if l.strip()]
    body = Path(a.pr_body_file).read_text() if a.pr_body_file and Path(a.pr_body_file).exists() else ""
    ok, msg = check_pr(ctx, changed, body, Path(a.models_dir))
    print(msg)
    sys.exit(0 if ok else 1)


def cmd_workitems(ctx, a):
    policy = ctx.policy
    w = csv.writer(sys.stdout)
    w.writerow(["Work Item Type", "Title", "Description", "Acceptance Criteria", "Priority", "Tags"])
    prio = {"critical": 1, "high": 1, "medium": 2, "low": 3}
    for path in find_models(a.paths):
        doc = load_yaml(path)
        for t in doc.get("threats", []):
            if t["status"] in ("rejected", "accepted", "transferred"):
                continue
            sev = severity(policy, t.get("likelihood"), t.get("impact")) or "low"
            for m in t.get("mitigations", []):
                if m.get("work_item") or (a.committed_only and m["status"] == "proposed"):
                    continue
                w.writerow(["User Story", f"[{doc['id']}] {m['description'][:200]}",
                            f"Mitigates {t['id']} ({STRIDE_NAMES[t['stride']]}, {sev}): {t['title']}",
                            f"SECURITY: {m['description']} (domain: {m['domain']}; ISMS-DEV-003 §6.1)",
                            prio[sev], f"security; threat-model; {doc['id']}; {m['domain']}"])


def main(argv=None):
    p = argparse.ArgumentParser(prog="threatmod", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--policy"); p.add_argument("--library"); p.add_argument("--schema")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("init"); s.set_defaults(fn=cmd_init)
    s.add_argument("--id", required=True, help="TM-<PRODUCT>-<WORKITEM>, e.g. TM-NMM-48211")
    s.add_argument("--title", required=True); s.add_argument("--product", required=True, choices=["NME", "NMM", "Platform", "Internal"])
    s.add_argument("--owner", required=True); s.add_argument("--owner-email"); s.add_argument("--work-item", required=True)
    s.add_argument("--out")

    s = sub.add_parser("triage"); s.set_defaults(fn=cmd_triage); s.add_argument("paths", nargs="+"); s.add_argument("--write", action="store_true")
    s = sub.add_parser("generate"); s.set_defaults(fn=cmd_generate); s.add_argument("paths", nargs="+"); s.add_argument("--write", action="store_true")

    s = sub.add_parser("validate"); s.set_defaults(fn=cmd_validate); s.add_argument("paths", nargs="+")
    s.add_argument("--stage", choices=["design", "release"], default="design")
    s.add_argument("--format", choices=["text", "github", "json"], default="text"); s.add_argument("--today")

    s = sub.add_parser("report"); s.set_defaults(fn=cmd_report); s.add_argument("path")
    s.add_argument("--stage", choices=["design", "release"], default="design"); s.add_argument("--out"); s.add_argument("--today")

    s = sub.add_parser("check-pr"); s.set_defaults(fn=cmd_check_pr)
    s.add_argument("--changed-files", required=True); s.add_argument("--pr-body-file"); s.add_argument("--models-dir", default="threat-models")

    s = sub.add_parser("workitems"); s.set_defaults(fn=cmd_workitems); s.add_argument("paths", nargs="+")
    s.add_argument("--committed-only", action="store_true", help="skip mitigations still in 'proposed' status")

    a = p.parse_args(argv)
    try:
        a.fn(Ctx(a.policy, a.library, a.schema), a)
    except BrokenPipeError:  # output piped to `head` etc.
        sys.stderr.close()


if __name__ == "__main__":
    main()
