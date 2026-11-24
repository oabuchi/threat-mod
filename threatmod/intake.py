"""threatmod intake — turn a submitted intake request into a triaged threat model and check the package.

Accepts the YAML intake form (templates/intake-request.yaml) or the body of a GitHub issue created
from .github/ISSUE_TEMPLATE/threat-model-intake.yml (the '### Label' / answer format). Produces
threat-models/<id>/threat-model.yaml with triage filled in and the tier computed, copies attachments
to inputs/, and reports the intake decision: closed_tier0, needs_info, or accepted (with routing and
SLAs from the policy's `intake` section).
"""
from __future__ import annotations

import datetime as dt
import re
import shutil
from pathlib import Path

import yaml

from . import cli as engine

YES = {"yes", "true", "y", "1"}
URL_RE = re.compile(r"^https?://", re.I)


# --------------------------------------------------------------------------- parsing
def parse_issue_body(text: str, policy: dict) -> dict:
    """GitHub issue-form bodies render as '### <label>\\n\\n<answer>' blocks."""
    blocks = re.split(r"^### ", text, flags=re.M)
    answers = {}
    for b in blocks:
        if not b.strip():
            continue
        label, _, val = b.partition("\n")
        answers[label.strip().lower()] = val.strip()

    def get(*labels):
        for l in labels:
            for k, v in answers.items():
                if k.startswith(l.lower()):
                    return v
        return ""

    triage = {}
    for i, (q, meta) in enumerate(policy["triage"]["questions"].items(), 1):
        triage[q] = get(f"triage {i} ").lower() in YES
    package = {}
    for line in get("intake package").splitlines():
        k, sep, v = line.partition(":")
        if sep and k.strip().lower() in policy["intake"]["package_items"]:
            package[k.strip().lower()] = v.strip()
    title = get("title")
    return {
        "title": title, "product": get("product"), "owner": get("feature owner"), "work_item": get("work item"),
        "target_release": get("target release"), "dev_start": get("planned development start"),
        "repositories": [r.strip() for r in get("repositories").split(",") if r.strip()],
        "description": get("description"), "data_classification": get("highest data classification").lower(),
        "emergency": get("emergency change").lower() in YES, "triage": triage, "package": package,
        "external_parties": [x for x in get("third parties").splitlines() if x.strip()],
        "notes": get("notes for the security team"),
    }


def load_request(path: Path, policy: dict, title: str | None = None) -> dict:
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() in (".yaml", ".yml"):
        req = yaml.safe_load(text) or {}
    else:
        req = parse_issue_body(text, policy)
        if title:
            req["title"] = re.sub(r"^\[intake\]\s*", "", title, flags=re.I).strip()
    req.setdefault("triage", {})
    req.setdefault("package", {})
    req.setdefault("repositories", [])
    return req


# --------------------------------------------------------------------------- checks
def working_days_until(start: dt.date, end: dt.date) -> int:
    days, d = 0, start
    while d < end:
        d += dt.timedelta(days=1)
        if d.weekday() < 5:
            days += 1
    return days


def evaluate(policy: dict, req: dict, inputs_dir: Path | None, today: dt.date) -> dict:
    """Compute tier, check fields and package, decide the intake state."""
    icfg = policy["intake"]
    problems, warnings = [], []
    for f in icfg["required_fields"]:
        if not req.get(f):
            problems.append(f"missing field: {f}")
    missing_triage = [q for q in policy["triage"]["questions"] if q not in req["triage"]]
    if missing_triage:
        problems.append("triage questions unanswered: " + ", ".join(missing_triage))
    cls = req.get("data_classification")
    if cls and cls not in policy["triage"]["classification_min_tier"]:
        problems.append(f"unknown data_classification '{cls}'")

    pseudo = {"triage": req["triage"], "data_classification": cls if cls in policy["triage"]["classification_min_tier"] else None}
    tier, reasons = engine.required_tier(policy, pseudo)

    # package completeness for the computed tier
    missing_pkg = []
    for item in icfg["required_package"][tier]:
        ref = (req["package"] or {}).get(item, "")
        if not ref:
            missing_pkg.append(item)
            continue
        if URL_RE.match(ref):
            continue
        if inputs_dir is None or not (inputs_dir / ref).exists():
            missing_pkg.append(f"{item} (file '{ref}' not found in inputs/)")
        else:
            ext = Path(ref).suffix.lstrip(".").lower()
            if ext not in icfg["package_items"][item]["accepts"]:
                warnings.append(f"{item}: '{ref}' has an unexpected type .{ext}")

    # lead time before development start
    lead_ok = True
    if req.get("dev_start"):
        try:
            ds = engine.parse_date(req["dev_start"])
            need = icfg["sla_working_days"]["lead_time_before_dev_start"].get(tier, 0)
            have = working_days_until(today, ds)
            if tier > 0 and have < need and not req.get("emergency"):
                lead_ok = False
                warnings.append(f"only {have} working day(s) before dev start; policy expects {need} for tier {tier}")
        except ValueError:
            problems.append("dev_start is not a date (YYYY-MM-DD)")

    if problems or missing_pkg:
        state = "needs_info"
    elif tier == 0:
        state = "closed_tier0"
    else:
        state = "accepted"
    sla = icfg["sla_working_days"]
    due = {"completeness_decision": sla["completeness_decision"]}
    if tier == 2:
        due.update(facilitator_assigned=sla["facilitator_assigned"], session_scheduled=sla["session_scheduled"])
    if req.get("emergency"):
        due = {"triage": icfg["emergency"]["triage_within_working_days"],
               "remodel": icfg["emergency"]["remodel_within_working_days"]}
    return {"tier": tier, "reasons": reasons, "state": state, "problems": problems, "missing_package": missing_pkg,
            "warnings": warnings, "lead_time_ok": lead_ok, "routing": icfg["routing"][tier],
            "due_working_days": due, "emergency": bool(req.get("emergency"))}


# --------------------------------------------------------------------------- model creation
def build_model(ctx: engine.Ctx, req: dict, model_id: str, result: dict, today: dt.date) -> dict:
    doc = engine.load_yaml(engine.ROOT / "templates/threat-model.template.yaml")
    doc["id"] = model_id
    doc["feature"].update(title=req["title"], product=req["product"], description=req.get("description", ""),
                          work_item=req["work_item"], repositories=req.get("repositories", []),
                          target_release=req.get("target_release", ""))
    doc["feature"]["owner"].update(name=req["owner"], email=req.get("owner_email", ""))
    if not doc["feature"]["owner"]["email"]:
        del doc["feature"]["owner"]["email"]
    doc["tier"] = result["tier"]
    doc["last_updated"] = today.isoformat()
    doc["data_classification"] = req["data_classification"]
    doc["triage"] = {q: bool(req["triage"].get(q, False)) for q in ctx.policy["triage"]["questions"]}
    doc["references"] = [f"Intake submitted {today.isoformat()}; state {result['state']}; package: "
                         + ", ".join(f"{k}={v}" for k, v in (req.get("package") or {}).items() if v)]
    return doc


def intake(ctx: engine.Ctx, request: Path, model_id: str, out_dir: Path, attachments: list[Path],
           today: dt.date | None = None, issue_title: str | None = None, write: bool = True) -> dict:
    today = today or dt.date.today()
    req = load_request(request, ctx.policy, issue_title)
    inputs_dir = out_dir / "inputs"
    if write:
        inputs_dir.mkdir(parents=True, exist_ok=True)
        for a in attachments:
            shutil.copy2(a, inputs_dir / a.name)
    present = inputs_dir if inputs_dir.exists() else None
    if not present and attachments:
        present = Path(attachments[0]).parent
    result = evaluate(ctx.policy, req, present, today)
    result["id"], result["request"] = model_id, req
    if write:
        doc = build_model(ctx, req, model_id, result, today)
        engine.dump_yaml(doc, out_dir / "threat-model.yaml")
        shutil.copy2(request, out_dir / ("intake-request" + request.suffix))
        result["model_path"] = str(out_dir / "threat-model.yaml")
    return result


def render(result: dict, policy: dict) -> str:
    tiers = policy["triage"]["tiers"]
    lines = [f"Intake {result['id']}: {result['request'].get('title') or '(untitled)'}",
             f"  computed tier: {result['tier']} ({tiers[result['tier']]['name']})"]
    lines += [f"    - {r}" for r in result["reasons"]] or ["    - no triage trigger fired"]
    lines.append(f"  state: {result['state'].upper()}" + (" (EMERGENCY fast path)" if result["emergency"] else ""))
    for p in result["problems"]:
        lines.append(f"  ! {p}")
    for m in result["missing_package"]:
        lines.append(f"  ! package item required for tier {result['tier']}: {m}")
    for w in result["warnings"]:
        lines.append(f"  ~ {w}")
    lines.append(f"  routing: {result['routing']}")
    if result["state"] != "closed_tier0":
        lines.append("  due (working days from submission): " + ", ".join(f"{k} ≤ {v}" for k, v in result["due_working_days"].items()))
    if result.get("model_path"):
        lines.append(f"  model: {result['model_path']}")
    return "\n".join(lines)


def cmd_intake(ctx: engine.Ctx, a):
    out = Path(a.out or f"threat-models/{a.id.lower()}")
    attachments = [Path(p) for p in a.attach]
    for p in attachments:
        if not p.exists():
            raise SystemExit(f"attachment not found: {p}")
    r = intake(ctx, Path(a.request), a.id, out, attachments,
               today=engine.parse_date(a.today) if a.today else None, issue_title=a.issue_title, write=not a.dry_run)
    print(render(r, ctx.policy))
    if a.format == "json":
        import json
        print(json.dumps({k: v for k, v in r.items() if k != "request"}, indent=2, default=str))
    raise SystemExit(0 if r["state"] in ("accepted", "closed_tier0") else 2)


def add_parser(sub):
    s = sub.add_parser("intake", help="turn an intake request (YAML form or issue body) into a triaged model and check the package")
    s.set_defaults(fn=cmd_intake)
    s.add_argument("request", help="intake-request.yaml or a GitHub issue body (.md/.txt)")
    s.add_argument("--id", required=True, help="TM-<PRODUCT>-<WORKITEM>")
    s.add_argument("--attach", nargs="*", default=[], help="files to copy into <out>/inputs/")
    s.add_argument("--out"); s.add_argument("--issue-title"); s.add_argument("--today")
    s.add_argument("--dry-run", action="store_true", help="evaluate only; write nothing")
    s.add_argument("--format", choices=["text", "json"], default="text")
