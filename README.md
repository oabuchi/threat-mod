# threat-mod — Nerdio Threat Modelling as Code (ISMS-DEV-004)

This repository puts into practice the threat modelling requirements of **ISMS-DEV-003 Secure Software Development Policy v3.3** (§6.2 STRIDE threat modelling, §6.3 Architectural Security Review, §8.1.4 verification before release, §15 risk acceptance). Teams use it to define, score, treat and evidence the **threat landscape of every feature**, with the checks running automatically in CI.

| What | Where |
|---|---|
| Policy (governing text) | [`policy/ISMS-DEV-004-threat-modeling-policy.md`](policy/ISMS-DEV-004-threat-modeling-policy.md) · branded Word copy in [`dist/`](dist/) |
| Machine-readable rule set | [`policy/threat-modeling-policy.yaml`](policy/threat-modeling-policy.yaml) |
| Threat model schema | [`schema/threat-model.schema.json`](schema/threat-model.schema.json) |
| Nerdio STRIDE threat library | [`catalog/stride-threat-library.yaml`](catalog/stride-threat-library.yaml) |
| CLI | [`threatmod/`](threatmod/) |
| GitHub reusable workflow | [`.github/workflows/threat-model.yml`](.github/workflows/threat-model.yml) |
| Azure DevOps release gate | [`pipelines/threat-model-gate.yml`](pipelines/threat-model-gate.yml) |
| Worked Tier 2 example | [`examples/tm-nmm-48211/`](examples/tm-nmm-48211/) ([rendered report](examples/tm-nmm-48211/threat-model-report.md)) |
| Diagram-to-SIA example | [`examples/assess-demo/`](examples/assess-demo/) ([SIA](examples/assess-demo/output/security-impact-assessment.md)) |

## Quick start for a feature team

```bash
pip install -r requirements.txt
export PYTHONPATH=/path/to/threat-mod     # or THREATMOD_HOME for policy files

# 1. Scaffold, then answer the 9 triage questions in the file
python -m threatmod init --id TM-NMM-48211 --title "PSA webhook triggers Scripted Actions" \
  --product NMM --owner "Jordan Example" --work-item https://dev.azure.com/nerdio/NMM/_workitems/edit/48211
python -m threatmod triage threat-models/tm-nmm-48211 --write        # computes tier 0/1/2

# 2. Model assets, trust zones, elements, data flows, entry points — then seed STRIDE threats
python -m threatmod generate threat-models/tm-nmm-48211 --write

# 3. Score, treat, link work items; check the design gate
python -m threatmod validate threat-models --stage design
python -m threatmod workitems threat-models/tm-nmm-48211 --committed-only > ado-import.csv

# 4. See the threat landscape
python -m threatmod report threat-models/tm-nmm-48211/threat-model.yaml --out landscape.md

# 5. Before release (after Security Team verification)
python -m threatmod validate threat-models --stage release
```

## Start from a diagram or requirements doc (AI-assisted)

```bash
pip install -r requirements-assess.txt        # anthropic SDK
export ANTHROPIC_API_KEY=...                   # or `ant auth login`
python -m threatmod assess design/architecture.png design/requirements.md \
  --id TM-NME-52310 --owner "Priya Example" --work-item https://dev.azure.com/nerdio/NME/_workitems/edit/52310
```

Outputs in `threat-models/tm-nme-52310/`: `threat-model.yaml` (draft), `threat-model-report.md`,
`security-impact-assessment.md`, plus `extraction.json` and `assessment.json` showing what Claude was given and returned.
Claude only extracts the feature description from the inputs and drafts the narrative; the tier, threats, scores and gate
verdict come from the policy engine. Accepts PNG/JPG/WebP diagrams, PDF, DOCX, Markdown and text.
See `examples/assess-demo/` for a full sample, and `.github/workflows/threat-model-assess.yml` to run it on upload.

## Human sign-off and development-time checks

```bash
# After the Security Team reviews and corrects the AI draft (Tier 2 needs the final SIA rating confirmed)
python -m threatmod sign-off threat-models/tm-nme-52310/threat-model.yaml \
  --by "Avery SecTeam:security_team" --sia-rating high --rating-confirmed-by "A. Markell:head_of_information_security" \
  --changes "Rejected 6 generated threats on Microsoft-internal flows"

# In the PR that implements a security requirement
python -m threatmod mark-implemented threat-models/tm-nme-52310/threat-model.yaml \
  --mitigations M-P1-FEAT-004-1 M-P1-S-002-1 --evidence https://dev.azure.com/nerdio/NME/_git/nme/pullrequest/9120
# ...and in the PR body:  Threat-Model: TM-NME-52310  /  Mitigates: M-P1-FEAT-004-1, M-P1-S-002-1

# Scorecard for sprint review / release stage
python -m threatmod coverage threat-models --stage release
```

An AI-drafted model fails `TM-VALIDATED` until a person signs it off; `check-pr` fails `TM-PR-EVIDENCE` if a PR claims a mitigation that isn't marked implemented with evidence; `coverage` shows how many committed mitigations are done, by §6.1 domain and threat severity. See `examples/assess-demo/validated/` for the demo model after review and one implementation PR.

## What the gates enforce

**Design gate:**

- `TM-SCHEMA`: the model conforms to the schema
- `TM-TRIAGE`: the declared tier is at least the computed tier
- `TM-SCOPE`: assets, zones, elements, flows and entry points are present
- `TM-STRIDE`: STRIDE-per-element completeness
- `TM-SCORED`: every threat has likelihood × impact
- `TM-TREATED`: every Medium+ threat has a treatment
- `TM-WORKITEM`: every committed mitigation links to a work item that carries it as a security acceptance criterion
- `TM-ACCEPTANCE`: risk acceptances follow §15 tiers, with no self-approval, a review date of 365 days or less, and a Risk Register ID
- `TM-VALIDATED`: an AI-drafted model has a human validation record (Security Team for Tier 2, with the SIA rating confirmed)
- `TM-ARCH-REVIEW` / `TM-APPROVAL`: Tier 2 has the §6.3 review and Security Team sign-off

**Release gate** (everything in the design gate, plus):

- `TM-IMPLEMENTED`: High/Critical mitigations are implemented with evidence
- `TM-RESIDUAL`: no unaccepted High/Critical residual risk
- `TM-VERIFIED`: Security Team verification, including the attack-surface delta
- `TM-FRESH`: verification is 30 days old or less and newer than the last model change

**PR check** (`check-pr`): a PR that touches security-relevant paths must contain `Threat-Model: TM-<ID>` or update a model (`TM-PR-REFERENCE`); any `Mitigates: M-…` it claims must be implemented with evidence in the model (`TM-PR-EVIDENCE`).

## Using it from a product repository

```yaml
# .github/workflows/security.yml
jobs:
  threat-model:
    uses: oabuchi/threat-mod/.github/workflows/threat-model.yml@main
    with: { models-dir: threat-models }
```

Azure DevOps: see the header of `pipelines/threat-model-gate.yml`.

## Maintaining the policy

- Thresholds live only in `policy/threat-modeling-policy.yaml`. If you change one, update the policy text in the same PR.
- Rebuild the Word copy: `NODE_PATH=$(npm root -g) node tools/build-policy-docx.js`
- Tests: `python -m unittest discover -s tests -v`
