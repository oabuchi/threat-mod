# Threat Modelling Policy

| Field | Value |
|---|---|
| Organization | Nerdio |
| Document ID | ISMS-DEV-004 (proposed) |
| Version | 1.0 (Draft for review) |
| Effective Date | Upon CPTO approval |
| Parent Policy | ISMS-DEV-003 Secure Software Development Policy v3.3 |
| Classification | Confidential — Internal Use Only |
| Policy Owner | Head of Information Security (Security Team) |
| Approval Authority | CPTO; reviewed by VP Technical Solutions and Head of Information Security |
| Applicable Controls | ISO/IEC 27001:2022 A.8.25, A.8.26, A.8.27, A.8.29 · NIST SP 800-218 PO.4, PW.1, PW.2, RV.3 · Microsoft SDL Design, Verification |

## Document Control

| Edited By | Date | Description | Reviewed By | Review Date |
|---|---|---|---|---|
| Information Security Manager | 2026-11-05 | v1.0: Initial draft. Derives threat modelling requirements from ISMS-DEV-003 v3.3 §6.2, §6.3, §8.1.4 and §15 and encodes them as an automatable rule set. | Head of Information Security | Pending |

## 1. Purpose and Scope

### 1.1 Purpose

ISMS-DEV-003 requires a formal STRIDE threat modelling exercise for every feature that involves architectural decisions, data handling changes, new integrations or elevated security risk (§6.2), and requires the threat model to be verified against the final implementation before release (§8.1.4). This policy sets out how Nerdio teams meet those requirements in a consistent, measurable and **automatable** way, so that the threat landscape of every feature is defined, scored, treated and evidenced as part of normal engineering flow rather than as a separate manual exercise.

This policy is written to be enforced as code. Every requirement marked with a rule ID (for example **TM-STRIDE**) is evaluated automatically by the `threatmod` tooling against the machine-readable rule set `policy/threat-modeling-policy.yaml`. Where this document and the rule set differ, this document governs and the rule set must be corrected.

### 1.2 Scope

This policy applies to:

- All features, epics and changes to Nerdio software in scope of ISMS-DEV-003, including Nerdio Manager for Enterprise (NME), Nerdio Manager for MSPs (NMM), shared platform services and internal tools that process customer data
- All infrastructure-as-code (Bicep, ARM, Terraform) and pipeline changes that alter trust boundaries, identities or network exposure
- Outsourced development performed on Nerdio's behalf (ISMS-DEV-003 §11)
- All Nerdio employees, contractors and third parties who design, build, review or release that software

### 1.3 Exclusions

- Changes with no security impact (copy, styling, documentation, test-only changes) are excluded from modelling but not from triage. The triage record is the evidence of exclusion.
- Corporate IT systems not developed by Nerdio are governed by the Risk Management Program (ISMS-RISK-001).

### 1.4 Relationship to ISMS-DEV-003

| ISMS-DEV-003 requirement | Implemented in this policy | Automated rule |
|---|---|---|
| §6.2 When a threat model is required | §4.1 Applicability triage | TM-TRIAGE |
| §6.2 step 1: assets, data flows, trust boundaries, entry points | §4.4 Scope the feature | TM-SCOPE |
| §6.2 step 2: enumerate STRIDE threats per component | §4.5 Enumerate threats | TM-STRIDE |
| §6.2 step 3: likelihood and impact scoring | §4.6 Score risk | TM-SCORED |
| §6.2 step 4: mitigations incorporated into design | §4.7 Treat threats | TM-TREATED, TM-WORKITEM |
| §6.1 security requirements as story acceptance criteria | §4.7 Treat threats | TM-WORKITEM |
| §6.2 step 5: document and retain as evidence | §4.11 Evidence and retention | Report artefact |
| §6.3 Architectural Security Review | §4.3 Tier 2 | TM-ARCH-REVIEW, TM-APPROVAL |
| §8.1.4 verify threat model before release | §4.9 Release verification | TM-IMPLEMENTED, TM-RESIDUAL, TM-VERIFIED, TM-FRESH |
| §12.2 remediation SLAs | §4.10 Post-release threats | Rule set `remediation_sla_days` |
| §12.3 root cause analysis | §4.10 Re-modelling triggers | Rule set `remodel_triggers` |
| §15 exceptions and risk acceptance | §4.8 Risk acceptance | TM-ACCEPTANCE |

## 2. Roles and Responsibilities

| Role | Accountability | Key duties under this policy |
|---|---|---|
| CPTO | Executive owner | Approves this policy; accepts High and Critical residual risk on the recommendation of the Head of Information Security. |
| Head of Information Security | Policy owner | Owns the rule set and threat library; accepts Low and Medium residual risk; recommends High and Critical acceptances; reports threat modelling KPIs. |
| VP Technical Solutions | Independent oversight | Reviews this policy; receives KPI and compliance reporting. |
| Security Team | Assurance | Facilitates Tier 2 sessions; approves Tier 2 designs; verifies every model before release; maintains the threat library, schema and CI gates. May withhold release approval (ISMS-DEV-003 §2). |
| Feature Owner (Development Team lead) | Model owner | Completes triage; owns the threat model file; ensures mitigations are planned, implemented and evidenced; keeps the model current. |
| Development Team | Contributors | Participates in modelling; implements mitigations; records evidence; raises re-modelling triggers. |
| QA Team | Verification | Turns mitigations into test cases; confirms evidence before release. |
| DevOps Team | Pipeline | Runs the threat model gates in GitHub and Azure DevOps pipelines; protects pipeline configuration. |
| VP of Product & Engineering | Requirements | Ensures security acceptance criteria from threat models are scheduled in sprint scope. |

No individual may approve a threat model, or accept a risk, for a feature they own or requested (ISMS-DEV-003 §15).

## 3. Definitions

| Term | Definition |
|---|---|
| Threat landscape | The full set of assets, trust zones, entry points, data flows, threats and residual risks for a feature, as recorded in its threat model and rendered by `threatmod report`. |
| Threat model file | A YAML document (`threat-models/<id>/threat-model.yaml`) conforming to `schema/threat-model.schema.json`. It is the system of record for the feature's threat model. |
| Element | A process, data store or external entity in the feature's data flow diagram. |
| Trust zone | A region of uniform trust (for example Internet = 0, NMM data plane = 9). A data flow between different zones crosses a trust boundary. |
| STRIDE-per-element | Microsoft SDL technique that assigns the applicable STRIDE categories to each element type (§4.5). |
| Inherent risk | Likelihood × impact before mitigations. |
| Residual risk | Likelihood × impact after the planned mitigations are implemented. |
| Gate | An automated check (design or release) that must pass before work proceeds. |

## 4. Policy Requirements

### 4.1 Applicability Triage (TM-TRIAGE)

1. Every feature, epic or change request in scope must have a triage record before development begins. Teams record it by answering the nine triage questions in the threat model file.
2. The triage questions are: architectural change; data handling change; new integration; authentication or authorization change; new external entry point; privileged Azure or Entra ID operation; cross-tenant data; Restricted data; and cryptography change.
3. Any "yes" answer means a threat model is required. The required tier is the highest tier triggered by any answer or by the feature's highest data classification. `threatmod triage` computes it.
4. The declared tier may be raised but never lowered below the computed tier.
5. In CI, a pull request that changes security-relevant paths (authentication, APIs, webhooks, infrastructure-as-code, cryptography, secrets, configuration, data migrations or dependency manifests) must reference a threat model, either with `Threat-Model: TM-<ID>` in the PR description or by updating a model in the same PR. An exemption (`Threat-Model: N/A - <reason>`) must be confirmed by a Security Team reviewer.

### 4.2 Threat Model Identifier and Location

1. Each model has the identifier `TM-<PRODUCT>-<WORK ITEM>`, for example `TM-NMM-48211`.
2. Models are stored in the product repository under `threat-models/<id>/threat-model.yaml`, beside the code they describe. They are changed only through pull requests subject to branch protection (ISMS-DEV-003 §7.4).
3. Diagrams produced in the Microsoft Threat Modeling Tool may be attached as supporting material, but the YAML model is the system of record and the input to all gates.

### 4.3 Modelling Tiers

| Tier | Name | Triggered by | Facilitator | Approval required |
|---|---|---|---|---|
| 0 | Not required | No triage trigger; Public or Internal data only | Feature Owner | None (triage record retained) |
| 1 | Standard | Architectural, data handling or integration change; Confidential data | Development Team | Design approval by a reviewer other than the Feature Owner |
| 2 | Enhanced | Authentication or authorization change, new external entry point, privileged Azure operation, cross-tenant data, Restricted data or cryptography change | Security Team | Security Team design approval plus Architectural Security Review (ISMS-DEV-003 §6.3) |

For Tier 2, the Architectural Security Review must record a decision for each of the seven §6.3 domains: authentication and identity; access control and least privilege; encryption in transit and at rest; data handling, classification and retention; external interfaces and API security; consent and data subject rights; and residual risk acceptance (**TM-ARCH-REVIEW**, **TM-APPROVAL**).

### 4.4 Scope the Feature (TM-SCOPE)

For Tier 1 and Tier 2, the model must identify (ISMS-DEV-003 §6.2 step 1):

- **Assets**, each with a data classification (Public, Internal, Confidential, Restricted)
- **Trust zones**, at least two, each with a trust level from 0 (untrusted internet) to 10
- **Elements** (processes, data stores, external entities), each placed in a trust zone, with technology recorded and flags for multi-tenancy and internet exposure
- **Data flows** between elements, with protocol, assets carried, authentication and encryption
- **Entry points**, with the authentication mechanism and internet exposure of each

Trust boundaries are derived automatically from the zones of each flow's source and destination. If no flow crosses a boundary, the tooling raises a warning, because in practice that usually means the zones were modelled wrongly.

### 4.5 Enumerate Threats (TM-STRIDE)

1. Threats are enumerated using STRIDE-per-element:

| Element type | Applicable STRIDE categories |
|---|---|
| External entity | Spoofing, Repudiation |
| Process | Spoofing, Tampering, Repudiation, Information disclosure, Denial of service, Elevation of privilege |
| Data store | Tampering, Repudiation, Information disclosure, Denial of service |
| Data flow | Tampering, Information disclosure, Denial of service |

2. Teams run `threatmod generate` to seed threats from the Nerdio STRIDE Threat Library (`catalog/stride-threat-library.yaml`). The library covers Nerdio-specific concerns, including multi-tenant (MSP and customer) isolation, privileged ARM and Graph identities, Scripted Action execution, webhooks and Key Vault. Generation is idempotent and never overwrites human edits.
3. Generated threats are a starting point, not the model. Teams must add threats specific to the feature's business logic (`source: manual`) and remove irrelevant ones only by marking them `rejected` with a `rejection_reason`.
4. Every applicable STRIDE category on every element and data flow must be addressed, either by at least one threat or by a `not_applicable` entry with a written justification.

### 4.6 Score Risk (TM-SCORED)

1. Every threat that has not been rejected is scored for likelihood (1–5) and impact (1–5). Risk = likelihood × impact.
2. Severity bands, aligned with ISMS-SEC-002:

| Severity | Score |
|---|---|
| Critical | 20–25 |
| High | 12–19 |
| Medium | 6–11 |
| Low | 1–5 |

3. Generated threats receive conservative default scores. Likelihood starts at 3 and is raised by 1 when the target is internet-facing or crosses a trust boundary. Impact is set by data classification (Restricted = 4) and is set to 5 for information disclosure and elevation of privilege on multi-tenant elements. Teams must review and adjust every default score.
4. Scoring anchors for each level are defined in the rule set and in Appendix B.

### 4.7 Treat Threats (TM-TREATED, TM-WORKITEM)

1. Every Medium, High or Critical threat must have a treatment decision before the design gate. Low threats without a decision generate a warning.
2. Permitted treatments:
   - `mitigation_planned` or `mitigated`, with at least one committed mitigation
   - `accepted`, with a valid risk acceptance (§4.8)
   - `transferred`, with a rationale (for example, the customer's responsibility under the shared-responsibility model)
   - `rejected`, with a rationale
3. Each mitigation is tagged with an ISMS-DEV-003 §6.1 security requirement domain, or with the added domains for tenant isolation and availability.
4. Each committed mitigation must link to a work item that carries it as a **security acceptance criterion** (ISMS-DEV-003 §6.1, SSDF PO.4). `threatmod workitems` exports mitigations as an Azure DevOps CSV for bulk import.
5. For every High or Critical threat, teams record the expected residual likelihood and impact after mitigation.

### 4.8 Risk Acceptance (TM-ACCEPTANCE)

Risk acceptance follows ISMS-DEV-003 §15. The tooling enforces:

| Residual severity | Approver | Additional requirement |
|---|---|---|
| Low, Medium | Head of Information Security (or CPTO) | None |
| High | CPTO | Recommendation from the Head of Information Security |
| Critical | CPTO | Recommendation from the Head of Information Security; ratification at the next ISMS Management Review |

Every acceptance must record:

- requester and approver
- approval date
- a review date no more than 365 days after approval
- the ISMS Risk Register ID
- the justification
- the compensating controls

The approver may not be the requester or the Feature Owner. An acceptance past its review date fails every gate until it is reviewed again.

### 4.9 Release Verification (TM-IMPLEMENTED, TM-RESIDUAL, TM-VERIFIED, TM-FRESH)

Before release (ISMS-DEV-003 §8.1.4, §9.1 step 2):

1. Every mitigation for a High or Critical threat is `implemented` or `verified`, with `evidence` such as a pull request, test, pipeline run or configuration reference. The threat status is `mitigated`. Unimplemented Medium and Low mitigations generate warnings and are tracked to closure.
2. No High or Critical residual risk remains unless it has been accepted under §4.8.
3. The Security Team records a verification confirming that the model matches the implementation and that any **attack surface added since design** has been reviewed and modelled. The model status is `approved` or `verified`.
4. Verification must be no older than 30 days at release, and the model must not have changed since it was verified.

The release gate runs in the Azure DevOps release pipeline. A failed gate makes the build ineligible for release without documented Security Team authorization (ISMS-DEV-003 §9.2).

### 4.10 Maintenance, Re-modelling and Post-release Threats

1. The model returns to `draft` and must pass the design gate again when:
   - the architecture, data flows or trust boundaries change materially
   - new attack surface is identified
   - a Critical or High vulnerability is found in the feature (root cause analysis per ISMS-DEV-003 §12.3)
   - a Tier 2 feature reaches 12 months since its last verification
2. Threats discovered after release (`source: pentest`, `incident` or `rca`) are added to the model and remediated within the ISMS-SEC-002 SLAs: Critical 7 days, High 14 days, Medium 30 days, Low 90 days.
3. When a feature is decommissioned (ISMS-DEV-003 §13), its model is set to `retired` and retained.

### 4.11 Evidence and Retention

The threat model file, its Git history, and the Markdown landscape report produced by `threatmod report` together form the security evidence for the feature (ISMS-DEV-003 §6.2 step 5). CI publishes the report as a pipeline artefact on every run. The Security Team archives the release-gate report with the change record (ISMS-CMP-001), and evidence is retained for at least three years.

### 4.12 Human Validation of AI-Assisted Drafts (TM-VALIDATED)

A threat model or SIA produced with AI assistance (§5.3) is not in place until a person has validated it. The model's `provenance.ai_assisted` flag is set by the tooling and cannot be removed; while it is set:

1. A `validation` record is required before any design approval counts and before the model may carry the status `approved` or `verified`. It names the validator, the date, and the scope validated: the extraction (does the model match the diagram and requirements?), the threats (are the generated and feature-specific threats right, and are rejections justified?), the scores, and the SIA narrative.
2. For Tier 1, any engineer other than the author of the inputs may validate. For Tier 2, the validator must be a member of the Security Team, must not be the Feature Owner, and the SIA's security impact rating must be confirmed by the Head of Information Security (or CPTO) and recorded as the final rating.
3. Validation must be dated on or after the generation date. Re-running the assessment resets the generation date and requires a new validation.
4. Corrections made during validation are recorded in `changes_made`, so that the difference between what the AI produced and what was approved is auditable.
5. The validation is recorded with `threatmod sign-off`, which also checks the record against these rules.

### 4.13 Development-time Verification (TM-PR-REFERENCE, TM-PR-EVIDENCE)

The pipeline verifies that the threat model and its security requirements were acted on during development, not only at release:

1. Every pull request that changes security-relevant paths must name its threat model (§4.1 item 5).
2. A pull request that implements a security requirement states which mitigations it implements with a `Mitigates: M-<id>, …` line. The pipeline checks that each id exists in the referenced model and is marked `implemented` (or `verified`) with evidence in the same pull request. Developers record this with `threatmod mark-implemented`, which sets the status, the evidence reference and, when all committed mitigations of a threat are done, the threat status `mitigated`.
3. A pull request that references a model with planned mitigations but names none receives a warning, so reviewers can ask whether security requirements were in scope.
4. `threatmod coverage` reports, per model, the share of committed mitigations implemented with evidence, broken down by §6.1 domain and by threat severity, with the open security work items. It is published at every pipeline run and reviewed at Sprint Review (ISMS-DEV-003 §4.2). Coverage below 80% raises a warning; at the release stage, committed mitigations must be 100% implemented with evidence or formally accepted.

## 5. Procedures

### 5.1 Team Workflow

| Step | When | Who | Action | Output |
|---|---|---|---|---|
| 1 | Backlog refinement | Feature Owner | `threatmod init --id TM-NMM-48211 ...` and answer triage | Model file with triage |
| 2 | Backlog refinement | Feature Owner | `threatmod triage <file> --write` (or `threatmod assess` from a diagram, then `threatmod sign-off` after review, §4.12) | Required tier |
| 3 | Design | Dev Team (Security Team for Tier 2) | Model assets, zones, elements, flows and entry points | Scoped model |
| 4 | Design | Dev Team | `threatmod generate <file> --write`, then add manual threats | STRIDE threat set |
| 5 | Design session | Dev Team + Security Team | Score, treat, link work items, complete §6.3 review (Tier 2) | Treated model |
| 6 | Sprint planning | Feature Owner | `threatmod workitems <file>`, then import to Azure DevOps | Security acceptance criteria |
| 7 | Before development | Reviewer / Security Team | Record design approval; design gate passes in CI | Approved model |
| 8 | Development | Dev Team | `threatmod mark-implemented` in the PR that implements each mitigation; PR body lists `Mitigates:` | Evidence trail (TM-PR-EVIDENCE) |
| 8a | Sprint review | Feature Owner | `threatmod coverage` scorecard reviewed | Open security work items |
| 9 | Pre-release | Security Team | Verify model against implementation; record verification | Verified model |
| 10 | Release pipeline | DevOps | Release gate and evidence report | Gate result and archived report |

### 5.2 Pull Request Workflow

Product repositories call the reusable workflow `.github/workflows/threat-model.yml`. On every pull request it:

- runs `check-pr` to require a model reference for security-relevant changes and to verify `Mitigates:` claims against the model
- runs the design gate (or the release gate on `release/*` branches) on all models
- publishes each feature's threat landscape report to the job summary and as an artefact

The Azure DevOps template `pipelines/threat-model-gate.yml` runs the release gate in release stages.

### 5.3 AI-assisted Assessment from a Diagram or Requirements Document

Teams may start a threat model from a feature diagram, data flow diagram or requirements document instead of writing the model file by hand. `threatmod assess` reads the uploaded files and produces three artefacts: a draft threat model file, the threat landscape report, and a **Security Impact Assessment (SIA)**.

1. The AI model (Claude) is used for two steps only: extracting the feature description (triage answers with cited evidence, assets, trust zones, elements, data flows, entry points, feature-specific threats, assumptions and open questions) and drafting the SIA narrative.
2. The tier, the STRIDE threat enumeration, the risk scores and the gate verdict are computed by the policy engine from the extraction. They are never taken from the AI model's text, and the SIA is grounded only in the engine's output; any threat identifier in the narrative that is not in the model is flagged.
3. The outputs are drafts. They carry the status `draft` and a `provenance.ai_assisted` flag, fail the design gate by construction (no validation, no treatment decisions, no approvals), and must be validated under §4.12 and completed exactly as a hand-written model would be. No AI-generated artefact may be used as evidence of design approval or release verification.
4. The extraction and the SIA inputs are committed beside the model so reviewers can see what the AI was given and what it produced. Open questions raised by the extraction must be answered before the design gate.
5. The SIA records a security impact rating (Low to Critical), impact per §6.1 security requirement domain, key risks with required controls, conditions for design approval, verification required before release, compliance notes and a recommendation (proceed, proceed with conditions, or redesign required). The Head of Information Security owns the final rating.
6. Uploaded diagrams and documents are processed under Nerdio's AI Governance and Acceptable Use Policy. Inputs must not contain credentials, keys or production personal data.

## 6. Controls and Monitoring

### 6.1 Automated Gate Rules

| Rule ID | Gate | Requirement |
|---|---|---|
| TM-SCHEMA | Design | Model conforms to the schema; all references resolve; IDs unique |
| TM-TRIAGE | Design | All triage questions answered; declared tier ≥ computed tier |
| TM-SCOPE | Design | Assets, ≥2 trust zones, ≥2 elements, data flows and entry points present |
| TM-STRIDE | Design | Every applicable STRIDE category addressed for every element and flow |
| TM-SCORED | Design | Every threat that has not been rejected is scored |
| TM-TREATED | Design | Every Medium+ threat treated; rejections and transfers justified |
| TM-WORKITEM | Design | Every committed mitigation linked to a work item |
| TM-ACCEPTANCE | Design | Risk acceptances meet §4.8 |
| TM-ARCH-REVIEW | Design (Tier 2) | All seven §6.3 domains decided |
| TM-VALIDATED | Design | AI-drafted models carry a valid human validation record (§4.12) |
| TM-APPROVAL | Design | Tier 1 peer approval; Tier 2 Security Team approval |
| TM-IMPLEMENTED | Release | High/Critical mitigations implemented with evidence |
| TM-RESIDUAL | Release | No unaccepted High/Critical residual risk |
| TM-VERIFIED | Release | Security Team verification with attack-surface delta reviewed |
| TM-FRESH | Release | Verification ≤30 days old and newer than the last model change |
| TM-PR-REFERENCE | Pull request | Security-relevant change names a threat model or a reviewed exemption |
| TM-PR-EVIDENCE | Pull request | Mitigations the PR claims exist and are implemented with evidence in the model |

### 6.2 Approved Tooling

`threatmod`, the threat library and the CI templates must be added to the Approved Tools List under the Threat Modelling category, alongside the Microsoft Threat Modeling Tool, with documented Security Team approval (ISMS-DEV-003 §7.3, SSDF PO.3).

### 6.3 Change Control of the Rule Set

Changes to `policy/`, `catalog/`, `schema/` and `threatmod/` are made by pull request and require Security Team approval, enforced by CODEOWNERS. A change that alters a threshold (tiers, bands, SLAs, approver roles, freshness) must also update this document and follow the document approval process.

## 7. Exceptions and Enforcement

1. Exceptions to this policy follow ISMS-DEV-003 §15. They must be in writing, approved by severity tier, recorded in the ISMS Risk Register, and time-bound with a review date.
2. A gate may be bypassed only with documented Security Team authorization attached to the change record. Bypasses are reported in the monthly KPI report.
3. Violations of this policy are handled under ISMS-DEV-003 §16.

## 8. Review and Compliance

1. This policy, the rule set and the threat library are reviewed at least annually, and also after a material security incident, a change to ISMS-DEV-003, or a significant change in Nerdio's architecture or threat landscape.
2. The threat library is updated within 30 days when root cause analysis (ISMS-DEV-003 §12.3), penetration testing or threat intelligence identifies a recurring threat pattern.
3. The Security Team audits a sample of models against this policy at least annually, as part of the ISMS-DEV-003 compliance audit.

## 9. Key Performance Indicators

| KPI | Target | Frequency |
|---|---|---|
| Tier 1/2 features released with a verified threat model | 100% | Monthly |
| AI-drafted models validated before design approval | 100% | Monthly |
| Committed mitigations implemented with evidence at release | 100% | Per release |
| Security-relevant PRs passing `check-pr` without exemption | ≥ 95% | Monthly |
| Release-gate bypasses | 0 (each one reported) | Monthly |
| High/Critical post-release vulnerabilities that the model missed | Trending down; each feeds the threat library | Quarterly |
| Risk acceptances past their review date | 0 | Monthly |
| Median time from triage to design approval (Tier 2) | ≤ 10 working days | Quarterly |

## Appendix A. Policy-as-Code Artefacts

| Artefact | Path | Purpose |
|---|---|---|
| Rule set | `policy/threat-modeling-policy.yaml` | Thresholds, tiers, triage, gates, SLAs, approver roles |
| Schema | `schema/threat-model.schema.json` | Structure of a feature threat model |
| Threat library | `catalog/stride-threat-library.yaml` | Nerdio STRIDE threats and mitigations |
| Template | `templates/threat-model.template.yaml` | Starting point for `threatmod init` |
| CLI | `threatmod/` | init, triage, generate, validate, report, check-pr, workitems, assess |
| GitHub workflow | `.github/workflows/threat-model.yml` | Reusable PR and release gate |
| Azure DevOps template | `pipelines/threat-model-gate.yml` | Release-stage gate and evidence |
| Assess workflow | `.github/workflows/threat-model-assess.yml` | Diagram/requirements upload to draft model and SIA |
| Assess example | `examples/assess-demo/` | Sample diagram, requirements, and generated SIA |
| Worked example | `examples/tm-nmm-48211/` | Tier 2 NMM feature with report |

## Appendix B. Risk Scoring Anchors

| Score | Likelihood | Impact |
|---|---|---|
| 1 | Rare: requires insider access plus multiple control failures | Negligible: no customer data, no service effect |
| 2 | Unlikely: requires privileged access or a non-public flaw | Minor: Internal data, single-user degradation |
| 3 | Possible: reachable by an authenticated user or a known pattern | Moderate: Confidential data of one customer, partial outage |
| 4 | Likely: internet-reachable or crosses a trust boundary with low effort | Major: Restricted data, single-tenant compromise, possible regulatory notification |
| 5 | Almost certain: trivially exploitable, public tooling | Severe: cross-tenant or multi-customer compromise, privileged Azure takeover, platform outage |

## Appendix C. Related Documents

- ISMS-DEV-003 Secure Software Development Policy v3.3
- ISMS-SEC-002 Vulnerability and Threat Management Policy
- ISMS-CMP-001 Change Management Program
- ISMS-RISK-001 Risk Management Program and Risk Register
- Cryptographic Controls Policy; Access Control Policy
- Microsoft SDL: Threat Modeling; Microsoft Threat Modeling Tool documentation
- NIST SP 800-218 (SSDF) v1.1; OWASP Threat Modeling Cheat Sheet
