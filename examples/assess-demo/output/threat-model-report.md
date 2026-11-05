# Threat Model TM-NME-52310: Self-service session host restart from Microsoft Teams

**Product:** NME · **Owner:** Priya Example · **Work item:** https://dev.azure.com/nerdio/NME/_workitems/edit/52310 · **Tier:** 2 (Enhanced) · **Status:** draft

**Design gate:** ❌ FAIL (56 blocking) — policy ISMS-DEV-004 v1.0

## 1. Triage

Required tier **2** because: architectural_change → tier 1; data_handling_change → tier 1; new_integration → tier 1; authn_authz_change → tier 2; new_external_entry_point → tier 2; privileged_azure_operation → tier 2; data_classification=confidential → tier 1.

## 2. Attack surface

```mermaid
flowchart LR
  subgraph Z0["Internet / Microsoft 365 (trust 0)"]
    E1["AVD end user (Teams client)"]
    E2["Azure Bot Service"]
  end
  subgraph Z1["NME App Service (customer Azure subscription) (trust 7)"]
    P1(("Teams activity endpoint"))
    P2(("Restart worker"))
    D1[("NME SQL database")]
  end
  subgraph Z2["Customer Azure resources (trust 6)"]
    E3["Azure Resource Manager"]
    D2[("Log Analytics (NME audit log)")]
  end
  E1 -->|"F1: HTTPS (Teams)"| E2
  E2 -.->|"F2: HTTPS webhook (Bot Framework JWT)"| P1
  P1 -->|"F3: In-process job queue"| P2
  P2 -->|"F4: TDS/TLS"| D1
  P2 -.->|"F5: HTTPS (ARM REST)"| E3
  P2 -.->|"F6: HTTPS (Log Analytics ingestion)"| D2
  P2 -.->|"F7: HTTPS (Bot Framework REST API)"| E2
```

_Dashed arrows cross a trust boundary._

| Entry point | Element | Authentication | Internet-facing |
|---|---|---|---|
| EP1: POST /api/teams/activity | Teams activity endpoint | Bot Framework JWT (issuer + audience = bot app id) | yes |

Trust-boundary crossings: **4** of 7 data flows.

## 3. Threat landscape (inherent risk)

| STRIDE | Critical | High | Medium | Low |
|---|---|---|---|---|
| Spoofing | 0 | 7 | 1 | 0 |
| Tampering | 0 | 7 | 4 | 0 |
| Repudiation | 0 | 4 | 3 | 0 |
| Information disclosure | 0 | 7 | 4 | 0 |
| Denial of service | 0 | 7 | 5 | 0 |
| Elevation of privilege | 0 | 2 | 3 | 0 |

**Residual / untreated:** Critical 0 · High 34 · Medium 20 · Low 0

## 4. Threats

| ID | STRIDE | Target | Threat | Inherent | Status | Mitigations |
|---|---|---|---|---|---|---|
| T-P1-S-001 | S | P1 | Attacker impersonates a legitimate caller of Teams activity endpoint | high (4×4) | identified | M-P1-S-001-1 [proposed]<br>M-P1-S-001-2 [proposed] |
| T-P1-S-002 | S | P1 | Forged inbound event/webhook accepted by Teams activity endpoint | high (4×4) | identified | M-P1-S-002-1 [proposed]<br>M-P1-S-002-2 [proposed] |
| T-P1-S-003 | S | P1 | Service-to-service identity of Teams activity endpoint spoofed or credentials stolen | high (4×4) | identified | M-P1-S-003-1 [proposed]<br>M-P1-S-003-2 [proposed] |
| T-P1-T-005 | T | P1 | Build or deployment artifact of Teams activity endpoint tampered with | high (4×4) | identified | M-P1-T-005-1 [proposed]<br>M-P1-T-005-2 [proposed] |
| T-P1-R-001 | R | P1 | Actions performed through Teams activity endpoint cannot be attributed | high (4×4) | identified | M-P1-R-001-1 [proposed]<br>M-P1-R-001-2 [proposed] |
| T-P1-I-004 | I | P1 | Sensitive data leaked through errors, logs or telemetry of Teams activity endpoint | high (4×4) | identified | M-P1-I-004-1 [proposed]<br>M-P1-I-004-2 [proposed] |
| T-P1-D-001 | D | P1 | Teams activity endpoint exhausted by request flooding or expensive operations | high (4×4) | identified | M-P1-D-001-1 [proposed]<br>M-P1-D-001-2 [proposed] |
| T-P1-E-001 | E | P1 | Broken authorization in Teams activity endpoint allows privilege escalation | high (4×4) | identified | M-P1-E-001-1 [proposed] |
| T-F5-T-GEN | T | F5 | Tampering with Restart worker → Azure Resource Manager (HTTPS (ARM REST)) | high (4×4) | identified | M-F5-T-GEN-1 [proposed] |
| T-F5-I-GEN | I | F5 | Information disclosure from Restart worker → Azure Resource Manager (HTTPS (ARM REST)) | high (4×4) | identified | M-F5-I-GEN-1 [proposed] |
| T-F5-D-GEN | D | F5 | Denial of service against Restart worker → Azure Resource Manager (HTTPS (ARM REST)) | high (4×4) | identified | M-F5-D-GEN-1 [proposed] |
| T-P2-FEAT-001 | E | P2 | User restarts a host that is not their own (assignment confusion) | high (3×4) | identified | M-P2-FEAT-001-1 [proposed] |
| T-P1-FEAT-004 | S | P1 | Spoofed bot activity from a different bot or tenant | high (3×4) | identified | M-P1-FEAT-004-1 [proposed] |
| T-E1-S-004 | S | E1 | Third-party system AVD end user (Teams client) is impersonated or compromised | high (4×3) | identified | M-E1-S-004-1 [proposed]<br>M-E1-S-004-2 [proposed] |
| T-E1-R-001 | R | E1 | Actions performed through AVD end user (Teams client) cannot be attributed | high (4×3) | identified | M-E1-R-001-1 [proposed]<br>M-E1-R-001-2 [proposed] |
| T-E2-S-004 | S | E2 | Third-party system Azure Bot Service is impersonated or compromised | high (4×3) | identified | M-E2-S-004-1 [proposed]<br>M-E2-S-004-2 [proposed] |
| T-E2-R-001 | R | E2 | Actions performed through Azure Bot Service cannot be attributed | high (4×3) | identified | M-E2-R-001-1 [proposed]<br>M-E2-R-001-2 [proposed] |
| T-E3-S-004 | S | E3 | Third-party system Azure Resource Manager is impersonated or compromised | high (3×4) | identified | M-E3-S-004-1 [proposed]<br>M-E3-S-004-2 [proposed] |
| T-E3-R-001 | R | E3 | Actions performed through Azure Resource Manager cannot be attributed | high (3×4) | identified | M-E3-R-001-1 [proposed]<br>M-E3-R-001-2 [proposed] |
| T-F1-T-GEN | T | F1 | Tampering with AVD end user (Teams client) → Azure Bot Service (HTTPS (Teams)) | high (4×3) | identified | M-F1-T-GEN-1 [proposed] |
| T-F1-I-GEN | I | F1 | Information disclosure from AVD end user (Teams client) → Azure Bot Service (HTTPS (Teams)) | high (4×3) | identified | M-F1-I-GEN-1 [proposed] |
| T-F1-D-GEN | D | F1 | Denial of service against AVD end user (Teams client) → Azure Bot Service (HTTPS (Teams)) | high (4×3) | identified | M-F1-D-GEN-1 [proposed] |
| T-F2-T-002 | T | F2 | Malicious input injected across trust boundary via Azure Bot Service → Teams activity endpoint (HTTPS webhook (Bot Framework JWT)) | high (4×3) | identified | M-F2-T-002-1 [proposed]<br>M-F2-T-002-2 [proposed] |
| T-F2-I-GEN | I | F2 | Information disclosure from Azure Bot Service → Teams activity endpoint (HTTPS webhook (Bot Framework JWT)) | high (4×3) | identified | M-F2-I-GEN-1 [proposed] |
| T-F2-D-004 | D | F2 | Oversized or malformed payloads on Azure Bot Service → Teams activity endpoint (HTTPS webhook (Bot Framework JWT)) crash the receiver | high (4×3) | identified | M-F2-D-004-1 [proposed] |
| T-F3-T-GEN | T | F3 | Tampering with Teams activity endpoint → Restart worker (In-process job queue) | high (4×3) | identified | M-F3-T-GEN-1 [proposed] |
| T-F3-I-GEN | I | F3 | Information disclosure from Teams activity endpoint → Restart worker (In-process job queue) | high (4×3) | identified | M-F3-I-GEN-1 [proposed] |
| T-F3-D-GEN | D | F3 | Denial of service against Teams activity endpoint → Restart worker (In-process job queue) | high (4×3) | identified | M-F3-D-GEN-1 [proposed] |
| T-F6-T-GEN | T | F6 | Tampering with Restart worker → Log Analytics (NME audit log) (HTTPS (Log Analytics ingestion)) | high (4×3) | identified | M-F6-T-GEN-1 [proposed] |
| T-F6-I-GEN | I | F6 | Information disclosure from Restart worker → Log Analytics (NME audit log) (HTTPS (Log Analytics ingestion)) | high (4×3) | identified | M-F6-I-GEN-1 [proposed] |
| T-F6-D-GEN | D | F6 | Denial of service against Restart worker → Log Analytics (NME audit log) (HTTPS (Log Analytics ingestion)) | high (4×3) | identified | M-F6-D-GEN-1 [proposed] |
| T-F7-T-GEN | T | F7 | Tampering with Restart worker → Azure Bot Service (HTTPS (Bot Framework REST API)) | high (4×3) | identified | M-F7-T-GEN-1 [proposed] |
| T-F7-I-GEN | I | F7 | Information disclosure from Restart worker → Azure Bot Service (HTTPS (Bot Framework REST API)) | high (4×3) | identified | M-F7-I-GEN-1 [proposed] |
| T-F7-D-GEN | D | F7 | Denial of service against Restart worker → Azure Bot Service (HTTPS (Bot Framework REST API)) | high (4×3) | identified | M-F7-D-GEN-1 [proposed] |
| T-P1-FEAT-002 | D | P1 | Restart spam against a user's host (self-inflicted or via compromised Teams account) | medium (3×3) | identified | M-P1-FEAT-002-1 [proposed] |
| T-P2-S-003 | S | P2 | Service-to-service identity of Restart worker spoofed or credentials stolen | medium (3×3) | identified | M-P2-S-003-1 [proposed]<br>M-P2-S-003-2 [proposed] |
| T-P2-T-005 | T | P2 | Build or deployment artifact of Restart worker tampered with | medium (3×3) | identified | M-P2-T-005-1 [proposed]<br>M-P2-T-005-2 [proposed] |
| T-P2-R-001 | R | P2 | Actions performed through Restart worker cannot be attributed | medium (3×3) | identified | M-P2-R-001-1 [proposed]<br>M-P2-R-001-2 [proposed] |
| T-P2-I-004 | I | P2 | Sensitive data leaked through errors, logs or telemetry of Restart worker | medium (3×3) | identified | M-P2-I-004-1 [proposed]<br>M-P2-I-004-2 [proposed] |
| T-P2-D-GEN | D | P2 | Denial of service against Restart worker | medium (3×3) | identified | M-P2-D-GEN-1 [proposed] |
| T-P2-E-001 | E | P2 | Broken authorization in Restart worker allows privilege escalation | medium (3×3) | identified | M-P2-E-001-1 [proposed] |
| T-P2-E-002 | E | P2 | Over-privileged Azure/Entra identity used by Restart worker | medium (3×3) | identified | M-P2-E-002-1 [proposed]<br>M-P2-E-002-2 [proposed] |
| T-D1-T-004 | T | D1 | Unauthorized modification of data in NME SQL database | medium (3×3) | identified | M-D1-T-004-1 [proposed]<br>M-D1-T-004-2 [proposed] |
| T-D1-R-002 | R | D1 | Changes to NME SQL database are not traceable | medium (3×3) | identified | M-D1-R-002-1 [proposed] |
| T-D1-I-003 | I | D1 | Data at rest in NME SQL database exposed | medium (3×3) | identified | M-D1-I-003-1 [proposed]<br>M-D1-I-003-2 [proposed] |
| T-D1-D-003 | D | D1 | NME SQL database unavailable or data destroyed | medium (3×3) | identified | M-D1-D-003-1 [proposed] |
| T-D2-T-004 | T | D2 | Unauthorized modification of data in Log Analytics (NME audit log) | medium (3×3) | identified | M-D2-T-004-1 [proposed]<br>M-D2-T-004-2 [proposed] |
| T-D2-R-002 | R | D2 | Changes to Log Analytics (NME audit log) are not traceable | medium (3×3) | identified | M-D2-R-002-1 [proposed] |
| T-D2-I-003 | I | D2 | Data at rest in Log Analytics (NME audit log) exposed | medium (3×3) | identified | M-D2-I-003-1 [proposed]<br>M-D2-I-003-2 [proposed] |
| T-D2-D-003 | D | D2 | Log Analytics (NME audit log) unavailable or data destroyed | medium (3×3) | identified | M-D2-D-003-1 [proposed] |
| T-F4-T-GEN | T | F4 | Tampering with Restart worker → NME SQL database (TDS/TLS) | medium (3×3) | identified | M-F4-T-GEN-1 [proposed] |
| T-F4-I-GEN | I | F4 | Information disclosure from Restart worker → NME SQL database (TDS/TLS) | medium (3×3) | identified | M-F4-I-GEN-1 [proposed] |
| T-F4-D-GEN | D | F4 | Denial of service against Restart worker → NME SQL database (TDS/TLS) | medium (3×3) | identified | M-F4-D-GEN-1 [proposed] |
| T-P2-FEAT-003 | E | P2 | Feature enabled on a host pool without admin intent | medium (2×3) | identified | M-P2-FEAT-003-1 [proposed] |

## Gate findings

- ❌ **TM-TREATED** threat T-P2-FEAT-001 (high) has no treatment decision
- ❌ **TM-TREATED** threat T-P1-FEAT-002 (medium) has no treatment decision
- ❌ **TM-TREATED** threat T-P2-FEAT-003 (medium) has no treatment decision
- ❌ **TM-TREATED** threat T-P1-FEAT-004 (high) has no treatment decision
- ❌ **TM-TREATED** threat T-E1-S-004 (high) has no treatment decision
- ❌ **TM-TREATED** threat T-E1-R-001 (high) has no treatment decision
- ❌ **TM-TREATED** threat T-E2-S-004 (high) has no treatment decision
- ❌ **TM-TREATED** threat T-E2-R-001 (high) has no treatment decision
- ❌ **TM-TREATED** threat T-P1-S-001 (high) has no treatment decision
- ❌ **TM-TREATED** threat T-P1-S-002 (high) has no treatment decision
- ❌ **TM-TREATED** threat T-P1-S-003 (high) has no treatment decision
- ❌ **TM-TREATED** threat T-P1-T-005 (high) has no treatment decision
- ❌ **TM-TREATED** threat T-P1-R-001 (high) has no treatment decision
- ❌ **TM-TREATED** threat T-P1-I-004 (high) has no treatment decision
- ❌ **TM-TREATED** threat T-P1-D-001 (high) has no treatment decision
- ❌ **TM-TREATED** threat T-P1-E-001 (high) has no treatment decision
- ❌ **TM-TREATED** threat T-P2-S-003 (medium) has no treatment decision
- ❌ **TM-TREATED** threat T-P2-T-005 (medium) has no treatment decision
- ❌ **TM-TREATED** threat T-P2-R-001 (medium) has no treatment decision
- ❌ **TM-TREATED** threat T-P2-I-004 (medium) has no treatment decision
- ❌ **TM-TREATED** threat T-P2-D-GEN (medium) has no treatment decision
- ❌ **TM-TREATED** threat T-P2-E-001 (medium) has no treatment decision
- ❌ **TM-TREATED** threat T-P2-E-002 (medium) has no treatment decision
- ❌ **TM-TREATED** threat T-D1-T-004 (medium) has no treatment decision
- ❌ **TM-TREATED** threat T-D1-R-002 (medium) has no treatment decision
- ❌ **TM-TREATED** threat T-D1-I-003 (medium) has no treatment decision
- ❌ **TM-TREATED** threat T-D1-D-003 (medium) has no treatment decision
- ❌ **TM-TREATED** threat T-E3-S-004 (high) has no treatment decision
- ❌ **TM-TREATED** threat T-E3-R-001 (high) has no treatment decision
- ❌ **TM-TREATED** threat T-D2-T-004 (medium) has no treatment decision
- ❌ **TM-TREATED** threat T-D2-R-002 (medium) has no treatment decision
- ❌ **TM-TREATED** threat T-D2-I-003 (medium) has no treatment decision
- ❌ **TM-TREATED** threat T-D2-D-003 (medium) has no treatment decision
- ❌ **TM-TREATED** threat T-F1-T-GEN (high) has no treatment decision
- ❌ **TM-TREATED** threat T-F1-I-GEN (high) has no treatment decision
- ❌ **TM-TREATED** threat T-F1-D-GEN (high) has no treatment decision
- ❌ **TM-TREATED** threat T-F2-T-002 (high) has no treatment decision
- ❌ **TM-TREATED** threat T-F2-I-GEN (high) has no treatment decision
- ❌ **TM-TREATED** threat T-F2-D-004 (high) has no treatment decision
- ❌ **TM-TREATED** threat T-F3-T-GEN (high) has no treatment decision
- ❌ **TM-TREATED** threat T-F3-I-GEN (high) has no treatment decision
- ❌ **TM-TREATED** threat T-F3-D-GEN (high) has no treatment decision
- ❌ **TM-TREATED** threat T-F4-T-GEN (medium) has no treatment decision
- ❌ **TM-TREATED** threat T-F4-I-GEN (medium) has no treatment decision
- ❌ **TM-TREATED** threat T-F4-D-GEN (medium) has no treatment decision
- ❌ **TM-TREATED** threat T-F5-T-GEN (high) has no treatment decision
- ❌ **TM-TREATED** threat T-F5-I-GEN (high) has no treatment decision
- ❌ **TM-TREATED** threat T-F5-D-GEN (high) has no treatment decision
- ❌ **TM-TREATED** threat T-F6-T-GEN (high) has no treatment decision
- ❌ **TM-TREATED** threat T-F6-I-GEN (high) has no treatment decision
- ❌ **TM-TREATED** threat T-F6-D-GEN (high) has no treatment decision
- ❌ **TM-TREATED** threat T-F7-T-GEN (high) has no treatment decision
- ❌ **TM-TREATED** threat T-F7-I-GEN (high) has no treatment decision
- ❌ **TM-TREATED** threat T-F7-D-GEN (high) has no treatment decision
- ❌ **TM-ARCH-REVIEW** architectural review (§6.3) missing domains: authentication_identity, access_control_least_privilege, encryption_in_transit_at_rest, data_handling_classification_retention, external_interfaces_api_security, consent_data_subject_rights, residual_risk_acceptance
- ❌ **TM-APPROVAL** Tier 2 requires Security Team design approval (SSDF PW.2)

_Generated by threatmod on 2026-11-05 — retain as security evidence (3 years)._
