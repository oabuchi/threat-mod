# Security Impact Assessment: Self-service session host restart from Microsoft Teams

**Threat model:** TM-NME-52310 · **Product:** NME · **Policy:** ISMS-DEV-004 v1.0 · **Date:** 2026-11-05

| Security impact | Required tier | Threats enumerated | Design gate (as generated) | Recommendation |
|---|---|---|---|---|
| **HIGH** | **2** (Enhanced) | 54 (C 0 · H 34 · M 20 · L 0) | 56 open findings | **proceed with conditions** |

> Draft produced by `threatmod assess` from the uploaded inputs. The tier, threat list, scores and gate
> verdict are computed by the policy engine; the narrative is AI-drafted and must be reviewed by the
> Security Team before it is relied on (ISMS-DEV-004 §4.3).

## 1. Executive summary

The feature adds an internet-facing endpoint to NME that lets any Teams user in the customer tenant trigger a privileged ARM operation (VM restart) against a session host, using the NME managed identity. The security value is low data exposure (no new persisted data beyond audit entries) but high control-plane sensitivity: a flaw in how the caller is authenticated or how the user is mapped to a host turns a convenience feature into a way to disrupt other users' desktops. The policy engine places the feature at Tier 2 and enumerated 54 threats: 34 High and 20 Medium at default (conservative) scores, none Critical because the feature is single-tenant and no Restricted data is persisted. Most of the High scores come from the internet-facing entry point uplift and will fall once the team rescores with the planned controls in place. With strict JWT and tenant validation, object-id based host resolution, server-side rate limiting and a secure-by-default enable flag, the residual risk is manageable.

**Why high:** Internet-reachable entry point, new authentication path and a privileged Azure operation on customer compute (ISMS-DEV-003 §6.2 'elevated security risk'). No cross-tenant or Restricted-data exposure keeps it below Critical.

## 2. Feature and scope

AVD end users send /restart-my-desktop to the Nerdio Teams bot. Azure Bot Service forwards the activity to a new NME endpoint, which resolves the user's assigned personal session host from the NME database and restarts it through ARM using the NME managed identity, then confirms in Teams. Admins enable the feature per host pool and every restart is audit-logged.

Required tier **2** because: architectural_change → tier 1; data_handling_change → tier 1; new_integration → tier 1; authn_authz_change → tier 2; new_external_entry_point → tier 2; privileged_azure_operation → tier 2; data_classification=confidential → tier 1.

| Triage question | Answer | Evidence |
|---|---|---|
| Does the feature add or change a service, component, trust boundary, deployment topology or Azure resource type? | **Yes** | New component 'Teams activity endpoint' and 'Restart worker'; new trust boundary to Azure Bot Service (architecture.png) |
| Does the feature collect, store, process, transmit, export or delete data in a new way (new fields, new stores, new retention)? | **Yes** | Teams activity payload (user display name, Entra object id, tenant id, message text) is received; new audit log entries written (requirements §Data) |
| Does the feature add or change an integration with an external system (Microsoft Graph/ARM, PSA/RMM, IdP, webhook, third-party API)? | **Yes** | Azure Bot Service / Bot Framework REST API integration (flows 2 and 7) |
| Does the feature change authentication, authorization, RBAC roles, tokens, sessions or secrets handling? | **Yes** | New authentication path: Bot Framework JWT validated at POST /api/teams/activity; authorization decision maps Teams user to a host they may restart |
| Does the feature expose a new internet-reachable endpoint, file upload, or input parser? | **Yes** | POST /api/teams/activity is a new internet-reachable endpoint on the NME App Service |
| Does the feature create, modify or grant privileged permissions in customer Azure / Entra ID tenants? | **Yes** | Restart worker calls ARM virtualMachines/{vm}/restart with Virtual Machine Contributor on the host pool resource group |
| Could the feature cause data or actions to cross MSP, customer or tenant boundaries (NMM multi-tenancy)? | No | NME is single-customer; activity carries a tenant id but the requirements do not describe multi-tenant data. Open question: is the bot registered as multi-tenant? |
| Does the feature handle Restricted data (credentials, keys, tokens, personal data subject to GDPR/CCPA)? | No | Entra object id and display name are personal data but existing NME data; no credentials, keys or tokens are stored. Bot JWT is transient. |
| Does the feature introduce or change cryptographic design (algorithms, keys, certificates, key storage)? | No | Uses platform TLS and Bot Framework JWT validation; no new cryptographic design |

### Attack surface

| Entry point | Element | Authentication | Internet-facing |
|---|---|---|---|
| POST /api/teams/activity | Teams activity endpoint | Bot Framework JWT (issuer + audience = bot app id) | yes |

4 of 7 data flows cross a trust boundary.

## 3. Impact by security requirement domain (ISMS-DEV-003 §6.1)

| Domain | Impact | Summary |
|---|---|---|
| authentication identity | high | New inbound trust in Bot Framework JWTs; issuer, audience, expiry and tenant must be validated on every activity (T-P1-FEAT-004, T-P1-S-001, T-P1-S-002). |
| access control | high | Authorization is implicit in the user-to-host mapping; the managed identity holds VM Contributor on the resource group (T-P2-FEAT-001, T-P2-E-002). |
| api security | medium | A new public endpoint needs replay protection, size limits and rate limiting (T-P1-S-002, T-P1-D-001, T-F2-D-004). |
| error handling logging | medium | Restarts must be attributable to the Teams user and the admin flag changes must be logged (T-P1-R-001, T-P2-R-001). |
| data handling privacy | low | Entra object id and display name are processed transiently; only the audit entry is persisted. Message text should not be stored. |
| secure defaults | medium | The per-host-pool flag is the primary control and must default to off (T-P2-FEAT-003). |
| availability resilience | medium | Restart loops and ARM throttling affect the whole host pool (T-P1-FEAT-002, T-P1-D-001). |
| tenant isolation | low | NME is single-tenant, but a multi-tenant bot registration would make tenant validation a hard requirement (open question). |
| secrets management | low | Bot credentials used for outbound confirmation cards must live in Key Vault; the worker uses managed identity for ARM (T-P2-S-003). |
| input validation output encoding | low | Activity payloads cross the internet boundary; schema-validate and never echo message text into cards unescaped (T-F2-T-002). |
| cryptography | none | Platform TLS and Microsoft-issued JWT signing; no new cryptographic design. |
| third party components | low | Bot Framework SDK must come from the Approved Tools List and pass SCA (T-P1-T-005). |

## 4. Key risks

### 4.1 Accepting a forged or foreign bot activity

Threats: `T-P1-FEAT-004` (high), `T-P1-S-001` (high), `T-P1-S-002` (high)

The endpoint is reachable from the internet and its only guard is the Bot Framework JWT. If audience or tenant checks are missing, anyone who can obtain a Bot Framework token for another bot or tenant can restart hosts in this customer's environment.

Required controls:

- Validate JWT signature against Bot Framework OpenID metadata, issuer, audience = this bot's app id, and expiry on every request
- Reject activities whose tenant id is not the NME customer tenant, regardless of bot registration type
- Apply a 5-minute replay window using the activity id and timestamp

### 4.2 Restarting the wrong host, or more hosts than intended

Threats: `T-P2-FEAT-001` (high), `T-P2-E-001` (medium), `T-P2-E-002` (medium)

The worker acts with VM Contributor on the resource group. A mapping error (display name instead of object id, stale assignment, pooled host) restarts someone else's desktop; an over-scoped identity makes any bug in the worker a tenant-wide outage tool.

Required controls:

- Resolve the user by Entra object id + tenant id from the validated JWT only
- Restart only hosts whose assignment is personal and currently assigned to that object id; refuse pooled hosts explicitly
- Scope the managed identity to a custom role with only Microsoft.Compute/virtualMachines/restart/action on personal host pools, or at minimum per-host-pool resource groups

### 4.3 Restart loops and ARM throttling

Threats: `T-P1-FEAT-002` (medium), `T-P1-D-001` (high), `T-F2-D-004` (high)

A compromised or careless user can keep a host rebooting, and bursts of restarts count against ARM subscription throttling limits that NME's autoscale also depends on.

Required controls:

- Enforce one restart per user per 10 minutes and a per-host-pool concurrency cap in the worker, not in the bot
- Require the confirmation card server-side when the admin setting is on
- Front the endpoint with request size limits and per-source rate limiting

### 4.4 Feature exposed without admin intent

Threats: `T-P2-FEAT-003` (medium)

The per-host-pool flag is the gate for the whole feature. If it defaults to on or can be changed by a non-admin, every Teams user in the tenant gains restart capability silently.

Required controls:

- Default off per host pool; only the NME admin role can change it; write flag changes to the audit log

### 4.5 Restarts that cannot be attributed

Threats: `T-P1-R-001` (high), `T-P2-R-001` (medium), `T-D2-T-004` (medium)

Admins will investigate 'who rebooted my desktop'. Without actor, host, source (Teams) and correlation id in a tamper-evident log, the feature creates disputes it cannot settle.

Required controls:

- Audit event with Entra object id, tenant id, VM resource id, result, activity id and UTC time to Log Analytics
- Do not persist the free-text message body

## 5. Conditions for design approval

- [ ] Record decisions for all seven §6.3 Architectural Security Review domains (currently missing: TM-ARCH-REVIEW)
- [ ] Treat every Medium and High threat: plan a mitigation with a work item, accept with a Risk Register entry, transfer, or reject with a reason (TM-TREATED)
- [ ] Answer the open question on bot registration type; if multi-tenant, add tenant-id validation as a mandatory mitigation
- [ ] Confirm the managed identity scope and replace Virtual Machine Contributor with a restart-only custom role
- [ ] Obtain Security Team design approval (Tier 2, TM-APPROVAL)

## 6. Verification required before release

- [ ] Negative tests: JWT with wrong audience, wrong issuer, expired, wrong tenant id are rejected with 401 and logged
- [ ] Authorization tests: user A cannot restart user B's host; pooled hosts are refused; stale assignment is refused
- [ ] Rate-limit test: second restart within 10 minutes is refused server-side even if the bot is bypassed
- [ ] Fuzz the /api/teams/activity payload (ISMS-DEV-003 §8.1.3) including oversized and malformed activities
- [ ] DAST against the QA deployment with the endpoint enabled
- [ ] Verify the host-pool flag defaults to off on a fresh install and that only admins can change it
- [ ] Verify audit events contain actor, host, result and correlation id and that message text is absent

## 7. Compliance notes

- Entra object id and display name are personal data under GDPR; processing is transient and the audit log is existing NME processing, but the retention period for new audit entries must follow the Logging and Monitoring Policy.
- ISO 27001 A.8.27 (secure architecture) and SSDF PW.1/PW.2 are satisfied by completing the Tier 2 review before development starts.
- The feature performs a privileged operation in the customer tenant; document the restart-only role in the customer-facing permissions reference.

## 8. Recommendation

**Proceed with conditions.** The design is sound and the exposure is bounded (single tenant, no new persisted data, restart-only operation). Proceed once the design conditions above are met: strict JWT and tenant validation, object-id based host resolution, a restart-only identity scope, server-side rate limiting, and a secure-by-default enable flag, with the Tier 2 review and Security Team approval recorded in the threat model.

## 9. Assumptions and open questions

- Assumed: The in-process job queue (flow 3) stays inside the App Service; if it becomes a Service Bus/Storage queue it needs its own element and access controls.
- Assumed: The Bot Framework JWT validation uses the Microsoft-published OpenID metadata and is not a static shared secret.
- Open: Is the Nerdio Teams bot registered as single-tenant or multi-tenant in Entra ID? Multi-tenant registration makes tenant-id validation mandatory.
- Open: Does the managed identity's Virtual Machine Contributor scope cover only personal host pools, or the whole resource group including pooled hosts?
- Open: Is the confirmation step (user story 3) enforced server-side, or only in the Teams card UI?
- Open: What is retained from the Teams message text? Free-text message bodies should not be persisted in the audit log.

## 10. Design-gate findings on the generated model

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

_Full threat list: [threat-model-report.md](threat-model-report.md) · model: [threat-model.yaml](threat-model.yaml)_
