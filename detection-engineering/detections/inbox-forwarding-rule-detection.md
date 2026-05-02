# Detection: Inbox Forwarding Rule Created to External Address

**Detection Name:** Inbox Forwarding Rule Created to External Address
**MITRE ATT&CK Technique:** T1114.003 — Email Forwarding Rule
**MITRE ATT&CK Tactic:** Collection
**Log Source:** Microsoft 365 Unified Audit Log (OfficeActivity) via Microsoft Sentinel
**Severity:** High
**Author:** Warren Bowen
**Created:** May 2026

---

## Description

This detection identifies when a user creates an inbox forwarding rule that routes mail to an
external address outside the organization's verified domains. This is a high-fidelity indicator
of account compromise. Adversaries who gain access to a mailbox frequently establish server-side
forwarding rules immediately after authentication, ensuring persistent access to communications
even after the compromised password is reset.

This detection is based on real investigation experience with this alert type in production
managed service environments. The forwarding rule creation event itself is the primary trigger —
the rule appearing in Exchange Online audit logs is the signal, regardless of whether an
anomalous authentication preceded it.

---

## Detection Logic

```kql
// Inbox Forwarding Rule Created to External Address
// Targets: OfficeActivity log via Microsoft Sentinel
// Technique: T1114.003 — Email Forwarding Rule

OfficeActivity
| where TimeGenerated > ago(24h)
| where RecordType == "ExchangeAdmin"
| where Operation in (
    "New-InboxRule",
    "Set-InboxRule",
    "UpdateInboxRules"
)
| extend RuleParameters = parse_json(Parameters)
| mv-expand RuleParameters
| where RuleParameters.Name in (
    "ForwardTo",
    "ForwardAsAttachmentTo",
    "RedirectTo"
)
| extend ForwardingDestination = tostring(RuleParameters.Value)
| where ForwardingDestination !endswith "@yourdomain.com"
| where ForwardingDestination !endswith "@yourdomain.onmicrosoft.com"
| project
    TimeGenerated,
    UserId,
    ClientIP,
    Operation,
    ForwardingDestination,
    OfficeObjectId,
    UserAgent
| order by TimeGenerated desc
```

---

## Tuning Notes

Replace domain exclusions with the organization's actual verified domains before deploying.
Multi-domain organizations should add an exclusion line for each domain.

**Common false positives:**
- Legitimate email forwarding to a personal device configured by IT policy
- Executive assistants setting up approved forwarding on behalf of leadership
- Automated business process accounts with approved external forwarding

**Tuning approach:** Build an allowlist of approved forwarding destinations and exclude them
using a watchlist in Sentinel. Any destination not on the allowlist triggers the alert.

```kql
// Extended version with watchlist exclusion
let ApprovedForwardingDestinations = (_GetWatchlist('ApprovedForwarding')
    | project SearchKey);
OfficeActivity
| where TimeGenerated > ago(24h)
| where RecordType == "ExchangeAdmin"
| where Operation in ("New-InboxRule", "Set-InboxRule", "UpdateInboxRules")
| extend RuleParameters = parse_json(Parameters)
| mv-expand RuleParameters
| where RuleParameters.Name in ("ForwardTo", "ForwardAsAttachmentTo", "RedirectTo")
| extend ForwardingDestination = tostring(RuleParameters.Value)
| where ForwardingDestination !endswith "@yourdomain.com"
| where ForwardingDestination !in (ApprovedForwardingDestinations)
| project
    TimeGenerated,
    UserId,
    ClientIP,
    Operation,
    ForwardingDestination,
    OfficeObjectId,
    UserAgent
| order by TimeGenerated desc
```

---

## True Positive Criteria

Alert should be escalated when:
- Forwarding destination is a personal email provider (Gmail, Yahoo, Outlook personal, Proton)
- Forwarding destination has no organizational relationship to the company
- Rule creation was preceded by anomalous authentication — correlate with SigninLogs
- Rule scope is all mail rather than a specific filtered subset
- User has no prior history of inbox rules

---

## False Positive Scenarios

- IT-approved forwarding to a personal device (should be documented in change management)
- Executive assistant forwarding configured with authorization
- Automated workflow forwarding with a documented business justification

**Key differentiator:** Legitimate forwarding rules are almost always scoped — they forward
specific mail matching criteria. Adversary-created rules typically forward everything.

---

## Correlation Opportunity

For higher confidence, correlate with anomalous sign-in events in the same time window.
A forwarding rule created within 30 minutes of an anomalous authentication significantly
increases confidence of compromise.

```kql
// Correlation query — forwarding rule + anomalous sign-in within 30 min window
let ForwardingEvents = OfficeActivity
| where TimeGenerated > ago(24h)
| where RecordType == "ExchangeAdmin"
| where Operation in ("New-InboxRule", "Set-InboxRule", "UpdateInboxRules")
| extend RuleParameters = parse_json(Parameters)
| mv-expand RuleParameters
| where RuleParameters.Name in ("ForwardTo", "ForwardAsAttachmentTo", "RedirectTo")
| extend ForwardingDestination = tostring(RuleParameters.Value)
| where ForwardingDestination !endswith "@yourdomain.com"
| project ForwardingTime = TimeGenerated, UserId, ForwardingDestination, ClientIP;
let AnomalousSignins = SigninLogs
| where TimeGenerated > ago(24h)
| where RiskLevelDuringSignIn in ("medium", "high")
    or NetworkLocationDetails has "anonymizedIP"
    or conditionalAccessStatus == "failure"
| project SigninTime = TimeGenerated, UserPrincipalName, SigninIP = IPAddress,
    RiskLevel = RiskLevelDuringSignIn, Location;
ForwardingEvents
| join kind=inner (AnomalousSignins) on $left.UserId == $right.UserPrincipalName
| where abs(datetime_diff('minute', ForwardingTime, SigninTime)) <= 30
| project
    ForwardingTime,
    UserId,
    ForwardingDestination,
    SigninTime,
    SigninIP,
    RiskLevel,
    Location
| order by ForwardingTime desc
```

---

## Known Evasion Paths

- **Rule naming obfuscation:** Adversaries sometimes name rules to blend in with legitimate
  rules — detection fires on the forwarding action, not the rule name
- **Delayed rule creation:** Adversaries may wait hours after initial access before creating
  the rule — the base detection catches this regardless
- **Client-side rules:** Rules created in Outlook client rather than OWA may appear under
  different operation names — verify coverage with UpdateInboxRules inclusion

---

## Response Actions

When this alert fires:
1. Verify forwarding destination — personal provider vs. corporate vs. unknown domain
2. Review the user's recent sign-in history in Entra ID for anomalous authentication
3. Check for concurrent active sessions from different geolocations
4. If compromise is confirmed or probable:
   - Reset password on-premises AD
   - Disable account on-premises AD
   - Revoke all active sessions in Entra ID
   - Block source IP via conditional access named locations
   - Document the forwarding rule destination before removal
   - Notify client and defer rule removal to their confirmation

---

## References

- MITRE ATT&CK T1114.003: https://attack.mitre.org/techniques/T1114/003/
- Microsoft Sentinel OfficeActivity schema: https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/officeactivity
- Microsoft 365 Unified Audit Log operations: https://learn.microsoft.com/en-us/purview/audit-log-activities
