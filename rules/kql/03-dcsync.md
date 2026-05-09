# Rule 03 — DCSync

| Field | Value |
|---|---|
| Index pattern | `winlogbeat-*` |
| Severity | Critical |
| MITRE ATT&CK | T1003.006 — OS Credential Dumping: DCSync |
| Event ID | 4662 |
| Rule type | Custom query |
| Status | Verified firing — 103 alerts in lab |

---

## Purpose

This rule detects DCSync, a credential extraction technique in which an account holding Active Directory replication rights uses the Directory Replication Service (DRS) protocol to request password hashes for domain accounts — including the KRBTGT account — without requiring interactive access to the domain controller. The technique is indistinguishable from legitimate inter-DC replication at the protocol level; detection depends on identifying replication operations originating from accounts that are not domain controller machine accounts.

The rule was validated against Phase 7 of this project, during which `impacket-secretsdump` was used with r.hayes credentials to replicate credential material from WIN-DC01.

---

## KQL Query

```kql
event.code: "4662" and
winlog.event_data.AccessMask: "0x100" and
(
  winlog.event_data.Properties: "*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*" or
  winlog.event_data.Properties: "*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*" or
  winlog.event_data.Properties: "*89e95b76-444d-4c62-991a-0facbeda640c*"
) and
not winlog.event_data.SubjectUserName: "*$"
```

---

## Rule Logic

Event 4662 is generated on the domain controller when an operation is performed against an Active Directory object. The detection pivots on two conditions: the presence of specific GUIDs in the `Properties` field, and the identity of the subject performing the operation.

| GUID | Extended Right | Notes |
|---|---|---|
| `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` | DS-Replication-Get-Changes | Basic replication permission |
| `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` | DS-Replication-Get-Changes-All | Full replication — includes password hashes and secret attributes |
| `89e95b76-444d-4c62-991a-0facbeda640c` | DS-Replication-Get-Changes-In-Filtered-Set | Extended replication for read-only DCs |

The exclusion of `SubjectUserName` values ending in `$` removes legitimate domain controller machine accounts, which exercise these rights routinely as part of normal inter-DC replication. Any non-machine account appearing in `SubjectUserName` for these GUIDs is the DCSync detection signal — the account is performing an operation that only domain controllers should perform.

When `impacket-secretsdump` exercises replication rights, Windows records Event 4662 with the DS-Replication-Get-Changes-All GUID against the domain object. The event is structurally identical to what a legitimate DC replication generates — the only differentiating factor is that the `SubjectUserName` is a user account rather than a machine account. This specificity is what makes the GUID-plus-account-type filter effective and is also what makes DCSync difficult to detect through behavioral heuristics alone.

---

## Prerequisites

- Winlogbeat installed on WIN-DC01
- Directory Service Access auditing enabled:
  ```powershell
  auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable
  ```
  This was validated in Phase 10 of this lab. Without DS auditing, Event 4662 is not generated.
- winlogbeat-* data view configured in Kibana Security

---

## Test Method

From Kali-Attacker, run (requires a compromised account with replication rights):
```bash
impacket-secretsdump soc.local/r.hayes:[REDACTED]@192.168.10.160 -just-dc
```

Wait 30–60 seconds, then filter Kibana Discover:
```kql
event.code: "4662" and winlog.event_data.Properties: "*1131f6ad*"
```

---

## Expected Result

Event 4662 appears with:
- `winlog.event_data.SubjectUserName`: r.hayes (or compromised account)
- `winlog.event_data.Properties`: contains DS-Replication GUIDs
- `winlog.event_data.AccessMask`: 0x100
- Source is the Kali IP, not a DC machine account

---

## Evidence

- `evidence/screenshots/20260508_ad-lab_event-4662-elk.png`
- `evidence/screenshots/20260508_ad-lab_dcsync-rule-alert.png`

---

## False Positives

- Legitimate domain controller replication (filtered out by `SubjectUserName: *$`)
- Azure AD Connect or other directory sync tools that hold replication rights — should be explicitly excluded by `SubjectUserName`
- Microsoft Defender for Identity itself requests replication as part of its sensor operation

**Tuning:** Add known sync accounts to the exclusion list. Monitor the `SubjectUserName` field for any non-DC, non-sync accounts triggering this rule — those should be treated as critical incidents.

---

## Post-Hardening Note

DCSync requires an account with replication rights. The hardening actions in Phase 10 do not directly remove replication rights from r.hayes. The Protected Users group limits NTLM and credential caching but does not revoke directory permissions. DCSync prevention requires restricting the `Replicating Directory Changes All` right to DC machine accounts only — which is a production improvement documented in CURRENT_LIMITATIONS.md.
