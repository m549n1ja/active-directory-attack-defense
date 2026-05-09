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

Detects DCSync attacks — a technique where an attacker with replication rights uses the Directory Replication Service (DRS) protocol to request password hashes for any domain account, including the KRBTGT account. The attack mimics legitimate domain controller replication but originates from a non-DC source.

This rule fired on the DCSync attack executed in Phase 7 using `impacket-secretsdump` from Kali-Attacker.

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

Event 4662 fires when an operation is performed on an Active Directory object. The critical signal is the specific GUIDs in the `Properties` field:

| GUID | Right | Meaning |
|---|---|---|
| `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` | DS-Replication-Get-Changes | Basic replication right |
| `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` | DS-Replication-Get-Changes-All | Full replication — includes secret data (password hashes) |
| `89e95b76-444d-4c62-991a-0facbeda640c` | DS-Replication-Get-Changes-In-Filtered-Set | Extended replication |

`SubjectUserName` excluding `*$` — machine accounts (legitimate DCs) are excluded. A non-DC account performing replication is the DCSync signal.

---

## Why This Fires on DCSync

When `impacket-secretsdump` (or Mimikatz `dcsync`) exercises replication rights, Windows records Event 4662 with the DS-Replication-Get-Changes-All GUID. Legitimate replication between DCs also generates this event — but from machine accounts (`*$`). The filter on `SubjectUserName` without `$` isolates non-DC accounts exercising replication rights.

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
