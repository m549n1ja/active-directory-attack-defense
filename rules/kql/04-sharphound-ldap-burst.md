# Rule 04 — SharpHound LDAP Burst

| Field | Value |
|---|---|
| Index pattern | `winlogbeat-*` |
| Severity | High |
| MITRE ATT&CK | T1087.002 — Account Discovery: Domain Account |
| Event ID | 4662 / LDAP diagnostics |
| Rule type | Threshold or custom query |
| Status | Verified firing in lab |

---

## Purpose

This rule targets the LDAP query burst that SharpHound generates during BloodHound data collection. When SharpHound is executed with full collection options, it enumerates users, groups, computers, group policy objects, ACL entries, and domain trust data through a sustained series of LDAP queries against the domain controller. The resulting query volume and rate substantially exceed what standard user or application behavior produces against directory services, making volume-based threshold detection viable where LDAP diagnostic logging is enabled.

The rule was validated against the Phase 4 BloodHound reconnaissance executed in this project.

---

## KQL Query

```kql
event.code: "4662" and
winlog.event_data.OperationType: "Object Access" and
winlog.event_data.ObjectType: "%{19195a5b-6da0-11d0-afd3-00c04fd930c9}"
```

The GUID `19195a5b-6da0-11d0-afd3-00c04fd930c9` represents the `domainDNS` object class — one of the primary targets SharpHound queries during domain enumeration.

**Threshold approach (recommended for production):**
Apply this rule as a threshold — more than 100 Event 4662 events from the same `SubjectUserName` within 10 minutes triggers an alert. A single legitimate user will rarely query this many AD objects in that timeframe.

---

## Alternative: Windows Event 1644 (LDAP Query Statistics)

Event ID 1644 on the domain controller provides LDAP query statistics and is the most reliable signal for detecting LDAP reconnaissance. It requires enabling LDAP diagnostic logging:

```
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics
Value: 15 Field Engineering
Data: 5 (enables logging of expensive LDAP queries)
```

With 1644 enabled, unusually expensive or high-volume LDAP queries from non-DC sources appear in the Directory Service event log.

---

## Rule Logic

A full SharpHound collection produces hundreds to thousands of LDAP queries against the domain controller in a compressed timeframe — enumerating all user attributes, all nested group memberships, all computer account sessions, ACL entries for privileged objects, and Group Policy Objects in sequence. The volume of Event 4662 records attributable to a single `SubjectUserName` during that window is anomalous by any reasonable baseline. Threshold-based detection on that field — applied either to Event 4662 volume or to Event 1644 query statistics — captures the pattern without requiring knowledge of SharpHound's specific LDAP query signatures, which vary across versions.

---

## Prerequisites

- Winlogbeat installed on WIN-DC01
- Directory Service Access auditing enabled
- For Event 1644: LDAP diagnostic logging registry key set to 5 for Field Engineering
- winlogbeat-* data view configured in Kibana Security

---

## Test Method

From WIN10-ADCLIENT (logged in as a domain user), run SharpHound:
```powershell
.\SharpHound.exe -c All --domain soc.local --domaincontroller WIN-DC01.soc.local
```

Monitor Kibana for elevated Event 4662 volume from the executing user's account.

---

## Expected Result

Spike in Event 4662 events from the `SubjectUserName` running SharpHound, targeting `domainDNS` and other AD object classes over a short time window.

---

## Evidence

- `evidence/screenshots/20260507_ad-lab_sharphound-collection-complete.png`
- `evidence/screenshots/20260508_ad-lab_sharphound-rule-alert.png`

---

## False Positives

- Legitimate AD management tools that perform bulk LDAP queries (AD synchronization, HR system sync, identity governance)
- Domain controller replication processes
- Scheduled scripts that enumerate AD objects for reporting

**Tuning:** Establish a baseline of normal LDAP query volume per user and per source IP. Alert on deviations above a multiple of the baseline rather than a fixed threshold.
