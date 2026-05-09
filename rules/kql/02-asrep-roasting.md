# Rule 02 — AS-REP Roasting

| Field | Value |
|---|---|
| Index pattern | `winlogbeat-*` |
| Severity | High |
| MITRE ATT&CK | T1558.004 — Steal or Forge Kerberos Tickets: AS-REP Roasting |
| Event ID | 4768 |
| Rule type | Custom query |
| Status | Verified firing — 98 alerts in lab |

---

## Purpose

This rule detects AS-REP Roasting, a technique that targets accounts configured with Kerberos pre-authentication disabled (`DoesNotRequirePreAuth = True`). When that attribute is set, the Key Distribution Center returns an AS-REP containing a session key encrypted with the account's password-derived key in response to any AS-REQ — without requiring the requester to first prove knowledge of that key via an encrypted timestamp. The encrypted blob can then be subjected to offline dictionary or brute-force attack.

The rule was validated against Phase 6 of this project, during which `impacket-GetNPUsers` was used to extract an AS-REP from svc-backup-ops, which had DoesNotRequirePreAuth set to True during the attack phase.

---

## KQL Query

```kql
event.code: "4768" and
winlog.event_data.PreAuthType: "0" and
winlog.event_data.Status: "0x0" and
not winlog.event_data.TargetUserName: "*$"
```

---

## Rule Logic

Event 4768 records each Kerberos Authentication Service request received by the domain controller. Three field conditions define the detection. `PreAuthType: 0` indicates that the AS-REQ carried no pre-authentication data — no encrypted timestamp was provided to prove knowledge of the account key. `Status: 0x0` confirms the KDC returned a successful response, meaning the AS-REP was issued. The exclusion of `TargetUserName` values ending in `$` removes machine account authentication, which is both routine and voluminous.

The combination of `PreAuthType: 0` and `Status: 0x0` is the AS-REP Roasting signature. A legitimate user logging in through a Kerberos-capable client will always send a pre-authentication value; a request absent that value against a standard account is anomalous.

Following the re-enablement of Kerberos pre-authentication on svc-backup-ops in Phase 10 (`DoesNotRequirePreAuth = False`), the KDC requires an encrypted timestamp before issuing an AS-REP. Requests without it are rejected, and this rule's alert volume for that account drops to zero.

---

## Prerequisites

- Winlogbeat installed on WIN-DC01
- Windows Security event channel captured
- Kerberos authentication events enabled (enabled by default)
- winlogbeat-* data view configured in Kibana Security

---

## Test Method

From Kali-Attacker, run:
```bash
impacket-GetNPUsers soc.local/ -dc-ip 192.168.10.160 -no-pass -usersfile /tmp/users.txt
```

Or target directly:
```bash
impacket-GetNPUsers soc.local/svc-backup-ops -dc-ip 192.168.10.160 -no-pass -format hashcat
```

Wait 30–60 seconds, then filter Kibana Discover:
```kql
event.code: "4768" and winlog.event_data.PreAuthType: "0"
```

---

## Expected Result

Event 4768 appears with:
- `winlog.event_data.TargetUserName`: svc-backup-ops (or targeted user)
- `winlog.event_data.PreAuthType`: 0
- `winlog.event_data.Status`: 0x0
- `winlog.event_data.IpAddress`: Kali attacker IP (192.168.10.20)

---

## Evidence

- `evidence/screenshots/20260507_ad-lab_event-4768-elk.png`
- `evidence/screenshots/20260508_ad-lab_asrep-rule-alert.png`

---

## False Positives

- Legacy applications or clients that do not send Kerberos pre-authentication (rare in modern environments)
- Misconfigured or legacy services set to DoNotRequirePreAuth by an administrator for compatibility

**Tuning:** Any account with DoesNotRequirePreAuth = True is a misconfiguration and should be corrected. After re-enabling PreAuth on all accounts, this rule should produce zero true-positive alerts.
