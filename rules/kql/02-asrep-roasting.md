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

Detects AS-REP Roasting — an attack that targets accounts with Kerberos pre-authentication disabled. When pre-authentication is disabled, an attacker can request an Authentication Service Response (AS-REP) for any user without knowing their password, then crack the encrypted portion offline.

This rule fired on the AS-REP Roasting attack executed in Phase 6 against svc-backup-ops.

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

Event 4768 is generated on the domain controller when a Kerberos Authentication Service (AS) request is received. The key fields are:

- `PreAuthType: 0` — pre-authentication was not used. Legitimate logins always include pre-auth (type 2 = encrypted timestamp).
- `Status: 0x0` — the request succeeded. A success with no pre-auth is the AS-REP Roasting signature.
- `TargetUserName` excluding `*$` — machine accounts are excluded.

---

## Why This Fires on AS-REP Roasting

When `impacket-GetNPUsers` (or Rubeus `asreproast`) targets an account with `DoesNotRequirePreAuth = True`, it sends a bare AS-REQ with no encrypted timestamp. The KDC responds with an AS-REP containing a portion encrypted with the account's password hash — which can then be cracked offline. Event 4768 records this request with `PreAuthType = 0`.

After re-enabling PreAuth on svc-backup-ops in Phase 10, this attack fails because the KDC requires an encrypted timestamp before responding.

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
