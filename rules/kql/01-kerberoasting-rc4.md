# Rule 01 — Kerberoasting RC4

| Field | Value |
|---|---|
| Index pattern | `winlogbeat-*` |
| Severity | High |
| MITRE ATT&CK | T1558.003 — Steal or Forge Kerberos Tickets: Kerberoasting |
| Event ID | 4769 |
| Rule type | Custom query |
| Status | Verified firing — 237 alerts in lab |

---

## Purpose

Detects Kerberos service ticket requests using RC4 encryption (ticket_encryption_type 0x17). Legitimate modern environments use AES-256 (etype 0x12) or AES-128 (etype 0x11). An RC4 TGS request for a service account SPN is the primary signal of Kerberoasting.

This rule fired on the Kerberoasting attack executed in Phase 5 using `impacket-GetUserSPNs` with h.temp credentials against svc-sql-report.

---

## KQL Query

```kql
event.code: "4769" and
winlog.event_data.TicketEncryptionType: "0x17" and
not winlog.event_data.ServiceName: "*$" and
not winlog.event_data.ServiceName: "krbtgt"
```

---

## Rule Logic

Event 4769 is generated on the domain controller when a Kerberos service ticket (TGS) is requested. The critical fields are:

- `TicketEncryptionType: 0x17` — RC4-HMAC encryption. Modern Kerberos uses AES. An RC4 request targeting a user account SPN is a strong Kerberoasting indicator.
- `ServiceName` must not end in `$` — machine account tickets are excluded.
- `ServiceName` must not be `krbtgt` — TGT renewal is excluded.

**Field name note:** In Winlogbeat-shipped events, the encryption type appears under `winlog.event_data.TicketEncryptionType`. In ECS-normalized events it may appear under `winlog.event_data.ticket_encryption_type`. Verify the field name in Kibana Discover before deploying.

---

## Why This Fires on Kerberoasting

When `impacket-GetUserSPNs` (or Rubeus) requests a TGS for a service account, it can request RC4 encryption regardless of what the KDC prefers — unless RC4 is explicitly disabled on the account (`msDS-SupportedEncryptionTypes` set to AES only). In Phase 5, svc-sql-report allowed RC4, so the hash request used type 0x17. After hardening in Phase 10, this request would fail.

---

## Prerequisites

- Winlogbeat installed on WIN-DC01 (the domain controller)
- Windows Security event channel captured
- Kerberos service ticket events enabled (enabled by default with audit policy)
- winlogbeat-* data view configured in Kibana Security

**Note:** If Winlogbeat is not installed on the DC, this event will never reach ELK. This was the root cause of the telemetry gap discovered in Phase 5.

---

## Test Method

From Kali-Attacker, run:
```bash
impacket-GetUserSPNs soc.local/h.temp:'Password123!' -dc-ip 192.168.10.160 -request
```

Wait 30–60 seconds, then filter Kibana Discover:
```kql
event.code: "4769" and winlog.event_data.TicketEncryptionType: "0x17"
```

---

## Expected Result

Event 4769 appears in Kibana with:
- `winlog.event_data.TicketEncryptionType`: 0x17
- `winlog.event_data.ServiceName`: svc-sql-report (or the targeted SPN)
- `winlog.event_data.ClientAddress`: the Kali attacker IP (192.168.10.20)

---

## Evidence

- `evidence/screenshots/20260507_ad-lab_event-4769-elk.png`
- `evidence/screenshots/20260507_ad-lab_kerberoasting-rule-alert.png`

---

## False Positives

- Legacy applications that authenticate using RC4 Kerberos (older .NET services, some SQL Server configurations)
- Environments that have not completed AES migration and still have RC4 as an allowed encryption type

**Tuning:** After completing AES enforcement, this rule should produce zero false positives. Monitor for any services that break after RC4 removal.

---

## Post-Hardening Behavior

After applying AES-only encryption in Phase 10 (`Set-ADUser -Identity svc-sql-report -KerberosEncryptionType AES128,AES256`), RC4 TGS requests for this account are rejected by the KDC. This rule's alert volume should drop to zero for that account.
