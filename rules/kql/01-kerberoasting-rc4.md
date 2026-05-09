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

This rule detects Kerberos service ticket requests in which the client specifies RC4 encryption (TicketEncryptionType 0x17). In environments where AES-128 (0x11) or AES-256 (0x12) is the domain standard, an RC4 TGS request targeting a user account SPN is the primary indicator of Kerberoasting — an offline hash cracking technique that exploits the ability to request a service ticket encrypted with the target account's password-derived key.

The rule was validated against Phase 5 of this project, during which `impacket-GetUserSPNs` was used with h.temp credentials to request a TGS for svc-sql-report over the soc.local domain.

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

Event 4769 is generated on the domain controller each time a Kerberos service ticket (TGS) is issued. Three filter conditions define the detection boundary. First, `TicketEncryptionType: 0x17` identifies RC4-HMAC encryption — the algorithm selected by Kerberoasting tools when the account's `msDS-SupportedEncryptionTypes` attribute permits it. Second, exclusion of `ServiceName` values ending in `$` removes machine account ticket requests, which are routine and voluminous. Third, exclusion of the `krbtgt` service name removes TGT renewal traffic.

A note on field naming: Winlogbeat-forwarded events surface the encryption type under `winlog.event_data.TicketEncryptionType`. ECS-normalized events may present the same value as `winlog.event_data.ticket_encryption_type`. The field name should be confirmed in Kibana Discover against live data before the rule is deployed.

When `impacket-GetUserSPNs` or Rubeus requests a TGS, the client specifies the desired encryption type in the request. The KDC honors RC4 unless the account's `msDS-SupportedEncryptionTypes` attribute explicitly excludes it. In Phase 5 of this project, svc-sql-report permitted RC4, and all captured hashes carried etype 0x17. Following AES enforcement in Phase 10, the KDC rejects RC4 requests for that account, rendering the hash capture step ineffective.

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
