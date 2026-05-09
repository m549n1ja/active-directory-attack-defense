# Rule 06 — Lateral Movement NTLM

| Field | Value |
|---|---|
| Index pattern | `winlogbeat-*` |
| Severity | Medium |
| MITRE ATT&CK | T1550.002 — Use Alternate Authentication Material: Pass the Hash |
| Event ID | 4624 |
| Rule type | Custom query / threshold |
| Status | Verified firing in lab |

---

## Purpose

This rule detects lateral movement via NTLM network authentication, the mechanism underlying Pass-the-Hash. When a captured NTLM hash is used in place of a plaintext password, the resulting authentication event carries LogonType 3 (network logon) and an authentication package value of NTLM. In a correctly configured Kerberos domain, network-layer authentication between domain-joined systems defaults to Kerberos. NTLM appearing in a network logon context — particularly from unexpected source addresses or against domain controllers — warrants investigation as a potential lateral movement indicator.

---

## KQL Query

```kql
event.code: "4624" and
winlog.event_data.LogonType: "3" and
winlog.event_data.AuthenticationPackageName: "NTLM" and
not winlog.event_data.SubjectUserName: "ANONYMOUS LOGON" and
not winlog.event_data.WorkstationName: "-"
```

---

## Threshold Enhancement

For higher confidence detection, apply as a threshold:

```kql
event.code: "4624" and
winlog.event_data.LogonType: "3" and
winlog.event_data.AuthenticationPackageName: "NTLM"
```

Alert when more than 5 events from the same `winlog.event_data.IpAddress` within 5 minutes.

---

## Rule Logic

Event 4624 fires on successful logon. The fields of interest:

- `LogonType: 3` — Network logon. The credentials were presented over the network rather than interactively.
- `AuthenticationPackageName: NTLM` — NTLM was used instead of Kerberos. In a properly configured domain, network logons should use Kerberos unless:
  - The target is accessed by IP address instead of hostname
  - The target is a workgroup (non-domain) machine
  - A legacy or misconfigured application forces NTLM
  - An attacker is performing pass-the-hash
- `WorkstationName` present — excludes service account logons that leave this field blank

---

## Kerberos vs. NTLM and Detection Significance

Kerberos requires the authenticating client to prove knowledge of the account secret to obtain a ticket-granting ticket from the KDC. NTLM operates via a challenge-response protocol in which the client responds with a hash-derived value — meaning that possession of the NTLM hash is sufficient to complete authentication without the plaintext credential. Pass-the-Hash exploits this property directly.

Members of the Protected Users security group cannot authenticate using NTLM under any circumstance, regardless of what the client requests. Following the addition of r.hayes and Administrator to Protected Users in Phase 10, NTLM network logons for those accounts fail at the authentication layer, and the lateral movement path they represent is closed without requiring changes to network segmentation or firewall policy.

---

## Prerequisites

- Winlogbeat installed on WIN-DC01 and WIN10-ADCLIENT
- Windows Security Logon/Logoff auditing enabled
- winlogbeat-* data view configured in Kibana Security

---

## Test Method

From Kali-Attacker using a captured NTLM hash:
```bash
impacket-psexec -hashes :NTLM_HASH_HERE soc.local/r.hayes@192.168.10.161
```

Or using valid credentials over NTLM:
```bash
impacket-smbclient soc.local/h.temp:'Password123!'@192.168.10.160
```

Filter Kibana Discover:
```kql
event.code: "4624" and winlog.event_data.LogonType: "3" and winlog.event_data.AuthenticationPackageName: "NTLM"
```

---

## Expected Result

Event 4624 appears with:
- `winlog.event_data.LogonType`: 3
- `winlog.event_data.AuthenticationPackageName`: NTLM
- `winlog.event_data.TargetUserName`: target account
- `winlog.event_data.IpAddress`: attacker IP (192.168.10.20)
- `winlog.event_data.WorkstationName`: Kali hostname

---

## Evidence

- `evidence/screenshots/20260508_ad-lab_lateral-movement-ntlm-alert.png`

---

## False Positives

- Legacy applications that use NTLM because Kerberos is not configured (file shares accessed by IP instead of hostname, older software)
- Print servers and NAS devices that do not support Kerberos
- Some monitoring tools that authenticate via NTLM

**Tuning:**
1. Establish a baseline of which systems generate NTLM network logons legitimately
2. Alert on NTLM network logons from systems not on the baseline — especially workstations authenticating to other workstations or to the DC
3. NTLM logons from the Kali VM IP (192.168.10.20) should immediately alert — this IP has no legitimate business reason to authenticate via NTLM

## Post-Hardening Note

After adding r.hayes and Administrator to the Protected Users group (Phase 10), NTLM authentication is disabled for those accounts. Pass-the-Hash attacks against those accounts will fail at the authentication stage with a `STATUS_ACCOUNT_RESTRICTION` error, and the 4624 event will not appear — preventing lateral movement entirely for those accounts.
