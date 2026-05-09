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

Detects lateral movement using NTLM authentication, which is the primary signal for Pass-the-Hash attacks. When an attacker uses a captured NTLM hash to authenticate (rather than knowing the actual password), the authentication event is recorded with LogonType 3 (network logon) and authentication package NTLM.

In modern Kerberos environments, network authentication typically uses Kerberos. An NTLM network logon from an unexpected source — particularly a workstation authenticating to a server or DC — is a lateral movement indicator.

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

## Why Kerberos vs. NTLM Matters for Detection

Kerberos authentication requires the client to prove knowledge of the password to obtain a Kerberos ticket. NTLM authentication uses a challenge-response mechanism that only requires the NTLM hash — not the plaintext password. This is why pass-the-hash works: the attacker presents the hash directly during the NTLM challenge-response without needing to crack it.

Protected Users group members (applied to r.hayes and Administrator in Phase 10) cannot use NTLM authentication at all, which means this attack path is removed for those accounts after hardening.

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
