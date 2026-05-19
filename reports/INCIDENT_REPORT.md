# Incident Report — Active Directory Attack & Defense
**Lab:** active-directory-attack-defense  
**Domain:** soc.local  
**Date:** May 2026  
**Analyst:** John Medina  
**Classification:** Lab / Portfolio — Not a real incident  
**Methodology:** SANS SEC504 (GCIH) / MITRE ATT&CK Framework  

---

## Executive Summary

A simulated adversary compromised the `soc.local` Active Directory environment by chaining together four credential-based attack techniques: BloodHound reconnaissance, Kerberoasting, AS-REP Roasting, and DCSync. The attack escalated from a low-privilege foothold account to full Domain Admin credential access, with all stages detected in the ELK SIEM using Windows Event Logs and Sysmon telemetry.

Following the attack simulation, the environment was hardened against each exploited vulnerability. A post-hardening BloodHound analysis confirmed a reduced attack surface. Residual risk was identified and documented as a finding.

---

## Environment

| Asset | Role | IP |
|---|---|---|
| WIN-DC01 | Windows Server 2022 Domain Controller | 192.168.10.160 |
| WIN10-ADCLIENT | Windows 10 Pro — Domain Workstation | 192.168.10.161 |
| Kali-Attacker | Kali Linux — Adversary Emulation | 192.168.10.20 |
| ELK-SIEM | Elasticsearch + Kibana SIEM | 192.168.10.100 |

**Domain:** soc.local  
**Telemetry:** Winlogbeat on DC and client → Logstash → Elasticsearch. Sysmon (SwiftOnSecurity config) on WIN10-ADCLIENT.

---

## Attack Timeline

### Stage 1 — Reconnaissance (T1087.002)
**Tool:** BloodHound CE / SharpHound  
**Source:** WIN10-ADCLIENT (domain user context: SOC\r.hayes)  
**Detection:** LDAP query burst observed in ELK

SharpHound was executed on the domain workstation under an authenticated domain user context. It performed LDAP enumeration of all domain objects, collecting 315 objects including user accounts, group memberships, computer objects, and session data. The resulting ZIP was imported into BloodHound CE on the attacker machine, which immediately revealed the shortest path to Domain Admin.

**Key findings from BloodHound:**
- `svc-sql-report` holds an SPN (`MSSQLSvc/win-dc01.soc.local:1433`) making it Kerberoastable
- `svc-backup-ops` has pre-authentication disabled, making it AS-REP Roastable
- `r.hayes` is a member of Domain Admins and has an active session on WIN-DC01

**MITRE ATT&CK:** T1087.002 — Account Discovery: Domain Account  
**Evidence:** `20260507_ad-lab_bloodhound-attack-path.png`, `20260507_ad-lab_kerberoast-target-account.png`

---

### Stage 2 — Kerberoasting (T1558.003)
**Tool:** Impacket `GetUserSPNs`  
**Source:** Kali-Attacker (192.168.10.20)  
**Detection:** Event ID 4769 — RC4 encryption type (0x17) — 237 events in ELK

Using foothold credentials (`h.temp`), Impacket requested a Kerberos TGS ticket for `svc-sql-report`. The DC issued the ticket encrypted with the service account's RC4 password hash. The hash was written to `kerberoast_hashes.txt` and submitted to Hashcat for offline cracking simulation.

**Why RC4 is the indicator:** Modern environments enforce AES encryption. An RC4 TGS request (etype 0x17) for a service account is anomalous and a reliable detection signal for Kerberoasting.

**Detection gap discovered:** Event 4769 was initially invisible in ELK because WIN-DC01 lacked Winlogbeat. Winlogbeat was installed on the DC and telemetry was restored. This represents a real-world telemetry coverage gap — a SOC without DC log forwarding is blind to the most critical AD attack techniques.

**MITRE ATT&CK:** T1558.003 — Steal or Forge Kerberos Tickets: Kerberoasting  
**Evidence:** `20260507_ad-lab_kerberoast-hash-capture.png`, `20260507_ad-lab_event-4769-elk.png`, `20260507_ad-lab_dc-winlogbeat-installed.png`

---

### Stage 3 — AS-REP Roasting (T1558.004)
**Tool:** Impacket `GetNPUsers`  
**Source:** Kali-Attacker (192.168.10.20)  
**Detection:** Event ID 4768 — Pre-authentication not required — 98 events in ELK

`svc-backup-ops` was configured with `DoesNotRequirePreAuth = True`, allowing an attacker to request an AS-REP without knowing the account's password. Impacket retrieved the encrypted AS-REP, which contains material crackable offline with Hashcat.

**MITRE ATT&CK:** T1558.004 — Steal or Forge Kerberos Tickets: AS-REP Roasting  
**Evidence:** `20260507_ad-lab_asrep-hash-capture.png`, `20260507_ad-lab_event-4768-elk.png`

---

### Stage 4 — LSASS Credential Access (T1003.001) — BLOCKED
**Tool:** Mimikatz / ProcDump  
**Source:** WIN10-ADCLIENT  
**Detection:** Sysmon Event ID 10 — Process access to lsass.exe

A direct LSASS memory dump was attempted from WIN10-ADCLIENT. Windows Defender Protected Process Light (PPL) blocked the dump. Sysmon logged the process access attempt (Event 10) with the source process attempting to open lsass.exe with PROCESS_VM_READ access.

**Portfolio note:** This is documented as a defensive control validation, not a failed attack. A hardened endpoint blocking LSASS dumping is exactly what defenders want to see. The Sysmon telemetry still generated an alert, demonstrating detection coverage even for blocked techniques.

**MITRE ATT&CK:** T1003.001 — OS Credential Dumping: LSASS Memory  
**Evidence:** `20260508_ad-lab_lsass-ppl-blocked.png`, `20260508_ad-lab_sysmon-event10-elk.png`

---

### Stage 5 — DCSync (T1003.006)
**Tool:** Impacket `secretsdump`  
**Source:** Kali-Attacker (192.168.10.20)  
**Detection:** Event ID 4662 — DS-Replication-Get-Changes — 103 events in ELK

Using a compromised account with replication privileges, Impacket simulated a DCSync attack by requesting directory replication from WIN-DC01. The DC responded with NTLM hashes for all domain accounts including the krbtgt account. NTLM hashes were captured and redacted before any GitHub commit.

**Why this matters:** DCSync does not require interactive logon to the DC. It abuses legitimate Active Directory replication protocols, making it difficult to block without breaking AD replication. Detection relies on auditing DS-Replication-Get-Changes events from non-DC sources.

**MITRE ATT&CK:** T1003.006 — OS Credential Dumping: DCSync  
**Evidence:** `20260508_ad-lab_dcsync-secretsdump-output.png`, `20260508_ad-lab_event-4662-elk.png`

---

## Detection Engineering

Six Elastic Security detection rules were created and validated against real attack telemetry. All rules were exported as NDJSON to `kibana-exports/ad-detection-rules.ndjson`.

| Rule | Event | Logic | Status |
|---|---|---|---|
| Kerberoasting RC4 | 4769 | etype = 0x17, service not krbtgt | Validated |
| AS-REP Roasting | 4768 | PreAuth = disabled | Validated |
| DCSync | 4662 | DS-Replication GUIDs from non-DC source | Validated |
| SharpHound LDAP Burst | 1644 | High LDAP query volume spike | Validated |
| LSASS PPL Block | Sysmon 10 | lsass.exe target process access | Validated |
| Lateral Movement NTLM | 4624 | LogonType 3, non-machine accounts | Validated |

**False positive finding:** An initial Event 4672 rule generated excessive alerts on the DC for SYSTEM, LOCAL SERVICE, and NETWORK SERVICE accounts performing routine privileged logons. Recommendation: add exclusions for known service accounts and machine accounts. This is documented as a detection tuning finding, which is standard SOC analyst work.

---

## Hardening Actions

Following the attack simulation, the following hardening measures were applied to the soc.local domain.

| Control | Account/Scope | Attack Mitigated |
|---|---|---|
| Protected Users Group | r.hayes, Administrator | Blocks NTLM auth, RC4 Kerberos, credential caching |
| RC4 Disabled / AES Enforced | svc-sql-report | Directly mitigates Kerberoasting (no RC4 TGS issuable) |
| Kerberos Pre-Auth Re-enabled | svc-backup-ops | Closes AS-REP Roasting attack vector |
| Strong Password Policy | Domain-wide | MinLength 16, Complexity, Lockout after 5 attempts |
| Directory Service Auditing | WIN-DC01 | DS Access + DS Changes: Success and Failure |

**Post-hardening BloodHound analysis:**
- Pre-hardening: svc-sql-report Kerberoastable with RC4 → hash crackable offline
- Post-hardening: RC4 disabled — Kerberoast attempt would return AES ticket only, not crackable with standard wordlists without AES cracking capability

---

## Residual Risk Finding

**Finding:** svc-sql-report retains SQLAdmin privileges on WIN-DC01.

Post-hardening BloodHound analysis revealed a residual attack path:

```
SVC-SQL-REPORT → SQLAdmin → WIN-DC01 → HasSession → R.HAYES → MemberOf → DOMAIN ADMINS
```

Even with RC4 disabled and AES enforced, if an attacker obtains the AES hash for `svc-sql-report` through other means, they retain a lateral movement path to the Domain Controller via SQL admin rights.

**Recommendation:** Review and remove SQLAdmin privileges from `svc-sql-report` unless operationally required. Apply principle of least privilege — a reporting service account should not hold local admin rights on the DC.

**Risk rating:** Medium — requires prior credential compromise of svc-sql-report, but represents unnecessary attack surface.

---

## Detection Gap — Golden Ticket (T1558.001)

A Golden Ticket attack was not executed in this lab due to the risk of persistent forged tickets surviving environment resets. However, a detection gap was identified: Event 4769 with anomalous TGS requests using the krbtgt hash would be the primary detection signal, but this is only reliable if the DC's krbtgt key version number is known and monitored.

**Recommendation:** Rotate krbtgt password twice (to invalidate existing Golden Tickets), monitor for TGS requests with mismatched ticket lifetimes, and deploy Microsoft Defender for Identity (MDI) or equivalent for Golden Ticket behavioral detection.

---

## Lessons Learned

1. **Telemetry coverage is as important as detection rules.** The initial DC telemetry gap meant Kerberoasting was completely invisible in ELK despite generating 237 events. A detection rule is useless without log forwarding.

2. **BloodHound reveals what defenders overlook.** The SQLAdmin privilege on svc-sql-report was not obvious from AD Users and Computers. BloodHound graph analysis exposed it immediately. Defenders should run BloodHound on their own environments regularly.

3. **Protected Users Group is a high-value, low-cost control.** Adding privileged accounts to Protected Users breaks NTLM authentication and RC4 Kerberos with a single group membership change. It should be standard for all Tier 0 accounts.

4. **Blocking is not the same as detecting.** Defender PPL blocked LSASS dumping but the attempt still generated a Sysmon Event 10 alert. Detection coverage exists even for blocked techniques — both the block and the alert are valuable signals.

5. **Detection tuning is real analyst work.** The Event 4672 false positive finding is not a failure — it is exactly what SOC analysts do daily. Documenting the finding and the tuning recommendation demonstrates analyst maturity.

---

## References

| Source | Label |
|---|---|
| SANS SEC504 / GCIH | Binder-backed |
| SANS SEC450 / GSOC | Binder-backed |
| MITRE ATT&CK Framework | Supplemental |
| Adversary Emulation with MITRE ATT&CK | Supplemental |
| Applied Incident Response | Supplemental |
| Intelligence-Driven Incident Response, 2nd ed. | Supplemental |

---

*All attacks were performed in an isolated lab environment against systems owned and controlled by the analyst. No production systems were involved.*
