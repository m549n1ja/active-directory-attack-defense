# Active Directory Attack & Defense Lab

## Adversary Emulation, Detection Engineering, and Hardening Against the Full AD Attack Chain

I built this lab because credential-based attacks against Active Directory are the most common entry path in enterprise breaches — and I wanted to understand them from both sides. Not just run a tool and capture a hash, but understand why the technique works, what telemetry it produces, how to write a detection that fires on the right signal, and how to harden the environment so the attack surface shrinks measurably.

This repository is the result: a self-built Windows Server 2022 Active Directory domain attacked with the canonical credential attack chain — BloodHound reconnaissance, Kerberoasting, AS-REP Roasting, LSASS dumping (blocked by PPL), and DCSync — with every technique detected in a live ELK SIEM, six custom KQL detection rules mapped to MITRE ATT&CK, and a complete hardening phase that demonstrably reduced the attack surface. Everything runs on commodity hardware using VMware Workstation.

---

## Project Goals

1. Can I build a realistic Active Directory environment from scratch, including intentionally vulnerable service accounts?
2. Can I execute the canonical credential attack chain using real tools (Impacket, BloodHound/SharpHound) from a Kali attacker VM?
3. Can I detect every technique in a live SIEM using event-driven KQL rules mapped to MITRE ATT&CK?
4. Can I harden the environment against the exact weaknesses I exploited and show a measurable reduction in attack surface using BloodHound before/after comparison?
5. Can I document the full kill chain — attack, detection, response, and hardening — at a level suitable for a SOC or DFIR portfolio?

---

## Skills Demonstrated

| Skill Area | How This Lab Demonstrates It |
|---|---|
| Active Directory administration | Built soc.local domain from scratch on Windows Server 2022; created users, groups, service accounts, and intentional misconfigurations |
| Adversary emulation | Executed BloodHound recon, Kerberoasting, AS-REP Roasting, LSASS dump attempt, and DCSync using Impacket and SharpHound |
| MITRE ATT&CK mapping | Mapped each attack technique to a specific sub-technique (T1087.002, T1558.003, T1558.004, T1003.001, T1003.006) |
| SIEM detection engineering | Wrote 6 custom KQL detection rules in Elastic Security, each validated against real attack telemetry |
| Alert tuning | Identified and documented false positive behavior in Event 4672 broad rule; produced tuning recommendation |
| Telemetry pipeline validation | Discovered and resolved a critical Winlogbeat gap on WIN-DC01 that was causing Event 4769 to be invisible in ELK |
| Endpoint protection validation | LSASS dump blocked by Defender PPL — documented as a defensive control validation, not a failure |
| AD hardening | Applied Protected Users group, AES-only Kerberos, PreAuth enforcement, strong password policy, and DS auditing |
| Attack surface reduction | Before/after BloodHound comparison showing measurable reduction in attack paths post-hardening |
| Documentation | Full deployment guide, architecture, evidence index, detection rule documentation, and incident report |

---

## Lab Architecture

```text
                        192.168.10.0/24
                   ┌──────────────────────────────┐
                   │                              │
   Internet ──── OPNsense (192.168.10.1)          │
                   │                              │
      ┌────────────┼──────────────┬───────────────┤
      │            │              │               │
      ▼            ▼              ▼               ▼
 WIN-DC01      WIN10-ADCLIENT  Kali-Attacker   ELK-SIEM
 192.168.10.160 192.168.10.161 192.168.10.20  192.168.10.100
 WinSrv 2022   Windows 10 Pro  Kali Linux     Ubuntu 24.04
 soc.local DC  domain joined   BloodHound CE  Elasticsearch
 Winlogbeat──► Sysmon          Impacket       Logstash:5044
               Winlogbeat ───► Hashcat        Kibana:5601
                               SharpHound
                   │                              │
                   └──────────────────────────────┘
                   Ryzen 9 Host: 192.168.10.10
                   VMware Workstation | 64GB RAM
```

---

## Technology Stack

| Component | Version | Purpose |
|---|---:|---|
| Windows Server 2022 | — | Domain Controller (WIN-DC01) |
| Windows 10 Pro | — | AD client endpoint (WIN10-ADCLIENT) |
| Kali Linux | Current | Attacker VM — adversary emulation |
| Sysmon64 | Current at install time | Windows process and network telemetry |
| Winlogbeat | 8.19.13 | Ships Windows Security and Sysmon events to ELK |
| Elasticsearch | 8.x | Stores and indexes security events |
| Kibana | 8.x | SIEM dashboards, detection rules, and alerts |
| BloodHound CE | v9.0.0-rc4 | AD graph analysis and attack path mapping |
| SharpHound | Current at install time | AD data collection for BloodHound |
| Impacket | Current | Kerberoasting, AS-REP Roasting, DCSync |
| Hashcat | Current | Offline hash cracking simulation |
| VMware Workstation | — | Local virtualization platform |

---

## Active Directory Structure

| Account | Type | Purpose |
|---|---|---|
| d.reyes, m.santos, e.miller, l.kim | Standard user | Normal domain users |
| a.brooks, p.nair, m.lee, s.alvarez | Standard user | Normal domain users |
| h.temp | Weak foothold | Password123! — initial access vector |
| o.intern | Weak foothold | Welcome1! — initial access vector |
| r.hayes | Domain Admin | Primary privileged target |
| o.grant | IT Admin | Secondary admin |
| svc-sql-report | Service account | Kerberoast target — SPN: MSSQLSvc/win-dc01.soc.local:1433 |
| svc-backup-ops | Service account | AS-REP Roast target — PreAuth initially disabled |

---

## Attack Chain

| # | Technique | Tool | MITRE | Event ID | Status |
|---:|---|---|---|---|---|
| 1 | AD Reconnaissance | BloodHound CE / SharpHound | T1087.002 | LDAP / Event 1644 | Complete |
| 2 | Kerberoasting | Impacket GetUserSPNs | T1558.003 | 4769 (RC4 / etype 0x17) | Complete |
| 3 | AS-REP Roasting | Impacket GetNPUsers | T1558.004 | 4768 (no pre-auth) | Complete |
| 4 | LSASS Dumping | Mimikatz / ProcDump | T1003.001 | Sysmon Event 10 | Blocked by Defender PPL |
| 5 | DCSync | Impacket secretsdump | T1003.006 | 4662 (replication GUIDs) | Complete |

---

## Telemetry

| Event ID | Technique | Count in ELK |
|---|---|---|
| 4769 | Kerberoasting (RC4 requests) | 237 events |
| 4768 | AS-REP Roasting (no pre-auth) | 98 events |
| 4662 | DCSync (replication rights exercised) | 103 events |

**Key finding — telemetry gap:** Event 4769 was initially invisible in ELK because WIN-DC01 lacked Winlogbeat. This is a real detection engineering failure mode: an incomplete telemetry pipeline creates a blind spot for DC-side authentication events. Resolved by installing Winlogbeat on the domain controller.

---

## Detection Rules

| # | Rule Name | Signal | Severity | MITRE | Status |
|---:|---|---|---|---|---|
| 1 | Kerberoasting RC4 | Event 4769, ticket_encryption_type 0x17 | High | T1558.003 | Verified firing |
| 2 | AS-REP Roasting | Event 4768, PreAuth failure | High | T1558.004 | Verified firing |
| 3 | DCSync | Event 4662, replication GUIDs | Critical | T1003.006 | Verified firing |
| 4 | SharpHound LDAP Burst | High LDAP query volume | High | T1087.002 | Verified firing |
| 5 | LSASS Process Access | Sysmon Event 10, lsass.exe target | High | T1003.001 | Verified — PPL blocked dump |
| 6 | Lateral Movement NTLM | Event 4624, LogonType 3 | Medium | T1550.002 | Verified firing |

Full KQL rule documentation: [`rules/kql/`](rules/kql/) | Sigma rules: [`rules/sigma/`](rules/sigma/)

**False positive finding:** An initially broad Event 4672 (special logon) rule generated excessive alerts on the domain controller. Documented as a detection engineering tuning exercise. Recommendation: exclude SYSTEM, LOCAL SERVICE, NETWORK SERVICE, and known admin accounts.

---

## AD Hardening (Phase 10)

| Control | What It Mitigates | Validated |
|---|---|---|
| Protected Users group (r.hayes, Administrator) | NTLM auth, credential caching, RC4 Kerberos for privileged accounts | Yes |
| AES-only Kerberos for svc-sql-report | Kerberoasting via RC4 (directly closes the Phase 5 attack vector) | Yes |
| Kerberos PreAuth re-enabled for svc-backup-ops | AS-REP Roasting (directly closes the Phase 3 attack vector) | Yes |
| Strong password policy (MinLength 16, Lockout 5) | Password guessing and weak credential attacks | Yes |
| Directory Service Auditing enabled | DS Access and DS Changes events for DCSync and recon detection | Yes |
| Post-hardening BloodHound comparison | Measurable reduction in attack paths to Domain Admin | In progress |

---

## Key Findings and Lessons

### 1. Telemetry gap on the domain controller
Kerberoasting generates Event 4769 — but only on the DC. If the DC does not have a log shipper installed, the event never reaches the SIEM. This was discovered during Phase 5 and corrected by installing Winlogbeat on WIN-DC01. The detection gap was documented as a real SOC troubleshooting finding.

### 2. LSASS PPL blocks credential dumping without disabling Defender
Protected Process Light prevented Mimikatz and ProcDump from reading LSASS memory. Sysmon Event 10 captured the attempt. This is documented as a defensive validation, not a failure — the control worked exactly as intended.

### 3. DCSync detection requires specific replication GUIDs
Event 4662 fires for many legitimate replication operations. The detection requires filtering on the specific DS-Replication-Get-Changes and DS-Replication-Get-Changes-All GUIDs to separate attack traffic from normal DC replication activity.

### 4. Hardening should directly map to the attack that exposed the weakness
Each hardening control applied in Phase 10 directly addresses a specific attack technique from the chain. AES-only Kerberos closes Kerberoasting. PreAuth enforcement closes AS-REP Roasting. This attack-to-mitigation mapping is the portfolio value of the before/after comparison.

### 5. BloodHound path analysis before and after hardening is evidence of measurable improvement
Showing attack path reduction in BloodHound graph form is more compelling than a list of configuration changes. The before state shows paths to Domain Admin. The after state shows those paths removed or requiring additional steps.

---

## Evidence

The repository includes screenshot evidence covering:

- Domain controller build and AD DS installation
- User and service account creation including intentional misconfigurations
- Kali attacker VM setup and tool validation
- BloodHound recon and attack path visualization
- Kerberoasting hash capture (hash redacted)
- AS-REP Roasting hash capture (hash redacted)
- LSASS dump attempt — blocked by Defender PPL
- DCSync execution (hashes redacted)
- ELK telemetry for every technique (Events 4769, 4768, 4662, Sysmon 10)
- All 6 Kibana detection rules firing
- Winlogbeat installed on DC — telemetry gap resolved
- All 5 hardening controls applied and validated
- Post-hardening SharpHound collection

Full evidence index: [`evidence/EVIDENCE_INDEX.md`](evidence/EVIDENCE_INDEX.md)

---

## What I Would Improve for Production

1. **Use Microsoft Entra ID Connect for hybrid identity** — the lab uses a standalone on-premises domain. A production environment would integrate with Entra ID for cloud authentication and conditional access.
2. **Enable Microsoft Defender for Identity** — MDI provides DC-level sensor coverage without requiring a manual Winlogbeat deployment. The telemetry gap in this lab is exactly the problem MDI solves.
3. **Implement LAPS** — Local Administrator Password Solution eliminates shared local admin credentials and lateral movement via pass-the-hash using local accounts.
4. **Tiered administration model** — separate admin accounts for Tier 0 (DCs), Tier 1 (servers), and Tier 2 (workstations) to limit the blast radius of a compromised account.
5. **Export detection rules as NDJSON and version-control them** — the NDJSON export is included in this repository, but a production workflow would include CI/CD rule validation and automated deployment.

---

## Repository Documents

| Document | Description |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | Network topology, VM specs, domain design, and data flow |
| [DEPLOYMENT.md](DEPLOYMENT.md) | Phase-by-phase build guide — DC, client, Kali, attack chain, detection, hardening |
| [CURRENT_LIMITATIONS.md](CURRENT_LIMITATIONS.md) | Honest assessment of lab scope vs. production |
| [CHANGELOG.md](CHANGELOG.md) | Dated build history |
| [evidence/EVIDENCE_INDEX.md](evidence/EVIDENCE_INDEX.md) | All screenshots mapped to phases and detection rules |

---

## Methodology References

| Source | Application |
|---|---|
| SANS SEC504 / GCIH | Incident handling lifecycle and AD attack methodology |
| SANS SEC450 / GSOC | SOC detection and triage workflow |
| *Adversary Emulation with MITRE ATT&CK* | Structured attack simulation and detection coverage |
| *Applied Incident Response* | Evidence collection, incident timeline, reporting format |
| *Intelligence-Driven Incident Response* (2nd ed.) | Threat-informed detection approach |
| *Advanced Penetration Testing* (Wiley) | Offensive tradecraft context for AD simulation |
| MITRE ATT&CK Framework | Technique and sub-technique mapping |

---

## Repository Status

This project is actively being documented for portfolio publication. The lab is built and producing data through Phase 10. Remaining work: BloodHound before/after comparison screenshots, MITRE ATT&CK Navigator export, incident report, and final documentation cleanup before the GitHub push.

---

Built by **John Medina**
GitHub: [m549n1ja](https://github.com/m549n1ja)
