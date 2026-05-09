# Active Directory Attack & Defense Lab

## Adversary Emulation, Detection Engineering, and Hardening Against the Canonical Active Directory Attack Chain

Credential-based attacks targeting Active Directory represent the most prevalent initial access and privilege escalation vector in enterprise breach cases. This project examines that threat from both the offensive and defensive perspective: constructing a realistic Windows Server 2022 domain, executing the documented AD attack chain using purpose-built adversary emulation tools, engineering detection logic against the resulting telemetry, and applying targeted hardening controls to reduce the domain's attack surface.

The environment consists of a self-built soc.local domain controller (WIN-DC01), a domain-joined Windows 10 endpoint (WIN10-ADCLIENT), a Kali Linux attack platform, and an existing ELK 8.x SIEM. The attack chain encompasses BloodHound reconnaissance, Kerberoasting, AS-REP Roasting, LSASS credential dumping (blocked by Protected Process Light), and DCSync. Each technique produced measurable telemetry — 237 Event 4769 records, 98 Event 4768 records, and 103 Event 4662 records — that informed the construction of six custom KQL detection rules, each mapped to a specific MITRE ATT&CK sub-technique. A subsequent hardening phase applied five domain-level controls directly correlated to the exploited weaknesses and generated a BloodHound before-and-after comparison to quantify attack surface reduction.

---

## Scope and Purpose

The objectives governing this project were as follows: to build and configure an Active Directory domain from bare hardware without reliance on pre-built templates or cloud-hosted infrastructure; to execute each technique in the attack chain using the same tooling documented in adversary emulation methodology literature; to develop detection logic grounded in the specific event signatures produced by each technique rather than generic behavioral heuristics; and to apply hardening controls that directly address the misconfigurations exploited, with documented validation of each control.

The project is not intended to represent a fully hardened production deployment. Several configurations present in the environment — RC4-enabled Kerberos encryption, disabled pre-authentication, and weak foothold account credentials — were introduced deliberately to provide conditions under which the targeted techniques would succeed. Those misconfigurations are catalogued in [CURRENT_LIMITATIONS.md](CURRENT_LIMITATIONS.md) alongside the controls applied to remediate them.

---

## Competencies Addressed

| Domain | Evidence in This Project |
|---|---|
| Active Directory administration | soc.local domain built from installation; users, groups, service accounts, and intentional misconfigurations configured via PowerShell |
| Adversary emulation | BloodHound, SharpHound, Impacket GetUserSPNs, Impacket GetNPUsers, and Impacket secretsdump executed in sequence against the live domain |
| MITRE ATT&CK mapping | Each technique mapped to a specific sub-technique: T1087.002, T1558.003, T1558.004, T1003.001, T1003.006 |
| Detection engineering | Six custom Elastic Security KQL rules authored and validated against live attack telemetry |
| False positive analysis | Event 4672 over-alerting on the domain controller identified and documented with a tuning recommendation |
| Telemetry pipeline validation | Winlogbeat absence on WIN-DC01 identified as a blind spot causing Event 4769 to be absent from ELK; corrected and validated |
| Endpoint protection validation | LSASS credential dump blocked by Defender PPL; Sysmon Event 10 captured the access attempt independently of the dump outcome |
| Active Directory hardening | Protected Users group, AES-only Kerberos enforcement, PreAuth re-enablement, password policy strengthening, and Directory Service auditing applied |
| Attack surface reduction | Post-hardening SharpHound collection and BloodHound graph comparison document reduced attack paths to Domain Admin |

---

## Lab Architecture

```text
                        192.168.10.0/24
                   ┌──────────────────────────────┐
                   │                              │
   Internet ──── OPNsense (192.168.10.1)          │
                   │   Chromebox CN60             │
                   │                              │
      ┌────────────┼──────────────┬───────────────┤
      │            │              │               │
      ▼            ▼              ▼               ▼
 WIN-DC01      WIN10-ADCLIENT  Kali-Attacker   ELK-SIEM
 192.168.10.160 192.168.10.161 192.168.10.20  192.168.10.100
 WinSrv 2022   Windows 10 Pro  Kali Linux     Ubuntu 24.04
 soc.local DC  Domain joined   BloodHound CE  Elasticsearch
 Winlogbeat    Sysmon64        Impacket       Logstash:5044
               Winlogbeat ────────────────►  Kibana:5601
                   │                              │
                   └──────────────────────────────┘
              Ryzen 9 Desktop | 192.168.10.10
              VMware Workstation | 64 GB RAM
```

---

## Technology Stack

| Component | Version | Role |
|---|---:|---|
| Windows Server 2022 | — | Domain Controller (WIN-DC01) |
| Windows 10 Pro | — | Domain workstation (WIN10-ADCLIENT) |
| Kali Linux | Current | Adversary emulation platform |
| Sysmon64 | Current at install | Endpoint process and network telemetry |
| Winlogbeat | 8.19.13 | Windows Security and Sysmon event forwarding |
| Elasticsearch | 8.x | Event indexing and storage |
| Kibana | 8.x | SIEM detection rules and alert management |
| BloodHound CE | v9.0.0-rc4 | AD attack path analysis and graph visualization |
| SharpHound | Current at install | AD data collection for BloodHound |
| Impacket | Current | Kerberoasting, AS-REP Roasting, DCSync execution |
| Hashcat | Current | Offline hash cracking simulation |

---

## Domain Structure

| Account | Classification | Notes |
|---|---|---|
| d.reyes, m.santos, e.miller, l.kim | Standard user | Unprivileged domain accounts |
| a.brooks, p.nair, m.lee, s.alvarez | Standard user | Unprivileged domain accounts |
| h.temp | Weak foothold | Weak credential — initial access vector for attack chain |
| o.intern | Weak foothold | Weak credential — initial access vector for attack chain |
| r.hayes | Domain Admin | Primary privileged target; Protected Users member post-hardening |
| o.grant | IT Admin | Secondary privileged account |
| svc-sql-report | Service account | SPN registered (MSSQLSvc/win-dc01.soc.local:1433); Kerberoast target |
| svc-backup-ops | Service account | DoesNotRequirePreAuth initially set True; AS-REP Roast target |

---

## Attack Chain

| Technique | Tool | MITRE Sub-Technique | Key Event | Outcome |
|---:|---|---|---|---|
| AD Reconnaissance | SharpHound / BloodHound CE | T1087.002 | LDAP burst / Event 1644 | Complete |
| Kerberoasting | Impacket GetUserSPNs | T1558.003 | 4769 (etype 0x17) | Complete |
| AS-REP Roasting | Impacket GetNPUsers | T1558.004 | 4768 (no pre-auth) | Complete |
| LSASS Credential Dumping | ProcDump / Mimikatz | T1003.001 | Sysmon Event 10 | Blocked by Defender PPL |
| DCSync | Impacket secretsdump | T1003.006 | 4662 (replication GUIDs) | Complete |

---

## Telemetry

| Event ID | Technique | Volume |
|---|---|---|
| 4769 | Kerberoasting (RC4 TGS requests) | 237 events |
| 4768 | AS-REP Roasting (no pre-auth requests) | 98 events |
| 4662 | DCSync (directory replication access) | 103 events |

An absence of Event 4769 data early in Phase 5 led to the identification of a critical telemetry gap: Winlogbeat had not been deployed to WIN-DC01, leaving all domain controller authentication events unshipped to the SIEM. Domain controllers generate the Kerberos events essential to detecting both Kerberoasting (4769) and AS-REP Roasting (4768) — neither technique produces these events on the endpoint. The gap was identified, corrected, and documented as a finding. In environments relying on a generic SIEM rather than a dedicated identity threat detection product, DC telemetry coverage is a prerequisite for Kerberos-based detection.

---

## Detection Rules

| Rule | Signal | Severity | MITRE | Validation |
|---:|---|---|---|---|
| 01 — Kerberoasting RC4 | Event 4769, TicketEncryptionType 0x17 | High | T1558.003 | Verified — 237 alerts |
| 02 — AS-REP Roasting | Event 4768, PreAuthType 0 | High | T1558.004 | Verified — 98 alerts |
| 03 — DCSync | Event 4662, DS-Replication GUIDs | Critical | T1003.006 | Verified — 103 alerts |
| 04 — SharpHound LDAP Burst | Event 4662 volume threshold | High | T1087.002 | Verified |
| 05 — LSASS Process Access | Sysmon Event 10, lsass.exe target | High | T1003.001 | Verified — PPL blocked dump |
| 06 — Lateral Movement NTLM | Event 4624, LogonType 3, NTLM | Medium | T1550.002 | Verified |

Full rule documentation with KQL queries, logic, prerequisites, test methods, and false positive analysis: [`rules/kql/`](rules/kql/) | Sigma format: [`rules/sigma/`](rules/sigma/)

During detection engineering, a rule targeting Event 4672 (Special Logon) was found to generate excessive alerts on the domain controller due to the high volume of privileged logons by system processes. The rule was not included in the final rule set. The recommended tuning approach — excluding SYSTEM, LOCAL SERVICE, NETWORK SERVICE, and known administrative accounts — is documented in [`rules/kql/`](rules/kql/).

---

## Hardening Controls (Phase 10)

Each control was selected to directly address a specific weakness exploited during the attack chain.

| Control | Exploited Weakness Addressed | Validated |
|---|---|---|
| Protected Users group — r.hayes, Administrator | NTLM authentication and credential caching for privileged accounts | Yes |
| AES-only Kerberos enforcement — svc-sql-report | RC4 TGS requests that enabled offline hash cracking (T1558.003) | Yes |
| Kerberos PreAuth re-enabled — svc-backup-ops | AS-REP returned without pre-authentication challenge (T1558.004) | Yes |
| Password policy — MinLength 16, Complexity, Lockout 5 | Weak foothold credentials that provided initial access | Yes |
| Directory Service Access auditing | Event 4662 generation required for DCSync and LDAP recon detection | Yes |

A post-hardening SharpHound collection (315 objects enumerated) was run to generate data for BloodHound before-and-after comparison. That comparison is pending and will be added to [`evidence/EVIDENCE_INDEX.md`](evidence/EVIDENCE_INDEX.md) upon completion.

---

## Selected Findings

**Telemetry blind spot on the domain controller.** Kerberoasting and AS-REP Roasting generate their primary Windows Security events (4769 and 4768) exclusively on the domain controller. When the DC lacks a log-forwarding agent, neither technique produces any SIEM-visible evidence regardless of the quality of detection rules authored against the winlogbeat-* index. The finding underscores that detection engineering and telemetry pipeline validation are inseparable disciplines.

**PPL as a detection enabler.** The LSASS credential dump was blocked by Windows Defender Protected Process Light before any credential material was extracted. Sysmon Event 10 recorded the process access attempt independently of the dump outcome. The result is a case in which a functioning endpoint control and a functioning SIEM detection both fired on the same event — the control prevented harm and the SIEM captured evidence of the attempt.

**DCSync detection requires specific replication GUIDs.** Event 4662 is generated for routine directory operations as well as for DCSync. Filtering on the DS-Replication-Get-Changes-All GUID (`1131f6ad-9c07-11d1-f79f-00c04fc2dcd2`) and excluding machine accounts (`SubjectUserName` ending in `$`) isolates non-DC sources exercising replication rights. Without that specificity, the rule produces an unworkable alert volume.

**Attack-to-mitigation traceability.** The hardening controls applied in Phase 10 were selected in direct correspondence with the techniques executed in Phases 5–7. AES-only Kerberos enforcement renders the Phase 5 attack ineffective. PreAuth re-enablement renders the Phase 6 attack ineffective. That one-to-one correspondence between identified weakness and applied control is the measurable outcome of the project.

---

## Production Considerations

Several design decisions appropriate for a controlled research environment would require revision in a production context. Certificate verification between Logstash and Elasticsearch was relaxed during initial setup and should be enforced in any external deployment. Beat agents authenticate using the elastic superuser rather than a least-privilege API key, which is inconsistent with production credential hygiene. The domain operates without Microsoft Defender for Identity, without LAPS, and without a tiered administration model — each of which would materially reduce the attack surface in a production environment. These limitations are addressed in detail in [CURRENT_LIMITATIONS.md](CURRENT_LIMITATIONS.md).

---

## Repository Documents

| Document | Description |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | Network topology, VM specifications, domain design, telemetry flow, and design rationale |
| [DEPLOYMENT.md](DEPLOYMENT.md) | Phase-by-phase build reference — domain controller, endpoints, attack chain, detection, hardening |
| [CURRENT_LIMITATIONS.md](CURRENT_LIMITATIONS.md) | Scope boundaries, known gaps, and planned improvements |
| [CHANGELOG.md](CHANGELOG.md) | Dated build history by phase |
| [evidence/EVIDENCE_INDEX.md](evidence/EVIDENCE_INDEX.md) | Screenshot inventory mapped to phases and detection rules |

---

## References

Bhatt, Sherri, and others. *Applied Incident Response*. Wiley, 2020.

Caliber, John, and Rebekah Brown. *Intelligence-Driven Incident Response*, 2nd ed. O'Reilly Media, 2023.

Engebretson, Patrick. *Advanced Penetration Testing*. Wiley, 2014.

MITRE Corporation. "MITRE ATT&CK Enterprise Matrix." *MITRE ATT&CK*, 2024, attack.mitre.org.

Peacock, Robby, and others. *Adversary Emulation with MITRE ATT&CK*. No Starch Press, 2023.

SANS Institute. *SEC504: Hacker Tools, Techniques, and Incident Handling*. SANS Institute, 2025.

---

Built by John Medina | GitHub: [m549n1ja](https://github.com/m549n1ja)
