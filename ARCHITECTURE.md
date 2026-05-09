# Architecture — Active Directory Attack & Defense Lab

---

## Network Topology

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
 soc.local DC  Domain joined   Attack tools   Elasticsearch
 AD DS + DNS   Sysmon64        BloodHound CE  Logstash:5044
 Winlogbeat    Winlogbeat ─────────────────► Kibana:5601
      │              │
      └──────────────┘
      Both forward to Logstash on ELK-SIEM
                   │                              │
                   └──────────────────────────────┘
              Ryzen 9 Desktop | 192.168.10.10
              VMware Workstation | 64 GB RAM
```

All four virtual machines operate on VMware Workstation in bridged network mode, placing each on the 192.168.10.0/24 segment alongside the physical host. Bridged networking was selected rather than NAT to preserve realistic source IP addressing in telemetry — NAT would mask the Kali attacker's address behind the host IP, complicating event correlation in Kibana. All traffic transits OPNsense at 192.168.10.1.

---

## Virtual Machine Specifications

| VM | Operating System | IP Address | vCPU | RAM | Role |
|---|---|---|---:|---:|---|
| WIN-DC01 | Windows Server 2022 | 192.168.10.160 | 2 | 4 GB | Domain Controller |
| WIN10-ADCLIENT | Windows 10 Pro | 192.168.10.161 | 2 | 4 GB | Domain workstation |
| Kali-Attacker | Kali Linux | 192.168.10.20 | 2 | 4 GB | Adversary emulation platform |
| ELK-SIEM | Ubuntu Server 24.04 | 192.168.10.100 | 4 | 16 GB | SIEM (shared with Lab 1) |

---

## Domain Design

The soc.local domain was configured as a single-forest, single-domain environment with WIN-DC01 operating as the sole domain controller. The domain name soc.local and NetBIOS name SOC were selected to reflect a plausible internal naming convention without conflict with any external namespace. All virtual machines are configured with 192.168.10.160 as their primary DNS server to ensure Kerberos and domain join operations resolve correctly against the domain controller. The forest and domain functional levels are set to Windows Server 2016.

| Item | Value |
|---|---|
| Domain name | soc.local |
| NetBIOS name | SOC |
| Domain Controller | WIN-DC01 |
| Forest/Domain functional level | Windows Server 2016 |
| DNS authority | WIN-DC01 (192.168.10.160) |

---

## Active Directory User Structure

The account population was designed to reflect a plausible small organization while providing the specific conditions required by each attack technique. Two categories of accounts carry intentional misconfigurations: service accounts provisioned with the attributes that make Kerberoasting and AS-REP Roasting possible, and low-privilege foothold accounts with weak credentials to simulate the initial access phase.

| Account | Classification | Group Membership | Configuration Notes |
|---|---|---|---|
| d.reyes, m.santos, e.miller, l.kim | Standard user | Domain Users | No special attributes |
| a.brooks, p.nair, m.lee, s.alvarez | Standard user | Domain Users | No special attributes |
| h.temp | Weak foothold | Domain Users | Weak credential — primary initial access account |
| o.intern | Weak foothold | Domain Users | Weak credential — secondary initial access account |
| r.hayes | Domain Admin | Domain Admins | Primary privileged target; added to Protected Users in Phase 10 |
| o.grant | IT Admin | Domain Admins | Secondary privileged account |
| svc-sql-report | Service account | Domain Users | SPN registered: MSSQLSvc/win-dc01.soc.local:1433; RC4 initially permitted |
| svc-backup-ops | Service account | Domain Users | DoesNotRequirePreAuth initially set to True |

---

## Intentional Misconfigurations

The following misconfigurations were introduced deliberately to create conditions under which the targeted attack techniques would succeed. Each was remediated in Phase 10.

| Misconfiguration | Affected Account | MITRE Sub-Technique | Exploited In | Remediation |
|---|---|---|---|---|
| Registered SPN on service account | svc-sql-report | T1558.003 | Phase 5 | AES-only Kerberos enforced |
| PreAuth disabled | svc-backup-ops | T1558.004 | Phase 6 | DoesNotRequirePreAuth set to False |
| Weak password on foothold accounts | h.temp, o.intern | T1078 | Phases 5, 6, 7 | Password policy strengthened |
| Domain Admin without Protected Users membership | r.hayes | T1003 | Phase 7 | Added to Protected Users group |
| RC4 encryption permitted on SPN account | svc-sql-report | T1558.003 | Phase 5 | msDS-SupportedEncryptionTypes restricted to AES128/AES256 |

---

## Telemetry Architecture

### Domain Controller Event Flow

WIN-DC01 is the exclusive source of the Kerberos-related Windows Security events critical to this project. Events 4769, 4768, and 4662 are generated by the Kerberos Distribution Center and the directory service audit subsystem on the domain controller and are not replicated to endpoints. Consequently, a Winlogbeat agent on WIN10-ADCLIENT alone is insufficient for detection of Kerberoasting, AS-REP Roasting, or DCSync. This constraint was identified as a gap during Phase 5 and resolved by deploying Winlogbeat on WIN-DC01.

```text
WIN-DC01 (192.168.10.160)
    │
    └── Winlogbeat 8.19.13
          ├── Windows Security event channel
          │     Events: 4769, 4768, 4762, 4672, 4720, 4740, 4624, 4625
          └── Ships to: Logstash 192.168.10.100:5044
```

### Domain Workstation Event Flow

WIN10-ADCLIENT provides endpoint-level telemetry not available from the domain controller, including Sysmon process and network events that underpin the LSASS access detection.

```text
WIN10-ADCLIENT (192.168.10.161)
    │
    ├── Sysmon64 (SwiftOnSecurity configuration)
    │     Event 10 — ProcessAccess (LSASS access detection)
    │     Event 1  — Process creation
    │     Event 3  — Network connection
    │
    └── Winlogbeat 8.19.13
          ├── Windows Security event channel
          ├── Microsoft-Windows-Sysmon/Operational
          ├── Microsoft-Windows-PowerShell/Operational
          └── Ships to: Logstash 192.168.10.100:5044
```

### ELK Processing Pipeline

```text
Logstash (192.168.10.100:5044)
    │
    ├── input: beats (Winlogbeat from WIN-DC01 and WIN10-ADCLIENT)
    ├── filter: agent type tagging, lab metadata fields
    └── output: Elasticsearch (https://localhost:9200)
                   index pattern: winlogbeat-*
                              ↓
                   Kibana Security — winlogbeat-* data view
```

---

## Event Reference by Technique

| Technique | MITRE Sub-Technique | Event ID | Generating Source | Filter Conditions |
|---|---|---|---|---|
| BloodHound Reconnaissance | T1087.002 | 4662, Event 1644 | WIN-DC01 | High LDAP query volume; domainDNS object type |
| Kerberoasting | T1558.003 | 4769 | WIN-DC01 | TicketEncryptionType = 0x17 (RC4) |
| AS-REP Roasting | T1558.004 | 4768 | WIN-DC01 | PreAuthType = 0; Status = 0x0 |
| LSASS Memory Access | T1003.001 | Sysmon Event 10 | WIN10-ADCLIENT | TargetImage = lsass.exe; high GrantedAccess mask |
| DCSync | T1003.006 | 4662 | WIN-DC01 | DS-Replication-Get-Changes-All GUID present; SubjectUserName not machine account |
| NTLM Lateral Movement | T1550.002 | 4624 | WIN-DC01 / ADCLIENT | LogonType = 3; AuthenticationPackageName = NTLM |

---

## Attack Sequence

The following diagram traces the logical flow of the attack chain as executed against the lab environment.

```text
Kali-Attacker (192.168.10.20)
    │
    ├── Phase 4: SharpHound.exe on WIN10-ADCLIENT (domain user context: SOC\r.hayes)
    │     LDAP enumeration → WIN-DC01 → BloodHound CE maps attack paths on Kali
    │
    ├── Phase 5: impacket-GetUserSPNs
    │     h.temp credentials → TGS request for svc-sql-report → RC4 hash extracted
    │     Event 4769 (etype 0x17) generated on WIN-DC01
    │
    ├── Phase 6a: impacket-GetNPUsers
    │     No credentials required → AS-REP for svc-backup-ops (no pre-auth)
    │     Event 4768 (PreAuthType 0) generated on WIN-DC01
    │
    ├── Phase 6b: ProcDump / Mimikatz → lsass.exe
    │     Defender PPL denies handle → dump fails
    │     Sysmon Event 10 generated on WIN10-ADCLIENT
    │
    └── Phase 7: impacket-secretsdump (DCSync)
          Replication rights exercised by r.hayes account
          Event 4662 (DS-Replication-Get-Changes-All GUID) generated on WIN-DC01
```

---

## Hardening State Comparison

The table below documents the security state of the domain before and after Phase 10 hardening, with direct mapping to the attack techniques each change addresses.

| Control Point | Pre-Hardening State | Post-Hardening State | Technique Addressed |
|---|---|---|---|
| svc-sql-report encryption | RC4 permitted (etype 0x17 requests succeed) | AES128/AES256 only (RC4 rejected by KDC) | T1558.003 |
| svc-backup-ops PreAuth | DoesNotRequirePreAuth = True | DoesNotRequirePreAuth = False | T1558.004 |
| r.hayes group membership | Domain Admins only | Domain Admins + Protected Users | T1003, T1550.002 |
| Domain password policy | Default (MinLength 7) | MinLength 16, Complexity, Lockout 5 | T1078 |
| Directory Service auditing | Not configured | DS Access + DS Changes: Success and Failure | T1003.006, T1087.002 |

---

## Design Rationale

**Bridged networking over NAT.** VMware NAT assigns virtual machines private addresses that are masqueraded behind the host IP in all external traffic. Bridged mode places each VM directly on the physical LAN with its own IP address, preserving realistic source addressing in telemetry and ensuring OPNsense logs reflect actual VM-to-VM communication paths.

**Intentional misconfigurations as research conditions.** A freshly installed Active Directory domain with no SPNs and PreAuth enabled universally is not susceptible to Kerberoasting or AS-REP Roasting in their standard forms. The misconfigurations introduced simulate the configuration debt present in many production environments where service accounts have accumulated attributes over years without review. The project documents both the exploitation of those conditions and their remediation.

**Shared ELK infrastructure.** The ELK-SIEM at 192.168.10.100 was originally deployed as part of a separate homelab-elk-soc project. Reusing that infrastructure reflects a realistic architecture in which a single SIEM platform ingests telemetry from multiple environments. The winlogbeat-* index pattern captures events from both the original Lab 1 endpoints and both Lab 2 Windows machines without requiring a separate indexing configuration.

**Documenting the telemetry gap as a finding rather than correcting it silently.** The absence of Winlogbeat on WIN-DC01 at the outset of Phase 5 created a condition in which Kerberoasting produced no SIEM-visible evidence. Correcting it without documentation would obscure a class of operational failure — incomplete telemetry pipeline coverage — that occurs regularly in production SOC environments. The discovery and resolution of the gap, with before-and-after evidence, constitutes a more instructive record than a lab in which all telemetry was present from the start.
