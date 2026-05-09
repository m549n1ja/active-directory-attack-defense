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
 soc.local DC  domain joined   Attack tools   Elasticsearch
 AD DS + DNS   Sysmon64        BloodHound CE  Logstash:5044
 Winlogbeat    Winlogbeat ─────────────────► Kibana:5601
      │              │
      └──────────────┘
      Both ship to Logstash on ELK-SIEM
                   │                              │
                   └──────────────────────────────┘
              Ryzen 9 Desktop | 192.168.10.10
              VMware Workstation | 64 GB RAM
```

---

## VM Specifications

| VM | OS | IP | vCPU | RAM | Role |
|---|---|---|---:|---:|---|
| WIN-DC01 | Windows Server 2022 | 192.168.10.160 | 2 | 4 GB | Domain Controller |
| WIN10-ADCLIENT | Windows 10 Pro | 192.168.10.161 | 2 | 4 GB | Domain workstation |
| Kali-Attacker | Kali Linux | 192.168.10.20 | 2 | 4 GB | Attack platform |
| ELK-SIEM | Ubuntu Server 24.04 | 192.168.10.100 | 4 | 16 GB | SIEM (Lab 1, reused) |

All VMs run on VMware Workstation with bridged networking. Bridged mode is intentional — it places all VMs on the same physical LAN segment as the OPNsense gateway, ensuring realistic network topology without NAT obscuring traffic.

---

## Domain Design

| Item | Value |
|---|---|
| Domain name | soc.local |
| NetBIOS name | SOC |
| Domain Controller | WIN-DC01 (192.168.10.160) |
| Forest / Domain functional level | Windows Server 2016 |
| DNS | WIN-DC01 serves DNS for soc.local; all VMs point to 192.168.10.160 as primary DNS |

---

## Active Directory User Structure

| Account | Type | Group Membership | Notes |
|---|---|---|---|
| d.reyes | Standard user | Domain Users | Normal employee |
| m.santos | Standard user | Domain Users | Normal employee |
| e.miller | Standard user | Domain Users | Normal employee |
| l.kim | Standard user | Domain Users | Normal employee |
| a.brooks | Standard user | Domain Users | Normal employee |
| p.nair | Standard user | Domain Users | Normal employee |
| m.lee | Standard user | Domain Users | Normal employee |
| s.alvarez | Standard user | Domain Users | Normal employee |
| h.temp | Weak foothold | Domain Users | Password123! — initial access foothold |
| o.intern | Weak foothold | Domain Users | Welcome1! — initial access foothold |
| r.hayes | Domain Admin | Domain Admins | Primary privileged target; added to Protected Users in Phase 10 |
| o.grant | IT Admin | Domain Admins | Secondary admin |
| svc-sql-report | Service account | Domain Users | SPN: MSSQLSvc/win-dc01.soc.local:1433 — Kerberoast target |
| svc-backup-ops | Service account | Domain Users | DoesNotRequirePreAuth initially True — AS-REP Roast target |

---

## Intentional Misconfigurations (Lab Design)

The following misconfigurations were created deliberately to simulate a realistic vulnerable AD environment:

| Misconfiguration | Account | MITRE Technique | Phase Exploited |
|---|---|---|---|
| Registered SPN on service account | svc-sql-report | T1558.003 — Kerberoasting | Phase 5 |
| PreAuth disabled | svc-backup-ops | T1558.004 — AS-REP Roasting | Phase 6 |
| Weak password on foothold account | h.temp, o.intern | T1078 — Valid Accounts | Phases 5, 6, 7 |
| Domain Admin without Protected Users | r.hayes | T1003 — Credential Dumping | Phase 7 |
| RC4 encryption allowed on SPN account | svc-sql-report | T1558.003 — Kerberoasting (RC4) | Phase 5 |

All misconfigurations were remediated in Phase 10 (AD Hardening).

---

## Telemetry Architecture

### Windows Endpoint → ELK

```text
WIN10-ADCLIENT (192.168.10.161)
    │
    ├── Sysmon64 (SwiftOnSecurity config)
    │     └── writes to: Microsoft-Windows-Sysmon/Operational event channel
    │
    └── Winlogbeat 8.19.13
          ├── collects: Windows Security (Security event channel)
          ├── collects: Sysmon events (Microsoft-Windows-Sysmon/Operational)
          └── ships to: Logstash 192.168.10.100:5044
```

### Domain Controller → ELK

```text
WIN-DC01 (192.168.10.160)
    │
    └── Winlogbeat 8.19.13
          ├── collects: Windows Security (Security event channel)
          │     └── includes DC-only events: 4769, 4768, 4662, 4672, 4724
          └── ships to: Logstash 192.168.10.100:5044

Note: Winlogbeat was not installed on WIN-DC01 until Phase 5.
      This caused a telemetry blind spot for all DC-side Kerberos events.
      Documented as a critical detection engineering finding.
```

### ELK Processing

```text
Logstash (192.168.10.100:5044)
    │
    ├── input: beats (Winlogbeat from both WIN-DC01 and WIN10-ADCLIENT)
    ├── filter: tag by agent type (winlogbeat), add lab metadata
    └── output: Elasticsearch (https://localhost:9200)
                   └── index: winlogbeat-*
                              └── Kibana Security reads: winlogbeat-* data view
```

---

## Key Events by Technique

| Technique | MITRE | Key Event ID | Source | Notes |
|---|---|---|---|---|
| BloodHound Recon | T1087.002 | LDAP burst / Event 1644 | WIN-DC01 | Event 1644 requires registry key to enable LDAP diagnostic logging |
| Kerberoasting | T1558.003 | 4769 | WIN-DC01 | Filter on ticket_encryption_type = 0x17 (RC4) |
| AS-REP Roasting | T1558.004 | 4768 | WIN-DC01 | Filter on failure code 0x0 with pre-auth type 0 |
| LSASS Dumping (blocked) | T1003.001 | Sysmon Event 10 | WIN10-ADCLIENT | TargetImage: lsass.exe; Defender PPL blocked the dump |
| DCSync | T1003.006 | 4662 | WIN-DC01 | Properties: DS-Replication-Get-Changes GUIDs |
| Lateral Movement | T1550.002 | 4624 LogonType 3 | WIN-DC01 / ADCLIENT | Network logon via NTLM |

---

## Attack Flow

```text
Kali-Attacker (192.168.10.20)
    │
    ├── Phase 4: SharpHound.exe runs on WIN10-ADCLIENT (domain user context)
    │     └── LDAP queries → WIN-DC01 → BloodHound CE on Kali maps attack paths
    │
    ├── Phase 5: impacket-GetUserSPNs
    │     └── h.temp credentials → request TGS for svc-sql-report → capture RC4 hash
    │         └── Event 4769 generated on WIN-DC01
    │
    ├── Phase 6: impacket-GetNPUsers
    │     └── svc-backup-ops (no pre-auth) → capture AS-REP hash
    │         └── Event 4768 generated on WIN-DC01
    │
    ├── Phase 6: ProcDump/Mimikatz → LSASS
    │     └── Defender PPL blocks → Sysmon Event 10 captured, dump fails
    │
    └── Phase 7: impacket-secretsdump (DCSync)
          └── replicate NTDS.dit hashes from WIN-DC01
              └── Event 4662 generated on WIN-DC01 (replication GUIDs)
```

---

## Hardening Architecture (Phase 10)

```text
Before hardening:
    svc-sql-report  →  SPN registered + RC4 allowed  →  Kerberoast target
    svc-backup-ops  →  DoesNotRequirePreAuth = True   →  AS-REP Roast target
    r.hayes         →  Domain Admin, no PPL           →  DCSync / pass-the-hash target

After hardening:
    svc-sql-report  →  AES128 + AES256 only           →  RC4 Kerberoasting fails
    svc-backup-ops  →  DoesNotRequirePreAuth = False   →  AS-REP Roasting fails
    r.hayes         →  Protected Users group           →  NTLM auth disabled, no RC4, no caching
    Administrator   →  Protected Users group           →  Same protections applied
    Domain policy   →  MinLength 16, Lockout 5        →  Password spray resistance
    DS Auditing     →  DS Access + DS Changes enabled  →  DCSync events now audited
```

---

## Design Decisions

### Why bridged networking instead of NAT?
VMware NAT would isolate VM traffic from the physical LAN and give each VM a separate NAT'd IP. Bridged networking places all VMs on the real 192.168.10.0/24 segment, which is how they would exist in a real environment. This also means all traffic flows through OPNsense, keeping the network model realistic and allowing the SIEM to see actual source IPs.

### Why intentional misconfigurations instead of a default installation?
A default Active Directory installation with no SPNs and no PreAuth-disabled accounts is not attackable using Kerberoasting or AS-REP Roasting. The misconfigurations were created deliberately to simulate the kind of legacy service accounts and configuration debt found in real enterprise environments.

### Why reuse the existing ELK-SIEM from Lab 1?
The ELK stack from Lab 1 (homelab-elk-soc) was already running and validated. Reusing it demonstrates that a single SIEM can ingest telemetry from multiple environments — which is realistic for an enterprise SOC. The winlogbeat-* index pattern covers both the Lab 1 Windows endpoint and both Lab 2 Windows machines.

### Why document the telemetry gap as a finding instead of just fixing it quietly?
The Winlogbeat gap on WIN-DC01 was not a setup error — it was a deliberate documentation decision. In a real SOC, identifying and closing telemetry blind spots is a primary job function. Discovering that Event 4769 was not reaching the SIEM, diagnosing the cause (missing Beat agent on the DC), and validating the fix (events appearing in Kibana after installation) is a more valuable portfolio story than a lab where everything worked perfectly from the start.
