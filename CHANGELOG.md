# Changelog — active-directory-attack-defense

---

## 2026-05-08

### Phase 10 — AD Hardening (in progress)
- Applied Protected Users group to r.hayes and Administrator
- Enforced AES128/AES256 only on svc-sql-report (RC4 removed — closes Kerberoasting vector)
- Re-enabled Kerberos PreAuth on svc-backup-ops (closes AS-REP Roasting vector)
- Strengthened domain password policy: MinLength 16, Complexity enabled, LockoutThreshold 5
- Enabled Directory Service Auditing: DS Access + DS Changes (Success and Failure)
- Executed post-hardening SharpHound collection: 315 objects, new ZIP generated
- Screenshots captured for all hardening actions

### Phase 9 — Detection Engineering (complete)
- Created 6 custom Elastic Security KQL detection rules
- Validated all rules against live telemetry in Kibana
- Identified false positive in broad Event 4672 rule — documented with tuning recommendation
- Exported all rules as NDJSON: kibana-exports/ad-detection-rules.ndjson
- Rule 1: Kerberoasting RC4 (Event 4769, etype 0x17)
- Rule 2: AS-REP Roasting (Event 4768, no pre-auth)
- Rule 3: DCSync (Event 4662, replication GUIDs)
- Rule 4: SharpHound LDAP Burst (high LDAP query volume)
- Rule 5: LSASS Process Access (Sysmon Event 10)
- Rule 6: Lateral Movement NTLM (Event 4624 LogonType 3)

---

## 2026-05-07 / 2026-05-08

### Phase 7 — DCSync Attack (complete)
- Executed impacket-secretsdump from Kali-Attacker
- Event 4662 confirmed in ELK: 103 events — DS-Replication-Get-Changes GUIDs visible
- Hashes captured (redacted before GitHub commit)
- VMware snapshot: phase8-dcsync-complete

### Phase 6 — AS-REP Roasting + LSASS (complete)
- Executed impacket-GetNPUsers against svc-backup-ops
- Event 4768 confirmed in ELK: 98 events
- VMware snapshot: phase6-asrep-roasting-complete
- LSASS dump attempted — blocked by Windows Defender PPL
- Sysmon Event 10 captured; documented as defensive control validation

### Phase 5 — Kerberoasting (complete)
- Executed impacket-GetUserSPNs with h.temp credentials against soc.local
- Kerberoast hash captured for svc-sql-report (SPN: MSSQLSvc/win-dc01.soc.local:1433)
- Event 4769 confirmed in ELK: 237 events
- **Critical finding:** Event 4769 initially invisible — WIN-DC01 lacked Winlogbeat
- Installed Winlogbeat on WIN-DC01; telemetry gap resolved
- VMware snapshot: phase5-kerberoasting-detected

---

## 2026-05-06 / 2026-05-07

### Phase 4 — BloodHound Reconnaissance (complete)
- BloodHound CE v9.0.0-rc4 launched and authenticated on Kali
- SharpHound downloaded to WIN10-ADCLIENT under C:\Tools\SharpHound
- Defender exclusion added for C:\Tools\SharpHound
- SharpHound collected from WIN10-ADCLIENT as SOC\r.hayes
- Output ZIP: 20260506050050_BloodHound.zip
- ZIP transferred to Kali via SCP; ingested into BloodHound CE
- Attack path to Domain Admin confirmed via r.hayes
- svc-sql-report Kerberoast target confirmed in BloodHound
- VMware snapshot: phase4-bloodhound-recon-complete

### Phase 3 — Kali Attack Machine (complete)
- Kali Linux VM created; username kali_hacker
- Static IP configured: 192.168.10.20
- BloodHound CE, Impacket, Hashcat validated
- Connectivity to WIN-DC01 and ELK-SIEM confirmed
- VMware snapshot: phase3-kali-tools-ready
- Troubleshooting: DHCP/static dual-IP conflict resolved via nmcli

---

## 2026-05-02 / 2026-05-05

### Phase 2 — Windows 10 AD Client (complete)
- WIN10-ADCLIENT created on Ryzen 9 host
- Static IP: 192.168.10.161; DNS: 192.168.10.160 (DC)
- Domain joined: soc.local
- Sysmon64 installed with SwiftOnSecurity config
- Winlogbeat 8.19.13 installed and shipping to Logstash 192.168.10.100:5044
- winlogbeat-* indices confirmed in ELK
- VMware snapshot: phase2-ad-client-domain-joined-telemetry-active
- Troubleshooting: domain join failed on first attempt (DHCP DNS pointed to gateway, not DC); static IP and DNS corrected

---

## 2026-04-30

### Phase 1 — Domain Controller (complete)
- WIN-DC01 built on Ryzen 9 host: Windows Server 2022
- Static IP: 192.168.10.160
- AD DS and DNS roles installed; domain promoted: soc.local
- Users created: d.reyes, m.santos, e.miller, l.kim, a.brooks, p.nair, m.lee, s.alvarez
- Weak accounts: h.temp (Password123!), o.intern (Welcome1!)
- Domain Admins: r.hayes, o.grant
- Service accounts: svc-sql-report (SPN registered), svc-backup-ops (PreAuth disabled)
- VMware snapshot: phase1-dc-configured
- Troubleshooting: VMware floppy conflict fixed; IP conflict with 192.168.10.160 resolved

### Phase 0 — Repository Setup (complete)
- Git repository initialized: active-directory-attack-defense
- Folder structure created: configs/, rules/kql/, rules/sigma/, evidence/screenshots/, scripts/attack/, scripts/detection/, reports/
- Screenshot folder created: C:\Users\jamed\CyberLab\Screenshots\lab2-active-directory-attack-defense\
