# Evidence Index — active-directory-attack-defense

All screenshots are saved to `evidence/screenshots/` and follow the naming convention:
`YYYYMMDD_ad-lab_description.png`

---

## Phase 0 — VMware Lab Setup

| Screenshot | Description | Notes |
|---|---|---|
| [Screenshot 2026-04-30 095908.png](screenshots/Screenshot%202026-04-30%20095908.png) | Initial VMware Workstation state | Pre-build baseline |
| [20260502_ad-lab_win-dc01-vm-settings.png](screenshots/20260502_ad-lab_win-dc01-vm-settings.png) | WIN-DC01 VM hardware configuration | — |
| [20260502_ad-lab_win-dc01-no-images-available.png](screenshots/20260502_ad-lab_win-dc01-no-images-available.png) | ISO library empty — pre-mount state | — |
| [20260502_ad-lab_iso-library-verified.png](screenshots/20260502_ad-lab_iso-library-verified.png) | Windows Server 2022 ISO added to library | — |
| [20260502_ad-lab_win-dc01-cdrom-server-iso-mounted.png](screenshots/20260502_ad-lab_win-dc01-cdrom-server-iso-mounted.png) | Server 2022 ISO mounted to WIN-DC01 CD-ROM | — |
| [20260502_ad-lab_win-dc01-floppy-autoinst-disabled.png](screenshots/20260502_ad-lab_win-dc01-floppy-autoinst-disabled.png) | VMware floppy autoinst.flp removed to prevent boot conflict | — |

---

## Phase 1 — Domain Controller Build

| Screenshot | Description | Related Rule |
|---|---|---|
| [20260502_ad-lab_win-dc01-server-manager.png](screenshots/20260502_ad-lab_win-dc01-server-manager.png) | Server Manager on WIN-DC01 post-install | — |
| [20260502_ad-lab_win-dc01-static-ip-duplicate.png](screenshots/20260502_ad-lab_win-dc01-static-ip-duplicate.png) | DC static IP conflicting with Ryzen host | — |
| [20260502_ad-lab_ryzen-host-ip-conflict-confirmed.png](screenshots/20260502_ad-lab_ryzen-host-ip-conflict-confirmed.png) | IP conflict confirmed on Ryzen host | — |
| [20260502_ad-lab_ryzen-host-static-ip-tentative.png](screenshots/20260502_ad-lab_ryzen-host-static-ip-tentative.png) | Ryzen host IP reconfiguration in progress | — |
| [20260502_ad-lab_ryzen-host-static-ip-restored.png](screenshots/20260502_ad-lab_ryzen-host-static-ip-restored.png) | Ryzen host static IP restored after conflict resolution | — |
| [20260502_ad-lab_win-dc01-static-ip-fixed.png](screenshots/20260502_ad-lab_win-dc01-static-ip-fixed.png) | WIN-DC01 static IP set to 192.168.10.160 | — |
| [20260502_ad-lab_win-dc01-ssh-working.png](screenshots/20260502_ad-lab_win-dc01-ssh-working.png) | SSH access to WIN-DC01 from Ryzen host | — |
| [20260502_ad-lab_win-dc01-ssh-working-confirmed.png](screenshots/20260502_ad-lab_win-dc01-ssh-working-confirmed.png) | SSH session confirmed stable | — |
| [20260502_ad-lab_win-dc01-ad-ds-installed.png](screenshots/20260502_ad-lab_win-dc01-ad-ds-installed.png) | AD DS role installation complete | — |
| [20260502_ad-lab_win-dc01-ad-ds-dns-installed.png](screenshots/20260502_ad-lab_win-dc01-ad-ds-dns-installed.png) | AD DS and DNS Server roles confirmed installed | — |
| [20260502_ad-lab_win-dc01-ad-domain-verified.png](screenshots/20260502_ad-lab_win-dc01-ad-domain-verified.png) | soc.local domain created and active | — |
| [20260502_ad-lab_win-dc01-domain-controller-verified.png](screenshots/20260502_ad-lab_win-dc01-domain-controller-verified.png) | WIN-DC01 confirmed as domain controller for soc.local | — |
| [20260502_ad-lab_soc-users-created.png](screenshots/20260502_ad-lab_soc-users-created.png) | SOC Users OU and domain user accounts created | Rules 01, 02 |
| [20260502_ad-lab_it-admins-created.png](screenshots/20260502_ad-lab_it-admins-created.png) | IT Admins group and r.hayes Domain Admin membership | Rule 03 |
| [20260502_ad-lab_service-accounts-vulnerable-config.png](screenshots/20260502_ad-lab_service-accounts-vulnerable-config.png) | svc-sql-report SPN + svc-backup-ops DoesNotRequirePreAuth configured | Rules 01, 02 |

---

## Phase 2 — AD Client Build

| Screenshot | Description | Related Rule |
|---|---|---|
| [20260502_ad-lab_win10-vm-settings.png](screenshots/20260502_ad-lab_win10-vm-settings.png) | WIN10-ADCLIENT VM hardware configuration | — |
| [20260502_ad-lab_win10-client-hostname-set.png](screenshots/20260502_ad-lab_win10-client-hostname-set.png) | WIN10-ADCLIENT hostname confirmed | — |
| [20260502_ad-lab_win10-client-dc-connectivity.png](screenshots/20260502_ad-lab_win10-client-dc-connectivity.png) | Client connectivity to DC at 192.168.10.160 | — |
| [20260502_ad-lab_domain-join-failure-dns-error.png](screenshots/20260502_ad-lab_domain-join-failure-dns-error.png) | Domain join failure — DNS pointed to gateway | — |
| [20260502_ad-lab_win10-client-dhcp-misconfiguration.png](screenshots/20260502_ad-lab_win10-client-dhcp-misconfiguration.png) | DHCP misconfiguration (DNS issue root cause) | — |
| [20260502_ad-lab_static-ip-config-attempt-invalid-state.png](screenshots/20260502_ad-lab_static-ip-config-attempt-invalid-state.png) | Static IP configuration blocked by adapter state | — |
| [20260502_ad-lab_static-ip-dns-corrected.png](screenshots/20260502_ad-lab_static-ip-dns-corrected.png) | Static IP set to 192.168.10.161, DNS pointed to DC | — |
| [20260502_ad-lab_sysmon-running.png](screenshots/20260502_ad-lab_sysmon-running.png) | Sysmon64 service running on WIN10-ADCLIENT | Rule 05 |
| [20260502_ad-lab_winlogbeat-config-test.png](screenshots/20260502_ad-lab_winlogbeat-config-test.png) | Winlogbeat configuration test — no errors | — |
| [20260502_ad-lab_winlogbeat-logstash-connection.png](screenshots/20260502_ad-lab_winlogbeat-logstash-connection.png) | Winlogbeat connected to Logstash at 192.168.10.100:5044 | — |
| [20260502_ad-lab_winlogbeat-running.png](screenshots/20260502_ad-lab_winlogbeat-running.png) | Winlogbeat service running on WIN10-ADCLIENT | — |
| [20260502_ad-lab_adclient-logs-in-elk.png](screenshots/20260502_ad-lab_adclient-logs-in-elk.png) | winlogbeat-* index showing client events in Kibana | — |

---

## Phase 3 — Kali Attacker Setup

| Screenshot | Description | Notes |
|---|---|---|
| [20260502_ad-lab_kali-vm-settings.png](screenshots/20260502_ad-lab_kali-vm-settings.png) | Kali-Attacker VM hardware configuration | — |
| [20260502_ad-lab_kali-display-manager-selection.png](screenshots/20260502_ad-lab_kali-display-manager-selection.png) | Kali display manager selection during install | — |
| [20260502_ad-lab_kali-ip-conflict-dhcp-and-static.png](screenshots/20260502_ad-lab_kali-ip-conflict-dhcp-and-static.png) | Dual-IP conflict — DHCP and static assigned simultaneously | — |
| [20260502_ad-lab_kali-static-ip-fixed.png](screenshots/20260502_ad-lab_kali-static-ip-fixed.png) | Static IP 192.168.10.20 confirmed on Kali | — |
| [20260502_ad-lab_kali-lab-connectivity.png](screenshots/20260502_ad-lab_kali-lab-connectivity.png) | Kali connectivity to DC (160), ELK (100), client (161) confirmed | — |
| [20260506_ad-lab_kali-bloodhound-tool-check.png](screenshots/20260506_ad-lab_kali-bloodhound-tool-check.png) | BloodHound CE, Impacket, and Hashcat validated on Kali | — |
| [20260506_ad-lab_neo4j-started.png](screenshots/20260506_ad-lab_neo4j-started.png) | Neo4j service started for BloodHound CE | — |

---

## Phase 4 — BloodHound Reconnaissance

| Screenshot | Description | Related Rule |
|---|---|---|
| [20260506_ad-lab_bloodhound-ce-login-troubleshoot.png](screenshots/20260506_ad-lab_bloodhound-ce-login-troubleshoot.png) | BloodHound CE login troubleshooting (initial credential issue) | — |
| [20260506_ad-lab_bloodhound-connected.png](screenshots/20260506_ad-lab_bloodhound-connected.png) | BloodHound CE connected and authenticated | Rule 04 |
| [20260506_ad-lab_bloodhound-dashboard-empty.png](screenshots/20260506_ad-lab_bloodhound-dashboard-empty.png) | BloodHound CE dashboard before data ingestion | Rule 04 |
| [20260506_ad-lab_sharphound-downloaded.png](screenshots/20260506_ad-lab_sharphound-downloaded.png) | SharpHound downloaded to WIN10-ADCLIENT | Rule 04 |
| [20260506_ad-lab_defender-blocked-sharphound.png](screenshots/20260506_ad-lab_defender-blocked-sharphound.png) | Windows Defender blocking SharpHound execution | — |
| [20260506_ad-lab_domain-user-login.png](screenshots/20260506_ad-lab_domain-user-login.png) | Domain user login attempt to WIN10-ADCLIENT | — |
| [20260506_ad-lab_domain-user-login-success.png](screenshots/20260506_ad-lab_domain-user-login-success.png) | Domain user login to WIN10-ADCLIENT confirmed | — |
| [20260506_ad-lab_sharphound-domain-user-context.png](screenshots/20260506_ad-lab_sharphound-domain-user-context.png) | SharpHound executed in domain user context | Rule 04 |
| [20260506_ad-lab_sharphound-collection-complete.png](screenshots/20260506_ad-lab_sharphound-collection-complete.png) | SharpHound full collection completed | Rule 04 |
| [20260506_ad-lab_sharphound-zip-generated.png](screenshots/20260506_ad-lab_sharphound-zip-generated.png) | SharpHound output ZIP generated on client | Rule 04 |
| [20260506_ad-lab_sharphound-zip-transferred.png](screenshots/20260506_ad-lab_sharphound-zip-transferred.png) | SharpHound ZIP transferred to Kali via SCP | Rule 04 |
| [20260507_ad-lab_bloodhound-domain-admin-user.png](screenshots/20260507_ad-lab_bloodhound-domain-admin-user.png) | r.hayes confirmed as Domain Admin in BloodHound graph | Rule 04 |
| [20260507_ad-lab_bloodhound-attack-path.png](screenshots/20260507_ad-lab_bloodhound-attack-path.png) | Attack path from o.intern to Domain Admin visualized | Rule 04 |
| [20260507_ad-lab_kerberoast-target-account.png](screenshots/20260507_ad-lab_kerberoast-target-account.png) | svc-sql-report SPN identified as Kerberoast target in BloodHound | Rule 01 |

---

## Phase 5 — Kerberoasting

| Screenshot | Description | Related Rule |
|---|---|---|
| [20260507_ad-lab_impacket-installed.png](screenshots/20260507_ad-lab_impacket-installed.png) | Impacket suite confirmed installed on Kali | Rule 01 |
| [20260507_ad-lab_kerberoast-hash-captured.png](screenshots/20260507_ad-lab_kerberoast-hash-captured.png) | impacket-GetUserSPNs capturing RC4 TGS hash for svc-sql-report | Rule 01 |
| [20260507_ad-lab_kerberoast-hash-file-verified.png](screenshots/20260507_ad-lab_kerberoast-hash-file-verified.png) | Captured hash written to file and verified | Rule 01 |
| [20260507_ad-lab_kali-resources-increased.png](screenshots/20260507_ad-lab_kali-resources-increased.png) | Kali VM resources increased for Hashcat workload | — |
| [20260507_ad-lab_kerberoast-hashcat-exhausted.png](screenshots/20260507_ad-lab_kerberoast-hashcat-exhausted.png) | Hashcat wordlist exhausted — password not cracked in lab | — |
| [20260507_ad-lab_kerberoast-event-4769-dc-local.png](screenshots/20260507_ad-lab_kerberoast-event-4769-dc-local.png) | Event 4769 visible in DC local event viewer (pre-Winlogbeat) | Rule 01 |
| [20260507_ad-lab_elk-no-4769-detection-gap.png](screenshots/20260507_ad-lab_elk-no-4769-detection-gap.png) | ELK showing no 4769 events — telemetry gap identified | Rule 01 |
| [20260507_ad-lab_win-dc01-winlogbeat-downloaded.png](screenshots/20260507_ad-lab_win-dc01-winlogbeat-downloaded.png) | Winlogbeat 8.x downloaded to WIN-DC01 | All DC rules |
| [20260507_ad-lab_winlogbeat-dc01-service-failed-first-attempt.png](screenshots/20260507_ad-lab_winlogbeat-dc01-service-failed-first-attempt.png) | Winlogbeat service failed to start on DC (YAML error) | — |
| [20260507_ad-lab_winlogbeat-dc01-yaml-error-line2.png](screenshots/20260507_ad-lab_winlogbeat-dc01-yaml-error-line2.png) | YAML parsing error at line 2 of winlogbeat.yml | — |
| [20260507_ad-lab_winlogbeat-dc01-yaml-error-repeat.png](screenshots/20260507_ad-lab_winlogbeat-dc01-yaml-error-repeat.png) | Repeated YAML error during configuration correction | — |
| [20260507_ad-lab_winlogbeat-dc01-test-run-success.png](screenshots/20260507_ad-lab_winlogbeat-dc01-test-run-success.png) | Winlogbeat configuration test passing on DC | All DC rules |
| [20260507_ad-lab_winlogbeat-dc01-running.png](screenshots/20260507_ad-lab_winlogbeat-dc01-running.png) | Winlogbeat service running on WIN-DC01 | All DC rules |
| [20260507_ad-lab_event4769-confirmed-elk.png](screenshots/20260507_ad-lab_event4769-confirmed-elk.png) | Event 4769 with TicketEncryptionType 0x17 in Kibana | Rule 01 |
| [20260507_ad-lab_event4769-confirmed-elk_2.png](screenshots/20260507_ad-lab_event4769-confirmed-elk_2.png) | Event 4769 detail view — RC4 encryption confirmed | Rule 01 |

---

## Phase 6 — AS-REP Roasting + LSASS Access

| Screenshot | Description | Related Rule |
|---|---|---|
| [20260507_ad-lab_asrep-hash-captured.png](screenshots/20260507_ad-lab_asrep-hash-captured.png) | impacket-GetNPUsers capturing AS-REP hash for svc-backup-ops | Rule 02 |
| [20260507_ad-lab_event4768-asrep-confirmed-elk.png](screenshots/20260507_ad-lab_event4768-asrep-confirmed-elk.png) | Event 4768 with PreAuthType 0 in Kibana | Rule 02 |
| [20260507_ad-lab_lsass-defender-alert.png](screenshots/20260507_ad-lab_lsass-defender-alert.png) | Windows Defender alert on LSASS access attempt | Rule 05 |
| [20260507_ad-lab_lsass-all-methods-blocked.png](screenshots/20260507_ad-lab_lsass-all-methods-blocked.png) | ProcDump and Mimikatz blocked by Defender PPL | Rule 05 |

---

## Phase 7 — DCSync

| Screenshot | Description | Related Rule |
|---|---|---|
| [20260507_ad-lab_dcsync-all-hashes-dumped.png](screenshots/20260507_ad-lab_dcsync-all-hashes-dumped.png) | impacket-secretsdump replication output — hashes redacted | Rule 03 |
| [20260507_ad-lab_dcsync-event4662-confirmed-elk.png](screenshots/20260507_ad-lab_dcsync-event4662-confirmed-elk.png) | Event 4662 with DS-Replication GUIDs in Kibana | Rule 03 |

---

## Phase 9 — Detection Engineering

| Screenshot | Description | Related Rule |
|---|---|---|
| [20260507_ad-lab_rule-kerberoasting-kibana-created.png](screenshots/20260507_ad-lab_rule-kerberoasting-kibana-created.png) | Kerberoasting detection rule created in Kibana Security | Rule 01 |
| [20260507_ad-lab_rule-kerberoasting-alert-fired.png](screenshots/20260507_ad-lab_rule-kerberoasting-alert-fired.png) | Kerberoasting rule alert firing in Kibana Security | Rule 01 |
| [20260508_ad-lab_rule-asrep-kibana-created.png](screenshots/20260508_ad-lab_rule-asrep-kibana-created.png) | AS-REP Roasting detection rule created in Kibana Security | Rule 02 |
| [20260508_ad-lab_rule-dcsync-kibana-created.png](screenshots/20260508_ad-lab_rule-dcsync-kibana-created.png) | DCSync detection rule created in Kibana Security | Rule 03 |
| [20260508_ad-lab_rule-sharphound-kibana-created.png](screenshots/20260508_ad-lab_rule-sharphound-kibana-created.png) | SharpHound LDAP Burst detection rule created in Kibana Security | Rule 04 |
| [20260508_ad-lab_rule-lsass-ppl-kibana-created.png](screenshots/20260508_ad-lab_rule-lsass-ppl-kibana-created.png) | LSASS Process Access detection rule created in Kibana Security | Rule 05 |
| [20260508_ad-lab_rule-lateral-movement-kibana-created.png](screenshots/20260508_ad-lab_rule-lateral-movement-kibana-created.png) | Lateral Movement NTLM detection rule created in Kibana Security | Rule 06 |

---

## Phase 10 — AD Hardening

| Screenshot | Description | Related Control |
|---|---|---|
| [20260508_ad-lab_ssh-permission-denied-troubleshoot.png](screenshots/20260508_ad-lab_ssh-permission-denied-troubleshoot.png) | SSH permission denied error during DC hardening access | — |
| [20260508_ad-lab_openssh-defaultshell-fixed.png](screenshots/20260508_ad-lab_openssh-defaultshell-fixed.png) | OpenSSH default shell corrected on WIN-DC01 | — |
| [20260508_ad-lab_protected-users-group-configured.png](screenshots/20260508_ad-lab_protected-users-group-configured.png) | r.hayes and Administrator added to Protected Users group | Protected Users |
| [20260508_ad-lab_rc4-disabled-aes-enabled.png](screenshots/20260508_ad-lab_rc4-disabled-aes-enabled.png) | svc-sql-report: AES128 + AES256 only, RC4 removed | Closes Rule 01 vector |
| [20260508_ad-lab_preauth-reenabled.png](screenshots/20260508_ad-lab_preauth-reenabled.png) | svc-backup-ops: DoesNotRequirePreAuth = False | Closes Rule 02 vector |
| [20260508_ad-lab_password-policy-strengthened.png](screenshots/20260508_ad-lab_password-policy-strengthened.png) | Domain password policy: MinLength 16, Complexity enabled, Lockout 5 | Password hardening |
| [20260508_ad-lab_ds-audit-policy-enabled.png](screenshots/20260508_ad-lab_ds-audit-policy-enabled.png) | DS Access and DS Changes subcategories auditing enabled | Supports Rules 03, 04 |

---

## Pending Screenshots

The following screenshots are captured but not yet committed, or remain outstanding:

| Screenshot | Status | Phase |
|---|---|---|
| `20260508_ad-lab_post-hardening-sharphound-complete.png` | Pending capture | Phase 10 |
| `20260508_ad-lab_bloodhound-after-hardening.png` | Pending capture | Phase 10 |
| `20260508_ad-lab_sysmon-event10-elk.png` | Pending capture | Phase 6 |
| `20260508_ad-lab_ndjson-export.png` | Pending capture | Phase 9 |
| `20260508_ad-lab_detection-rules-overview.png` | Pending capture | Phase 9 |

---

## Screenshot Count

| Phase | Captured | Pending |
|---|---:|---:|
| Phase 0 — VMware Setup | 6 | 0 |
| Phase 1 — DC Build | 15 | 0 |
| Phase 2 — AD Client | 12 | 0 |
| Phase 3 — Kali Setup | 7 | 0 |
| Phase 4 — BloodHound Recon | 14 | 0 |
| Phase 5 — Kerberoasting | 15 | 0 |
| Phase 6 — AS-REP + LSASS | 4 | 1 |
| Phase 7 — DCSync | 2 | 0 |
| Phase 9 — Detection Engineering | 7 | 2 |
| Phase 10 — Hardening | 7 | 2 |
| **Total** | **89** | **5** |
