# Evidence Index — active-directory-attack-defense

All screenshots are saved to `evidence/screenshots/` and follow the naming convention:
`YYYYMMDD_ad-lab_description.png`

---

## Phase 1 — Domain Controller Build

| Screenshot | Description | Related Rule |
|---|---|---|
| `20260430_ad-lab_dc-ad-ds-installed.png` | Server Manager showing AD DS role installed | — |
| `20260430_ad-lab_dc-promotion-complete.png` | Domain controller promotion wizard complete | — |
| `20260430_ad-lab_dc-ad-users-computers.png` | AD Users and Computers showing soc.local | — |
| `20260430_ad-lab_dc-service-accounts-created.png` | svc-sql-report and svc-backup-ops created | Rules 01, 02 |
| `20260430_ad-lab_dc-winlogbeat-running.png` | Winlogbeat service running on DC (Phase 5 install) | All rules |

---

## Phase 2 — AD Client Build

| Screenshot | Description | Related Rule |
|---|---|---|
| `20260502_ad-lab_win10-client-hostname-set.png` | WIN10-ADCLIENT hostname confirmed | — |
| `20260502_ad-lab_win10-client-dc-connectivity.png` | Client connectivity to DC at 192.168.10.160 | — |
| `20260502_ad-lab_domain-join-failure-dns-error.png` | Domain join failure — DNS pointed to gateway | — |
| `20260502_ad-lab_win10-client-dhcp-misconfiguration.png` | DHCP misconfiguration (DNS issue) | — |
| `20260502_ad-lab_win10-client-static-ip-fixed.png` | Static IP and DNS corrected | — |
| `20260502_ad-lab_domain-join-confirmed.png` | Domain join to soc.local confirmed | — |
| `20260502_ad-lab_sysmon-running.png` | Sysmon64 service running on client | Rule 05 |
| `20260502_ad-lab_winlogbeat-config-test.png` | Winlogbeat configuration test output | — |
| `20260502_ad-lab_winlogbeat-logstash-connection.png` | Winlogbeat connected to Logstash:5044 | — |
| `20260502_ad-lab_winlogbeat-running.png` | Winlogbeat service running on client | — |
| `20260502_ad-lab_adclient-logs-in-elk.png` | winlogbeat-* index with client events in Kibana | — |

---

## Phase 3 — Kali Attacker Setup

| Screenshot | Description | Related Rule |
|---|---|---|
| `20260507_ad-lab_kali-ip-conflict-dhcp-and-static.png` | Dual-IP conflict during setup | — |
| `20260507_ad-lab_kali-static-ip-fixed.png` | Static IP 192.168.10.20 confirmed | — |
| `20260507_ad-lab_kali-lab-connectivity.png` | Kali connectivity to DC and ELK confirmed | — |
| `20260507_ad-lab_kali-bloodhound-tool-check.png` | BloodHound CE, Impacket, Hashcat validated | — |

---

## Phase 4 — BloodHound Reconnaissance

| Screenshot | Description | Related Rule |
|---|---|---|
| `20260507_ad-lab_bloodhound-dashboard-empty.png` | BloodHound CE dashboard before data ingestion | Rule 04 |
| `20260507_ad-lab_sharphound-downloaded.png` | SharpHound downloaded to WIN10-ADCLIENT | Rule 04 |
| `20260507_ad-lab_defender-blocked-sharphound.png` | Defender blocking SharpHound (before exclusion) | — |
| `20260507_ad-lab_domain-user-login-success.png` | Domain user login to WIN10-ADCLIENT | — |
| `20260507_ad-lab_sharphound-collection-complete.png` | SharpHound collection completed | Rule 04 |
| `20260507_ad-lab_sharphound-zip-generated.png` | SharpHound output ZIP generated | Rule 04 |
| `20260507_ad-lab_sharphound-zip-transferred.png` | ZIP transferred to Kali via SCP | Rule 04 |
| `20260507_ad-lab_bloodhound-upload-complete.png` | BloodHound CE ingestion complete | Rule 04 |
| `20260507_ad-lab_bloodhound-domain-admin-user.png` | r.hayes confirmed as Domain Admin in BloodHound | Rule 04 |
| `20260507_ad-lab_bloodhound-attack-path.png` | Attack path from o.intern to Domain Admin | Rule 04 |
| `20260507_ad-lab_kerberoast-target-account.png` | svc-sql-report SPN in BloodHound | Rule 01 |

---

## Phase 5 — Kerberoasting

| Screenshot | Description | Related Rule |
|---|---|---|
| `20260507_ad-lab_kerberoast-hash-capture.png` | impacket-GetUserSPNs capturing RC4 hash | Rule 01 |
| `20260507_ad-lab_event-4769-elk.png` | Event 4769 with etype 0x17 in Kibana | Rule 01 |
| `20260507_ad-lab_dc-winlogbeat-installed.png` | Winlogbeat installed on WIN-DC01 (telemetry gap fix) | All DC rules |
| `20260507_ad-lab_telemetry-gap-resolved.png` | DC events appearing in ELK after Winlogbeat install | All DC rules |
| `20260508_ad-lab_kerberoasting-rule-alert.png` | Kerberoasting detection rule firing in Kibana Security | Rule 01 |

---

## Phase 6 — AS-REP Roasting + LSASS

| Screenshot | Description | Related Rule |
|---|---|---|
| `20260507_ad-lab_asrep-hash-capture.png` | impacket-GetNPUsers capturing AS-REP hash | Rule 02 |
| `20260507_ad-lab_event-4768-elk.png` | Event 4768 with PreAuthType 0 in Kibana | Rule 02 |
| `20260508_ad-lab_lsass-ppl-blocked.png` | ProcDump/Mimikatz blocked by Defender PPL | Rule 05 |
| `20260508_ad-lab_sysmon-event10-elk.png` | Sysmon Event 10 showing LSASS access attempt | Rule 05 |
| `20260508_ad-lab_asrep-rule-alert.png` | AS-REP Roasting detection rule firing in Kibana | Rule 02 |

---

## Phase 7 — DCSync

| Screenshot | Description | Related Rule |
|---|---|---|
| `20260508_ad-lab_dcsync-secretsdump-output.png` | impacket-secretsdump replication output (hashes redacted) | Rule 03 |
| `20260508_ad-lab_event-4662-elk.png` | Event 4662 with replication GUIDs in Kibana | Rule 03 |
| `20260508_ad-lab_dcsync-rule-alert.png` | DCSync detection rule firing in Kibana Security | Rule 03 |

---

## Phase 9 — Detection Engineering

| Screenshot | Description | Related Rule |
|---|---|---|
| `20260508_ad-lab_sharphound-rule-alert.png` | SharpHound LDAP Burst rule firing | Rule 04 |
| `20260508_ad-lab_lateral-movement-ntlm-alert.png` | Lateral Movement NTLM rule firing | Rule 06 |
| `20260508_ad-lab_ndjson-export.png` | Kibana rules exported as NDJSON | All rules |
| `20260508_ad-lab_detection-rules-overview.png` | All 6 rules visible in Kibana Security | All rules |

---

## Phase 10 — AD Hardening

| Screenshot | Description | Related Control |
|---|---|---|
| `20260508_ad-lab_protected-users-group-configured.png` | r.hayes + Administrator in Protected Users group | Protected Users |
| `20260508_ad-lab_rc4-disabled-aes-enabled.png` | svc-sql-report: AES128+AES256 only, RC4 removed | Closes Rule 01 vector |
| `20260508_ad-lab_preauth-reenabled.png` | svc-backup-ops: DoesNotRequirePreAuth = False | Closes Rule 02 vector |
| `20260508_ad-lab_password-policy-strengthened.png` | Domain policy: MinLength 16, Complexity, Lockout 5 | Password hardening |
| `20260508_ad-lab_ds-audit-policy-enabled.png` | DS Access + DS Changes auditing enabled | Supports Rule 03, 04 |
| `20260508_ad-lab_post-hardening-sharphound-complete.png` | Post-hardening SharpHound: 315 objects collected | — |
| `20260508_ad-lab_bloodhound-after-hardening.png` | BloodHound attack paths after hardening *(pending)* | All |

---

## Screenshot Count

| Phase | Count | Status |
|---|---:|---|
| Phase 1 — DC Build | 5 | Complete |
| Phase 2 — AD Client | 11 | Complete |
| Phase 3 — Kali Setup | 4 | Complete |
| Phase 4 — BloodHound Recon | 11 | Complete |
| Phase 5 — Kerberoasting | 5 | Complete |
| Phase 6 — AS-REP + LSASS | 5 | Complete |
| Phase 7 — DCSync | 3 | Complete |
| Phase 9 — Detection Engineering | 4 | Complete |
| Phase 10 — Hardening | 7 | 6 complete, 1 pending |
| **Total** | **55** | **54 captured, 1 pending** |
