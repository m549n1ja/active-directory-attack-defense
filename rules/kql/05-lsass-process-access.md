# Rule 05 — LSASS Process Access

| Field | Value |
|---|---|
| Index pattern | `winlogbeat-*` |
| Severity | High |
| MITRE ATT&CK | T1003.001 — OS Credential Dumping: LSASS Memory |
| Event ID | Sysmon Event 10 |
| Rule type | Custom query |
| Status | Verified — PPL blocked the dump; Sysmon Event 10 captured the attempt |

---

## Purpose

This rule detects attempts to open a handle to lsass.exe for the purpose of credential extraction from process memory. Sysmon Event 10 (ProcessAccess) records the handle request at the time it is made, irrespective of whether the requesting process successfully reads credential material. This property makes the rule effective even in environments where Windows Defender Protected Process Light (PPL) is configured to deny the actual memory read — the access attempt generates evidence independent of its outcome.

The rule was validated in Phase 6 of this project, during which ProcDump was used to attempt an LSASS dump on WIN10-ADCLIENT. PPL denied the dump; Sysmon Event 10 recorded the access attempt with the requested handle access mask.

---

## KQL Query

```kql
event.code: "10" and
winlog.event_data.TargetImage: "*\\lsass.exe" and
not winlog.event_data.SourceImage: "C:\\Windows\\System32\\*" and
not winlog.event_data.SourceImage: "C:\\Windows\\SysWOW64\\*" and
not winlog.event_data.SourceImage: "C:\\Program Files\\*" and
not winlog.event_data.GrantedAccess: "0x1000" and
not winlog.event_data.GrantedAccess: "0x1400"
```

---

## Rule Logic

Sysmon Event 10 fires when a process opens a handle to another process. The key signal is:

- `TargetImage: *\lsass.exe` — the target of the access is the Local Security Authority Subsystem Service
- `SourceImage` exclusions — filter out known-legitimate Windows processes that routinely access LSASS (Task Manager, WerFault, certain AV products)
- `GrantedAccess` exclusions — filter out low-privilege access masks that cannot extract credentials (0x1000 = PROCESS_QUERY_LIMITED_INFORMATION, 0x1400 = limited combined)

High-risk access masks for credential dumping include:
- `0x1010` — PROCESS_QUERY_INFORMATION + PROCESS_VM_READ
- `0x1038` — multiple read/query rights
- `0x1fffff` — PROCESS_ALL_ACCESS (full access)

---

## PPL and Telemetry Independence

Windows Defender Protected Process Light assigns lsass.exe a protection level that prevents non-PPL processes from obtaining handles with read or write access to its memory space. When ProcDump or Mimikatz requests such a handle, the kernel denies the request before any credential material is accessed. Sysmon, however, captures the ProcessAccess event at the point the request is made — before the kernel's enforcement decision — and records the `GrantedAccess` mask that was requested.

The result is that PPL and Sysmon provide complementary and independent evidence: the endpoint control prevents credential extraction, and the SIEM records that the attempt occurred. Both signals are present in the event record from Phase 6, which shows a high-privilege access mask against lsass.exe with no corresponding dump file created.

---

## Prerequisites

- Sysmon64 installed on WIN10-ADCLIENT (and ideally WIN-DC01) with ProcessAccess logging enabled
- SwiftOnSecurity Sysmon config enables Event 10 by default
- Winlogbeat configured to collect from `Microsoft-Windows-Sysmon/Operational` event channel
- winlogbeat-* data view configured in Kibana Security

---

## Test Method (Lab Only — Do Not Run on Production Systems)

From WIN10-ADCLIENT:
```powershell
# ProcDump (will be blocked by PPL on patched Win10)
.\procdump.exe -ma lsass.exe lsass.dmp
```

Wait 30–60 seconds, then filter Kibana Discover:
```kql
event.code: "10" and winlog.event_data.TargetImage: "*lsass.exe"
```

---

## Expected Result

Sysmon Event 10 appears with:
- `winlog.event_data.TargetImage`: C:\Windows\System32\lsass.exe
- `winlog.event_data.SourceImage`: path to ProcDump or Mimikatz executable
- `winlog.event_data.GrantedAccess`: high-privilege access mask (0x1010 or higher)
- If PPL is enabled: the dump file will not be created, but the event still fires

---

## Evidence

- `evidence/screenshots/20260508_ad-lab_lsass-ppl-blocked.png`
- `evidence/screenshots/20260508_ad-lab_sysmon-event10-elk.png`

---

## False Positives

- Antivirus and EDR products routinely access LSASS for behavioral monitoring (exclude by `SourceImage` path)
- Windows Error Reporting (WerFault.exe) accesses LSASS after crashes (excluded by default)
- Sysinternals Process Monitor and Process Explorer access LSASS (exclude known-good tools by path)

**Tuning:** Build an allowlist of known-legitimate processes that access LSASS in your environment. Any access from paths outside the allowlist, or with high-privilege `GrantedAccess` masks, should alert.
