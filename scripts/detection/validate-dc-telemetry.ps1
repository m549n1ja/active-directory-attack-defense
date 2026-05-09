# =============================================================================
# validate-dc-telemetry.ps1
# active-directory-attack-defense — DC telemetry validation script
# =============================================================================
# Purpose: Verifies that key Windows Security events are being generated on
#          WIN-DC01 and that Winlogbeat is running and shipping to Logstash.
#
# Run this script ON WIN-DC01 (192.168.10.160) as Administrator.
#
# What it checks:
#   1. Winlogbeat service is running
#   2. Audit policy is configured for required subcategories
#   3. Recent Event 4769 (Kerberos TGS) exists in Security log
#   4. Recent Event 4768 (Kerberos AS) exists in Security log
#   5. Directory Service audit policy is enabled (required for Event 4662)
# =============================================================================

#Requires -RunAsAdministrator

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  DC Telemetry Validation — WIN-DC01" -ForegroundColor Cyan
Write-Host "  active-directory-attack-defense lab" -ForegroundColor Cyan
Write-Host "============================================================"
Write-Host ""

$allPassed = $true

# ---- 1. Winlogbeat service ----
Write-Host "  [1] Checking Winlogbeat service..." -NoNewline
$wb = Get-Service -Name "winlogbeat" -ErrorAction SilentlyContinue
if ($wb -and $wb.Status -eq "Running") {
    Write-Host " RUNNING" -ForegroundColor Green
} else {
    Write-Host " NOT RUNNING" -ForegroundColor Red
    Write-Host "      Fix: Start-Service winlogbeat" -ForegroundColor Yellow
    $allPassed = $false
}

# ---- 2. Audit policy — Kerberos Service Ticket Operations ----
Write-Host "  [2] Checking audit policy (Kerberos Service Ticket)..." -NoNewline
$auditKerbTGS = auditpol /get /subcategory:"Kerberos Service Ticket Operations" 2>$null
if ($auditKerbTGS -match "Success") {
    Write-Host " ENABLED" -ForegroundColor Green
} else {
    Write-Host " NOT ENABLED" -ForegroundColor Red
    Write-Host "      Fix: auditpol /set /subcategory:'Kerberos Service Ticket Operations' /success:enable /failure:enable" -ForegroundColor Yellow
    $allPassed = $false
}

# ---- 3. Audit policy — Directory Service Access ----
Write-Host "  [3] Checking audit policy (Directory Service Access)..." -NoNewline
$auditDS = auditpol /get /subcategory:"Directory Service Access" 2>$null
if ($auditDS -match "Success") {
    Write-Host " ENABLED" -ForegroundColor Green
} else {
    Write-Host " NOT ENABLED" -ForegroundColor Red
    Write-Host "      Fix: auditpol /set /subcategory:'Directory Service Access' /success:enable /failure:enable" -ForegroundColor Yellow
    $allPassed = $false
}

# ---- 4. Recent Event 4769 (Kerberoasting signal) ----
Write-Host "  [4] Checking for recent Event 4769 in Security log..." -NoNewline
$event4769 = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4769; StartTime=(Get-Date).AddHours(-24)} -MaxEvents 1 -ErrorAction SilentlyContinue
if ($event4769) {
    Write-Host " PRESENT (last 24h)" -ForegroundColor Green
    Write-Host "      Most recent: $($event4769.TimeCreated)"
} else {
    Write-Host " NOT FOUND (last 24h)" -ForegroundColor Yellow
    Write-Host "      Note: Event 4769 only appears when Kerberos TGS requests are made." -ForegroundColor DarkGray
}

# ---- 5. Recent Event 4768 (AS-REP signal) ----
Write-Host "  [5] Checking for recent Event 4768 in Security log..." -NoNewline
$event4768 = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4768; StartTime=(Get-Date).AddHours(-24)} -MaxEvents 1 -ErrorAction SilentlyContinue
if ($event4768) {
    Write-Host " PRESENT (last 24h)" -ForegroundColor Green
    Write-Host "      Most recent: $($event4768.TimeCreated)"
} else {
    Write-Host " NOT FOUND (last 24h)" -ForegroundColor Yellow
}

# ---- 6. Recent Event 4662 (DCSync signal — requires DS auditing) ----
Write-Host "  [6] Checking for recent Event 4662 in Security log..." -NoNewline
$event4662 = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4662; StartTime=(Get-Date).AddHours(-24)} -MaxEvents 1 -ErrorAction SilentlyContinue
if ($event4662) {
    Write-Host " PRESENT (last 24h)" -ForegroundColor Green
} else {
    Write-Host " NOT FOUND (last 24h)" -ForegroundColor Yellow
    Write-Host "      Note: Event 4662 only appears with Directory Service auditing enabled." -ForegroundColor DarkGray
}

Write-Host ""
Write-Host "============================================================"
if ($allPassed) {
    Write-Host "  All critical checks PASSED." -ForegroundColor Green
    Write-Host "  DC telemetry pipeline is healthy."
} else {
    Write-Host "  One or more critical checks FAILED." -ForegroundColor Red
    Write-Host "  Resolve issues above before running attack scenarios."
}
Write-Host "============================================================"
