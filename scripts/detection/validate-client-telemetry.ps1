# =============================================================================
# validate-client-telemetry.ps1
# active-directory-attack-defense — AD client telemetry validation script
# =============================================================================
# Purpose: Verifies that Sysmon and Winlogbeat are running on WIN10-ADCLIENT
#          and that key event channels are active.
#
# Run this script ON WIN10-ADCLIENT (192.168.10.161) as Administrator.
# =============================================================================

#Requires -RunAsAdministrator

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Client Telemetry Validation — WIN10-ADCLIENT" -ForegroundColor Cyan
Write-Host "  active-directory-attack-defense lab" -ForegroundColor Cyan
Write-Host "============================================================"
Write-Host ""

$allPassed = $true

# ---- 1. Sysmon service ----
Write-Host "  [1] Checking Sysmon service..." -NoNewline
$sysmon = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
if (-not $sysmon) {
    $sysmon = Get-Service -Name "Sysmon" -ErrorAction SilentlyContinue
}
if ($sysmon -and $sysmon.Status -eq "Running") {
    Write-Host " RUNNING ($($sysmon.Name))" -ForegroundColor Green
} else {
    Write-Host " NOT RUNNING" -ForegroundColor Red
    Write-Host "      Fix: Start-Service Sysmon64" -ForegroundColor Yellow
    $allPassed = $false
}

# ---- 2. Winlogbeat service ----
Write-Host "  [2] Checking Winlogbeat service..." -NoNewline
$wb = Get-Service -Name "winlogbeat" -ErrorAction SilentlyContinue
if ($wb -and $wb.Status -eq "Running") {
    Write-Host " RUNNING" -ForegroundColor Green
} else {
    Write-Host " NOT RUNNING" -ForegroundColor Red
    Write-Host "      Fix: Start-Service winlogbeat" -ForegroundColor Yellow
    $allPassed = $false
}

# ---- 3. Sysmon event channel accessible ----
Write-Host "  [3] Checking Sysmon event channel..." -NoNewline
try {
    $sysmonEvent = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 1 -ErrorAction Stop
    Write-Host " ACCESSIBLE (last event: $($sysmonEvent.TimeCreated))" -ForegroundColor Green
} catch {
    Write-Host " NOT ACCESSIBLE" -ForegroundColor Red
    Write-Host "      Sysmon may not be installed or channel not registered." -ForegroundColor Yellow
    $allPassed = $false
}

# ---- 4. PowerShell Script Block Logging ----
Write-Host "  [4] Checking PowerShell Script Block Logging..." -NoNewline
$sbKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
$sbEnabled = (Get-ItemProperty -Path $sbKey -Name "EnableScriptBlockLogging" -ErrorAction SilentlyContinue).EnableScriptBlockLogging
if ($sbEnabled -eq 1) {
    Write-Host " ENABLED" -ForegroundColor Green
} else {
    Write-Host " NOT ENABLED" -ForegroundColor Yellow
    Write-Host "      Enable via gpedit.msc or Group Policy for Event 4104 capture." -ForegroundColor DarkGray
}

# ---- 5. Domain membership ----
Write-Host "  [5] Checking domain membership..." -NoNewline
$domain = (Get-WmiObject Win32_ComputerSystem).Domain
if ($domain -eq "soc.local") {
    Write-Host " JOINED ($domain)" -ForegroundColor Green
} else {
    Write-Host " NOT IN SOC.LOCAL (current: $domain)" -ForegroundColor Red
    $allPassed = $false
}

Write-Host ""
Write-Host "============================================================"
if ($allPassed) {
    Write-Host "  All critical checks PASSED." -ForegroundColor Green
    Write-Host "  Client telemetry pipeline is healthy."
} else {
    Write-Host "  One or more critical checks FAILED." -ForegroundColor Red
    Write-Host "  Resolve issues above before running attack scenarios."
}
Write-Host "============================================================"
