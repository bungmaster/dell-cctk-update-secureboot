<#
  CI Discovery Script: BIOS behind vendor (Dell only) using Dell Command | Update (DCU)
  Returns: "Compliant" or "NonCompliant" (or "NonCompliant:<reason>")
  https://www.dell.com/support/manuals/en-us/command-update/dcu_rg/command-line-interface-error-codes?guid=guid-fbb96b06-4603-423a-baec-cbf5963d8948&lang=en-us
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---- Helpers ----
function Get-DcuCliPath {
    $paths = @(
        "$env:ProgramFiles\Dell\CommandUpdate\dcu-cli.exe",
        "${env:ProgramFiles(x86)}\Dell\CommandUpdate\dcu-cli.exe"
    )
    foreach ($p in $paths) {
        if (Test-Path $p) { return $p }
    }
    return $null
}

function Is-DellSystem {
    try {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem
        return ($cs.Manufacturer -match 'Dell')
    } catch {
        # If we can't even read WMI, fail closed (noncompliant)
        return $true
    }
}

function Test-PendingReboot {
    # Common Windows pending reboot indicators (best-effort)
    $pending = $false

    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $pending = $true }
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $pending = $true }

    try {
        $pfro = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name 'PendingFileRenameOperations' -ErrorAction SilentlyContinue
        if ($pfro.PendingFileRenameOperations) { $pending = $true }
    } catch {}

    return $pending
}

# ---- Main ----
# Non-Dell devices are considered compliant (avoid noisy results if deployed broadly)
if (-not (Is-DellSystem)) {
    return "Compliant"
}

# If remediation already staged a BIOS update and Windows is pending reboot, consider compliant
$markerKey = 'HKLM:\SOFTWARE\SFU\BIOSCompliance'
$markerName = 'BiosUpdatePendingReboot'
try {
    $marker = (Get-ItemProperty -Path $markerKey -Name $markerName -ErrorAction SilentlyContinue).$markerName
    if ($marker -eq 1 -and (Test-PendingReboot)) {
        return "Compliant"
    }
} catch {}

$dcu = Get-DcuCliPath
if (-not $dcu) {
    return "NonCompliant:DCU_NotInstalled"
}

# Ensure log folder exists
$logDir = 'C:\SFUMW\Logs\Dell_Command_Update'
New-Item -ItemType Directory -Force -Path $logDir | Out-Null
$scanLog = Join-Path $logDir 'DCU_Scan_BIOS.log'

# Run scan (BIOS only)
# Dell DCU CLI uses /<command> -option=value style and supports scan/apply operations. [2](https://manuals.plus/m/b4336a771910937caacb0640cba375f29b62902b48ae2aec5f513d20844f00f7)[1](https://www.dell.com/support/kbdoc/en-us/000177325/dell-command-update)
# get this stuff back to basics:
# dcu-cli.exe /configure -restoreDefaults
$proc = Start-Process -FilePath $dcu -ArgumentList @(
    '/scan',
    '-updateType=bios',
    "-outputLog=$scanLog",
    '-silent'
) -PassThru -Wait -WindowStyle Hidden

# Parse log (robust-ish string checks across DCU versions)
if (-not (Test-Path $scanLog)) {
    return "NonCompliant:ScanLogMissing(ExitCode=$($proc.ExitCode))"
}

$logText = Get-Content -Path $scanLog -Raw -ErrorAction SilentlyContinue

# Heuristics:
# - If it explicitly says no updates -> compliant
# - If it indicates updates available (or lists BIOS) -> noncompliant
if ($logText -match '(?i)no updates( were)? found|no updates were found|no applicable updates|NO_UPDATES|The program exited with return code: 500') {
    return "Compliant"
}

if ($logText -match '(?i)BIOS|Update(s)? (are )?available|Applicable update(s)?|Number of updates|Updates found|Number of applicable updates') {
    return "NonCompliant"
}

# Unknown scan result -> fail closed so you see it
return "NonCompliant:UnknownScanResult(ExitCode=$($proc.ExitCode))"
