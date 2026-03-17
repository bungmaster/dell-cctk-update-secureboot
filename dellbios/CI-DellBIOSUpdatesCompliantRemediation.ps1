<#
  CI Remediation Script: Apply BIOS updates (Dell only) using Dell Command | Update (DCU)
  - Runs BIOS-only apply
  - Does NOT force reboot (lets ConfigMgr / maintenance windows control restarts)
  - Writes a marker indicating BIOS update may be pending reboot
  dcu-cli.exe /configure -biosPassword="%BIOSPASS%" -outputLog="%SYSTEMDRIVE%\SFUMW\Logs\Dell_Command_Update\DCU-CLI_biosPassword.log" -silent
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

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
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    return ($cs.Manufacturer -match 'Dell')
}

# Non-Dell systems: do nothing
if (-not (Is-DellSystem)) { return }

$dcu = Get-DcuCliPath
if (-not $dcu) {
    # DCU not installed -> cannot remediate BIOS via this method
    return
}

# Log folder
#$logDir = Join-Path $env:ProgramData 'SFU\BIOSCompliance'
$logDir = 'C:\SFUMW\Logs\Dell_Command_Update'
New-Item -ItemType Directory -Force -Path $logDir | Out-Null
$unlockLog = Join-Path $logDir 'DCU_Unlock.log'
$applyLog = Join-Path $logDir 'DCU_Apply_BIOS.log'
# ITDS ONLY unlock the BIOS PW
$unlock = Start-Process -FilePath $dcu -ArgumentList @(
    '/configure',
    '-biosPassword="**************"',
    "-outputLog=$unlockLog",
    '-silent'
) -PassThru -Wait -WindowStyle Hidden
# Apply BIOS-only updates; do not auto reboot
# DCU supports CLI automation for BIOS updates. [1](https://www.dell.com/support/kbdoc/en-us/000177325/dell-command-update)[2](https://manuals.plus/m/b4336a771910937caacb0640cba375f29b62902b48ae2aec5f513d20844f00f7)
$proc = Start-Process -FilePath $dcu -ArgumentList @(
    '/applyUpdates',
    '-updateType=bios',
    '-reboot=disable',
    '-autoSuspendBitLocker=enable',
    "-outputLog=$applyLog",
    '-silent'
) -PassThru -Wait -WindowStyle Hidden

# Create/update marker key so detection can treat "pending reboot" as compliant
$markerKey = 'HKLM:\SOFTWARE\SFU\BIOSCompliance'
New-Item -Path $markerKey -Force | Out-Null

# If apply log suggests reboot required, set pending marker
$pending = $false
if (Test-Path $applyLog) {
    $txt = Get-Content -Path $applyLog -Raw -ErrorAction SilentlyContinue
    if ($txt -match '(?i)restart required|reboot required|pending reboot') {
        $pending = $true
    }
}

Set-ItemProperty -Path $markerKey -Name 'LastApplyExitCode' -Type DWord -Value $proc.ExitCode -Force | Out-Null
Set-ItemProperty -Path $markerKey -Name 'LastApplyTime' -Type String -Value (Get-Date).ToString('s') -Force | Out-Null
Set-ItemProperty -Path $markerKey -Name 'BiosUpdatePendingReboot' -Type DWord -Value ([int]$pending) -Force | Out-Null
