<#
.SYNOPSIS
  SCCM CB Remediation - Secure Boot UEFI CA 2023 update enrollment + trigger + reboot staging

.DESCRIPTION
  0) Exit cleanly if:
       - AvailableUpdates == 0x4000
       - UEFICA2023Status == "Updated" (case-insensitive)
  1) Opt-in to Microsoft-managed servicing assist (MicrosoftUpdateManagedOptIn=1)
  2) Ensure HighConfidenceOptOut=0 (stay opted-in)
  3) Trigger servicing (AvailableUpdates = 0x5944)
  4) Start the Secure-Boot-Update scheduled task
  5) Wait until AvailableUpdates becomes 0x4100 (reboot-staged)
  6) Signal a soft restart (scheduled reboot with delay/message)

.NOTES
  - Designed for MECM/SCCM baselines (runs as LocalSystem by default).
  - Fail-safe behavior: unexpected errors -> report and exit without crashing CI execution.
  - Uses bounded wait to avoid hanging baseline evaluation.

REFERENCE
  Microsoft Secure Boot registry controls and monitoring keys. [2](https://support.microsoft.com/en-us/topic/registry-key-updates-for-secure-boot-windows-devices-with-it-managed-updates-a7be69c9-4634-42e1-9ca1-df06f43f360d)[1](https://windowsforum.com/threads/managing-the-microsoft-secure-boot-2023-certificate-rollout-with-registry-controls.384520/)
#>

# -----------------------------
# Configuration
# -----------------------------
$SecureBootRoot   = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot'
$ServicingKey     = Join-Path $SecureBootRoot 'Servicing'

$TriggerValueHex  = 0x5944
$RebootStageHex   = 0x4100

# Early exit condition (requested)
$TerminalNoActionHex = 0x4000

$PollIntervalSec  = 10
$MaxPolls         = 180    # 30 minutes max

$RestartDelaySec  = 300
$RestartMessage   = "Secure Boot certificate update staged. A reboot is required in less than 5 minutes to continue. Please save your work."

# -----------------------------
# Helper functions
# -----------------------------
function Write-Result {
    param([string]$Message)
    Write-Output $Message
}

function Ensure-RegistryKey {
    param([string]$Path)
    if (-not (Test-Path -Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }
}

function Get-DwordValue {
    param([string]$Path, [string]$Name)
    try {
        $obj = Get-ItemProperty -Path $Path -ErrorAction Stop
        if ($null -eq $obj.$Name) { return $null }
        return [int]$obj.$Name
    }
    catch { return $null }
}

function Get-Value {
    param([string]$Path, [string]$Name)
    try {
        $obj = Get-ItemProperty -Path $Path -ErrorAction Stop
        return $obj.$Name
    }
    catch { return $null }
}

function Start-SecureBootUpdateTask {
    $taskPathName = '\Microsoft\Windows\PI\Secure-Boot-Update'
    try {
        if (Get-Command Start-ScheduledTask -ErrorAction SilentlyContinue) {
            try {
                Start-ScheduledTask -TaskName $taskPathName -ErrorAction Stop
                return $true
            }
            catch {
                Start-ScheduledTask -TaskPath '\Microsoft\Windows\PI\' -TaskName 'Secure-Boot-Update' -ErrorAction Stop
                return $true
            }
        }
        else {
            $null = & schtasks.exe /Run /TN $taskPathName 2>$null
            if ($LASTEXITCODE -eq 0) { return $true }
        }
    }
    catch { }
    return $false
}

function Suspend-BitLockerForReboots {
    param([int]$RebootCount = 3)
    try {
        $drives = Get-BitLockerVolume -ErrorAction Stop | Where-Object { $_.LockStatus -eq 'On' }
        if ($null -ne $drives) {
            foreach ($drive in $drives) {
                Suspend-BitLocker -MountPoint $drive.MountPoint -RebootCount $RebootCount -ErrorAction Stop
                Write-Result ("BitLocker suspended on {0} for {1} reboots." -f $drive.MountPoint, $RebootCount)
            }
        }
        else {
            Write-Result "No BitLocker-enabled drives found or BitLocker is not active."
        }
    }
    catch {
        Write-Result ("Warning: Could not suspend BitLocker: {0}" -f $_.Exception.Message)
    }
}

# -----------------------------
# Main logic
# -----------------------------
try {
    # Ensure base key exists (some builds may not have it until updates are installed)
    Ensure-RegistryKey -Path $SecureBootRoot

    # ---------------------------------------------------------
    # EARLY EXIT CONDITIONS (requested)
    # ---------------------------------------------------------

    # A) Exit if AvailableUpdates == 0x4000
    $available = Get-DwordValue -Path $SecureBootRoot -Name 'AvailableUpdates'
    if ($null -ne $available -and $available -eq $TerminalNoActionHex) {
        Write-Result ("Exit: AvailableUpdates already 0x{0:X4} (no action taken)." -f $TerminalNoActionHex)
        exit 0
    }

    # B) Exit if UEFICA2023Status == "Updated" (case-insensitive)
    # Common status progression is NotStarted -> InProgress -> Updated. [1](https://windowsforum.com/threads/managing-the-microsoft-secure-boot-2023-certificate-rollout-with-registry-controls.384520/)
    $uefiStatus = Get-Value -Path $ServicingKey -Name 'UEFICA2023Status'
    if ($null -ne $uefiStatus) {
        $statusText = ([string]$uefiStatus).Trim()
        if ($statusText -ieq 'Updated') {
            Write-Result "Exit: UEFICA2023Status is Updated (no action taken)."
            exit 0
        }
    }

    # ---------------------------------------------------------
    # Main remediation steps
    # ---------------------------------------------------------

    # 0) Suspend BitLocker for up to three reboots
    Suspend-BitLocker -MountPoint "C:" -RebootCount 3

    # 1) Opt‑in to Microsoft-managed rollout assist. [2](https://support.microsoft.com/en-us/topic/registry-key-updates-for-secure-boot-windows-devices-with-it-managed-updates-a7be69c9-4634-42e1-9ca1-df06f43f360d)
    Set-ItemProperty -Path $SecureBootRoot -Name "MicrosoftUpdateManagedOptIn" -Type DWord -Value 1 -ErrorAction Stop

    # 2) Ensure HighConfidenceOptOut=0 (opted in). [2](https://support.microsoft.com/en-us/topic/registry-key-updates-for-secure-boot-windows-devices-with-it-managed-updates-a7be69c9-4634-42e1-9ca1-df06f43f360d)
    Set-ItemProperty -Path $SecureBootRoot -Name "HighConfidenceOptOut" -Type DWord -Value 0 -ErrorAction Stop

    # 3) Set update trigger (AvailableUpdates = 0x5944). [2](https://support.microsoft.com/en-us/topic/registry-key-updates-for-secure-boot-windows-devices-with-it-managed-updates-a7be69c9-4634-42e1-9ca1-df06f43f360d)
    Set-ItemProperty -Path $SecureBootRoot -Name "AvailableUpdates" -Type DWord -Value $TriggerValueHex -ErrorAction Stop
    Write-Result ("Triggered Secure Boot update: AvailableUpdates set to 0x{0:X4}" -f $TriggerValueHex)

    # 4) Start the Secure-Boot-Update task
    $taskStarted = Start-SecureBootUpdateTask
    if ($taskStarted) {
        Write-Result "Secure-Boot-Update task started."
    }
    else {
        Write-Result "Warning: Could not start Secure-Boot-Update task (will rely on next scheduled run)."
    }

    # 5) Wait for AvailableUpdates to become 0x4100
    #    ALSO: exit cleanly if it becomes 0x4000 during the wait.
    $observedRebootStage = $false
    for ($i = 1; $i -le $MaxPolls; $i++) {

        $current = Get-DwordValue -Path $SecureBootRoot -Name 'AvailableUpdates'

        if ($null -ne $current) {

            # Progress output (light touch)
            if ($i -eq 1 -or ($i % 30 -eq 0)) {
                Write-Result ("Waiting: AvailableUpdates=0x{0:X4}" -f $current)
            }

            # Early clean exit if 0x4000 appears during wait
            if ($current -eq $TerminalNoActionHex) {
                Write-Result ("Exit: AvailableUpdates became 0x{0:X4} during wait (no reboot signaled)." -f $TerminalNoActionHex)
                exit 0
            }

            # Desired reboot staging
            if ($current -eq $RebootStageHex) {
                $observedRebootStage = $true
                Write-Result ("Reached reboot stage: AvailableUpdates=0x{0:X4}" -f $RebootStageHex)
                break
            }
        }

        Start-Sleep -Seconds $PollIntervalSec
    }

    if (-not $observedRebootStage) {
        Write-Result ("Not rebooting: AvailableUpdates did not reach 0x{0:X4} within wait window." -f $RebootStageHex)
        exit 0
    }

    # 6) Signal a soft restart
    try {
        $msg = $RestartMessage.Replace('"','''')
        & shutdown.exe /r /t $RestartDelaySec /c $msg | Out-Null
        Write-Result ("Soft restart scheduled in {0} seconds." -f $RestartDelaySec)
    }
    catch {
        Write-Result ("Warning: Failed to schedule reboot: {0}" -f $_.Exception.Message)
    }

    exit 0
}
catch [System.UnauthorizedAccessException] {
    Write-Result ("Error: Access denied writing Secure Boot registry values: {0}" -f $_.Exception.Message)
    exit 0
}
catch {
    Write-Result ("Error: Remediation failed: {0}" -f $_.Exception.GetType().Name)
    exit 0
}
