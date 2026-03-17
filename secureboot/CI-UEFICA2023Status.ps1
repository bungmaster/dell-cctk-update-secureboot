<#
.SYNOPSIS
  SCCM CI Detection Script - Secure Boot UEFI CA 2023 certificate update status

.DESCRIPTION
  Reads the Secure Boot servicing status value:
    HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing\UEFICA2023Status

  CI is compliant ONLY when this script outputs exactly:  Updated

  Any other output string = Non-compliant (including missing key/value, errors, etc.)

.NOTES
  - Intended for MECM/SCCM Configuration Items (runs as Local System by default).
  - Keep output minimal: use Write-Output (not Write-Host).
  - Exception handling is intentionally “fail-safe”: unknown state -> Non-compliant.

#>

# Registry path and value name we expect
$RegPath  = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing'
$ValueName = 'UEFICA2023Status'

try {
    # 1) Confirm the key exists
    if (-not (Test-Path -Path $RegPath)) {
        # Key missing usually means: not applicable OS build, not yet staged, or feature not present
        Write-Output "NotUpdated: MissingKey ($RegPath)"
        exit 0
    }

    # 2) Try to read the value safely
    $item = Get-ItemProperty -Path $RegPath -ErrorAction Stop

    # 3) Confirm the property exists and is not null/empty
    if ($null -eq $item.$ValueName -or [string]::IsNullOrWhiteSpace([string]$item.$ValueName)) {
        Write-Output "NotUpdated: MissingValue ($ValueName)"
        exit 0
    }

    # 4) Normalize the status string (trim whitespace)
    $status = ([string]$item.$ValueName).Trim()

    # 5) Compliance check - MUST return exactly "Updated"
    if ($status -eq 'Updated') {
        Write-Output 'Updated'
        exit 0
    }

    # 6) Known/expected statuses may include NotStarted / InProgress (varies by rollout)
    # Any non-Updated value -> Non-compliant, but we return the actual status for reporting.
    Write-Output "NotUpdated: Status=$status"
    exit 0
}
catch [System.UnauthorizedAccessException] {
    # Rare in CI context (SYSTEM usually has access), but handle explicitly.
    Write-Output "NotUpdated: AccessDenied ($($_.Exception.Message))"
    exit 0
}
catch [System.Management.Automation.ItemNotFoundException] {
    # Path disappeared or was never present
    Write-Output "NotUpdated: MissingKeyOrValue"
    exit 0
}
catch {
    # Catch-all: any unexpected runtime failure should be treated as non-compliant.
    Write-Output "NotUpdated: Error=$($_.Exception.GetType().Name)"
    exit 0
}


