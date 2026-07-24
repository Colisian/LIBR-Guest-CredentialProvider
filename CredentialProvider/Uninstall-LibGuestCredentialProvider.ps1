<#
.SYNOPSIS
    Unregisters and removes the LibGuest credential provider. Also serves as the
    immediate-uninstall kill switch (README.md, "Recovery and kill-switch plan").

.DESCRIPTION
    Intune Win32 app uninstall command, and the target of a separate Intune
    uninstall assignment that can be activated immediately. Runs as SYSTEM.

    Removal order is deliberate and must not change (README.md, "Intune
    deployment design"):
      1. Remove the Credential Providers registration FIRST, so future LogonUI
         instances stop loading the DLL even if later steps fail.
      2. Remove the COM CLSID registration.
      3. Remove the DLL only after both registrations are gone.
      4. Return a failure exit code if any security-relevant registration
         remains, so Intune reports the machine as still-affected.

    Safe to run when the provider is already partially or fully removed.

.NOTES
    Relaunches under 64-bit PowerShell if started 32-bit, so it targets the same
    registry view the installer wrote to.
#>
[CmdletBinding()]
param(
    [switch]$KeepDll,          # leave the DLL on disk (registration still removed)
    [switch]$KeepSentinel      # leave the sentinel key (for diagnostics)
)

if ($env:PROCESSOR_ARCHITEW6432 -eq 'AMD64' -and -not [Environment]::Is64BitProcess) {
    $sysnative = Join-Path $env:WINDIR 'SysNative\WindowsPowerShell\v1.0\powershell.exe'
    if (Test-Path $sysnative) {
        & $sysnative -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath @args
        exit $LASTEXITCODE
    }
}

$ErrorActionPreference = 'Continue'   # best-effort removal; we verify at the end

# --- Configuration (keep in sync across all deployment scripts) ---------------
$CLSID       = '{AF63107A-B6A3-4A8D-A967-4D1F8339161C}'
$DllName     = 'LibGuestCredentialProvider.dll'
$InstallDir  = Join-Path $env:ProgramFiles 'UMD Libraries\LibGuestCredentialProvider'
$SentinelKey = 'HKLM:\SOFTWARE\UMD Libraries\LibGuestCredentialProvider'
$ClsidKey    = "HKLM:\SOFTWARE\Classes\CLSID\$CLSID"
$CpKey       = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\$CLSID"
$LogDir      = Join-Path $env:ProgramData 'LibGuestCredentialProvider'
$LogPath     = Join-Path $LogDir 'install.log'

function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $line = '{0} [{1}] {2}' -f (Get-Date -Format 's'), $Level, $Message
    try {
        if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
        Add-Content -Path $LogPath -Value $line -Encoding utf8
    } catch { }
    Write-Host $line
}

function Remove-KeyIfPresent {
    param([string]$Path)
    if (Test-Path $Path) {
        try {
            Remove-Item -Path $Path -Recurse -Force -ErrorAction Stop
            Write-Log "Removed $Path"
        } catch {
            Write-Log "FAILED to remove $Path : $($_.Exception.Message)" 'ERROR'
        }
    } else {
        Write-Log "Not present (already gone): $Path"
    }
}

Write-Log "Uninstall/kill starting for CLSID $CLSID."

# 1. Credential Providers registration FIRST.
Remove-KeyIfPresent -Path $CpKey

# 2. COM CLSID registration.
Remove-KeyIfPresent -Path $ClsidKey

# 3. DLL, only after registrations are gone.
if (-not $KeepDll) {
    $destDll = Join-Path $InstallDir $DllName
    if (Test-Path $destDll) {
        try {
            Remove-Item -Path $destDll -Force -ErrorAction Stop
            Write-Log "Removed DLL $destDll"
        } catch {
            # A file lock does not defeat the kill switch: the registrations are
            # already gone, so LogonUI will not load the DLL on next sign-in.
            Write-Log "DLL still locked, could not delete: $($_.Exception.Message). Registration is already removed, so the provider is disabled regardless." 'WARN'
        }
    }
    # Remove the install dir if now empty.
    if ((Test-Path $InstallDir) -and -not (Get-ChildItem $InstallDir -Force -ErrorAction SilentlyContinue)) {
        Remove-Item $InstallDir -Force -ErrorAction SilentlyContinue
    }
}

if (-not $KeepSentinel) {
    Remove-KeyIfPresent -Path $SentinelKey
}

# 4. Verify nothing security-relevant remains; fail loudly if it does.
$remaining = @()
if (Test-Path $CpKey)    { $remaining += $CpKey }
if (Test-Path $ClsidKey) { $remaining += $ClsidKey }

if ($remaining.Count -gt 0) {
    Write-Log "SECURITY-RELEVANT REGISTRATION STILL PRESENT: $($remaining -join '; ')" 'ERROR'
    exit 1
}

Write-Log "Uninstall/kill completed. Provider is unregistered."
Write-Log "NOTE: already-running LogonUI keeps the old provider until the next sign-out/reboot."
exit 0
