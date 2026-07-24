<#
.SYNOPSIS
    Remediation half of the LibGuest kill-switch Intune Remediation.

.DESCRIPTION
    Runs as SYSTEM when Detect-KillSwitch.ps1 reports non-compliant. Unregisters
    the provider using the same registration-first order as the uninstaller, so
    LogonUI stops loading the DLL on the next sign-out/reboot.

    Removes only the registrations (and leaves the DLL and sentinel on disk) so
    the machine's state is inspectable afterward and the sentinel's KillSwitch=1
    remains a durable record. Once unregistered, Detect-KillSwitch reports
    compliant and this stops running.

    Intune Remediation contract: exit 0 = remediation succeeded.
#>
[CmdletBinding()]
param()

if ($env:PROCESSOR_ARCHITEW6432 -eq 'AMD64' -and -not [Environment]::Is64BitProcess) {
    $sysnative = Join-Path $env:WINDIR 'SysNative\WindowsPowerShell\v1.0\powershell.exe'
    if (Test-Path $sysnative) {
        & $sysnative -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath @args
        exit $LASTEXITCODE
    }
}

$ErrorActionPreference = 'Continue'

$CLSID    = '{AF63107A-B6A3-4A8D-A967-4D1F8339161C}'
$ClsidKey = "HKLM:\SOFTWARE\Classes\CLSID\$CLSID"
$CpKey    = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\$CLSID"
$LogDir   = Join-Path $env:ProgramData 'LibGuestCredentialProvider'
$LogPath  = Join-Path $LogDir 'install.log'

function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $line = '{0} [{1}] KILLSWITCH {2}' -f (Get-Date -Format 's'), $Level, $Message
    try {
        if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
        Add-Content -Path $LogPath -Value $line -Encoding utf8
    } catch { }
    Write-Host $line
}

Write-Log "Engaged. Unregistering provider (registration-first order)."

# 1. Credential Providers registration FIRST.
if (Test-Path $CpKey) {
    Remove-Item -Path $CpKey -Recurse -Force -ErrorAction SilentlyContinue
    Write-Log "Removed $CpKey"
}

# 2. COM CLSID registration.
if (Test-Path $ClsidKey) {
    Remove-Item -Path $ClsidKey -Recurse -Force -ErrorAction SilentlyContinue
    Write-Log "Removed $ClsidKey"
}

# Verify.
if ((Test-Path $CpKey) -or (Test-Path $ClsidKey)) {
    Write-Log "Registration still present after removal attempt." 'ERROR'
    exit 1
}

Write-Log "Provider unregistered. Takes effect at next sign-out/reboot."
exit 0
