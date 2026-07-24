<#
.SYNOPSIS
    Detection half of the LibGuest kill-switch Intune Remediation.

.DESCRIPTION
    Runs as SYSTEM on the Remediation schedule. Reports NON-COMPLIANT (exit 1)
    when the kill switch is engaged AND the provider is still registered -- which
    causes Intune to run Remediate-KillSwitch.ps1. Reports COMPLIANT (exit 0)
    otherwise.

    Engage the kill switch fleet-wide by setting, through any channel you trust
    (a separate Intune settings/config profile, a config script, or manually):

        HKLM\SOFTWARE\UMD Libraries\LibGuestCredentialProvider
            KillSwitch (DWORD) = 1

    On the next Remediation cycle every affected machine unregisters the provider
    without waiting for an uninstall assignment to reach it. This is the fast
    "turn it off everywhere" path (README.md, "Recovery and kill-switch plan").

    Intune Remediation contract: exit 0 = compliant (no action),
    exit 1 = non-compliant (run the remediation script).
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

$ErrorActionPreference = 'SilentlyContinue'

$CLSID       = '{AF63107A-B6A3-4A8D-A967-4D1F8339161C}'
$SentinelKey = 'HKLM:\SOFTWARE\UMD Libraries\LibGuestCredentialProvider'
$ClsidKey    = "HKLM:\SOFTWARE\Classes\CLSID\$CLSID"
$CpKey       = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\$CLSID"

$kill = (Get-ItemProperty -Path $SentinelKey -Name 'KillSwitch').KillSwitch
$stillRegistered = (Test-Path $CpKey) -or (Test-Path $ClsidKey)

if ($kill -eq 1 -and $stillRegistered) {
    Write-Output "Kill switch engaged and provider still registered -> remediation needed."
    exit 1
}

if ($kill -eq 1 -and -not $stillRegistered) {
    Write-Output "Kill switch engaged; provider already unregistered. Compliant."
    exit 0
}

Write-Output "Kill switch not engaged. Compliant."
exit 0
