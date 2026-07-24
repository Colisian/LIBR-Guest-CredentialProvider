<#
.SYNOPSIS
    Intune Win32 app detection rule for the LibGuest credential provider.

.DESCRIPTION
    Runs as SYSTEM. A bare "CLSID exists" check is not strong enough for
    production health (README.md, "Intune deployment design"), so this verifies
    ALL of:
      - the Credential Providers registration exists,
      - the COM CLSID InprocServer32 points at the expected DLL path,
      - the DLL is present at that path,
      - the DLL's file version matches the expected version,
      - the DLL is Authenticode-valid (unless -AllowUnsigned),
      - the versioned sentinel matches the expected version,
      - the kill switch is NOT engaged.

    Intune detection contract: exit 0 AND write a line to STDOUT => detected.
    Anything else => not detected (Intune will (re)install).

.PARAMETER AllowUnsigned
    Treat an unsigned/invalid DLL signature as acceptable. VM TESTING ONLY, to
    match an install performed with the installer's -AllowUnsigned.
#>
[CmdletBinding()]
param(
    [switch]$AllowUnsigned
)

if ($env:PROCESSOR_ARCHITEW6432 -eq 'AMD64' -and -not [Environment]::Is64BitProcess) {
    $sysnative = Join-Path $env:WINDIR 'SysNative\WindowsPowerShell\v1.0\powershell.exe'
    if (Test-Path $sysnative) {
        & $sysnative -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath @args
        exit $LASTEXITCODE
    }
}

$ErrorActionPreference = 'SilentlyContinue'

# --- Configuration (keep in sync across all deployment scripts) ---------------
$CLSID           = '{AF63107A-B6A3-4A8D-A967-4D1F8339161C}'
$DllName         = 'LibGuestCredentialProvider.dll'
$ExpectedVersion = '0.1.0.0'
$InstallDir      = Join-Path $env:ProgramFiles 'UMD Libraries\LibGuestCredentialProvider'
$SentinelKey     = 'HKLM:\SOFTWARE\UMD Libraries\LibGuestCredentialProvider'
$InprocKey       = "HKLM:\SOFTWARE\Classes\CLSID\$CLSID\InprocServer32"
$CpKey           = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\$CLSID"

function NotDetected {
    param([string]$Reason)
    # No STDOUT on the "detected" channel; a non-zero exit keeps it unambiguous.
    Write-Verbose "Not detected: $Reason"
    exit 1
}

# Credential Providers registration.
if (-not (Test-Path $CpKey)) { NotDetected "Credential Providers key missing" }

# COM CLSID InprocServer32 -> expected DLL path.
$destDll = Join-Path $InstallDir $DllName
$inproc = (Get-ItemProperty -Path $InprocKey -Name '(default)').'(default)'
if ($inproc -ne $destDll) { NotDetected "InprocServer32 '$inproc' != '$destDll'" }

# DLL present.
if (-not (Test-Path $destDll)) { NotDetected "DLL missing at $destDll" }

# File version.
$fileVersion = (Get-Item $destDll).VersionInfo.FileVersion
if ($fileVersion -and $ExpectedVersion) {
    # Compare on the leading dotted-quad; FileVersion strings can vary in format.
    if (($fileVersion -replace '[^0-9.]', '') -notlike "$ExpectedVersion*") {
        NotDetected "DLL FileVersion '$fileVersion' != expected '$ExpectedVersion'"
    }
}

# Signature.
if (-not $AllowUnsigned) {
    $sig = Get-AuthenticodeSignature -FilePath $destDll
    if ($sig.Status -ne 'Valid') { NotDetected "DLL signature status '$($sig.Status)'" }
}

# Sentinel version.
$sentinelVer = (Get-ItemProperty -Path $SentinelKey -Name 'Version').Version
if ($sentinelVer -ne $ExpectedVersion) { NotDetected "Sentinel version '$sentinelVer' != '$ExpectedVersion'" }

# Kill switch must not be engaged.
$kill = (Get-ItemProperty -Path $SentinelKey -Name 'KillSwitch').KillSwitch
if ($kill -eq 1) { NotDetected "Kill switch engaged" }

# All checks passed.
Write-Output "LibGuestCredentialProvider $ExpectedVersion detected and healthy."
exit 0
