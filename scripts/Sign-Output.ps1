<#
.SYNOPSIS
    Authenticode-signs the built LibGuestCredentialProvider.dll.

.DESCRIPTION
    Signing placeholder for the scaffolding phase. When UMD's code-signing
    certificate is available, pass its thumbprint (certificate store) or a
    .pfx path. With neither parameter supplied, the script reports that
    signing was skipped and exits 0 so local/CI builds are not blocked before
    a real certificate exists.

    Production requirement (README.md, "Security boundaries"): the DLL and all
    deployment scripts must be Authenticode-signed before any deployment.

.PARAMETER DllPath
    Path to the DLL to sign. Defaults to the x64 Release output.

.PARAMETER CertificateThumbprint
    Thumbprint of a code-signing certificate in the CurrentUser or
    LocalMachine "My" store.

.PARAMETER PfxPath
    Path to a .pfx file containing the code-signing certificate. Prompts
    signtool for the password unless PfxPassword is provided.

.PARAMETER PfxPassword
    Password for the .pfx as a SecureString.

.PARAMETER TimestampUrl
    RFC 3161 timestamp server. Defaults to DigiCert's public server.

.EXAMPLE
    .\Sign-Output.ps1
    # -> "No signing certificate configured - skipping." (exit 0)

.EXAMPLE
    .\Sign-Output.ps1 -CertificateThumbprint 0123456789ABCDEF...
#>
[CmdletBinding()]
param(
    [string]$DllPath,
    [string]$CertificateThumbprint,
    [string]$PfxPath,
    [securestring]$PfxPassword,
    [string]$TimestampUrl = 'http://timestamp.digicert.com'
)

$ErrorActionPreference = 'Stop'

# $PSScriptRoot is not available in param() defaults under Windows PowerShell
# 5.1 when invoked with -File, so resolve the default here.
if (-not $DllPath) {
    $DllPath = Join-Path $PSScriptRoot '..\x64\Release\LibGuestCredentialProvider.dll'
}

if (-not $CertificateThumbprint -and -not $PfxPath) {
    Write-Host 'No signing certificate configured - skipping Authenticode signing.'
    Write-Host 'Provide -CertificateThumbprint or -PfxPath once a code-signing certificate is issued.'
    Write-Host 'REMINDER: unsigned builds are for disposable-VM testing only; never deploy unsigned.'
    exit 0
}

if (-not (Test-Path -LiteralPath $DllPath)) {
    Write-Error "DLL not found: $DllPath. Build the x64 Release configuration first."
}
$DllPath = (Resolve-Path -LiteralPath $DllPath).Path

# Locate signtool.exe from the Windows SDK.
$signtool = Get-Command signtool.exe -ErrorAction SilentlyContinue
if ($signtool) {
    $signtoolPath = $signtool.Source
} else {
    $sdkBin = 'C:\Program Files (x86)\Windows Kits\10\bin'
    $candidates = Get-ChildItem -Path $sdkBin -Directory -Filter '10.*' -ErrorAction SilentlyContinue |
        Sort-Object Name -Descending |
        ForEach-Object { Join-Path $_.FullName 'x64\signtool.exe' } |
        Where-Object { Test-Path $_ }
    if (-not $candidates) {
        Write-Error 'signtool.exe not found. Install the Windows SDK signing tools.'
    }
    $signtoolPath = $candidates | Select-Object -First 1
}

$signArgs = @('sign', '/fd', 'SHA256', '/td', 'SHA256', '/tr', $TimestampUrl)
if ($CertificateThumbprint) {
    $signArgs += @('/sha1', $CertificateThumbprint)
} else {
    $signArgs += @('/f', $PfxPath)
    if ($PfxPassword) {
        $plain = [Runtime.InteropServices.Marshal]::PtrToStringUni(
            [Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocUnicode($PfxPassword))
        $signArgs += @('/p', $plain)
    }
}
$signArgs += $DllPath

& $signtoolPath @signArgs
if ($LASTEXITCODE -ne 0) {
    Write-Error "signtool sign failed with exit code $LASTEXITCODE."
}

& $signtoolPath verify /pa $DllPath
if ($LASTEXITCODE -ne 0) {
    Write-Error "signtool verify failed with exit code $LASTEXITCODE."
}

Write-Host "Signed and verified: $DllPath"
