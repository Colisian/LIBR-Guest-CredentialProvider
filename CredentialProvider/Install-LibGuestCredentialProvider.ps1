<#
.SYNOPSIS
    Installs and registers the LibGuest credential provider.

.DESCRIPTION
    Intune Win32 app install command. Runs as SYSTEM. Performs, in order
    (README.md, "Intune deployment design"):
      1. Verify the DLL's Authenticode signature and expected publisher.
      2. Copy it to the protected installation directory.
      3. Create the COM CLSID registration.
      4. Register the credential provider.
      5. Write a versioned application sentinel.
      6. Log only deployment state (never secrets).

    The DLL does not self-register (DllRegisterServer returns E_NOTIMPL by
    design); this script is the only supported registration path.

.PARAMETER AllowUnsigned
    Skip signature verification. FOR DISPOSABLE VM TESTING ONLY, while no
    code-signing certificate exists. Never pass this in a real deployment;
    an unsigned provider will be blocked by WDAC/App Control on managed devices.

.NOTES
    Credential-provider registrations live in the 64-bit registry view. This
    script relaunches itself under 64-bit PowerShell if Intune started it in a
    32-bit host, so the keys are never written to Wow6432Node by mistake.
#>
[CmdletBinding()]
param(
    [switch]$AllowUnsigned
)

# --- Relaunch in 64-bit PowerShell if we were started 32-bit (Intune default).
if ($env:PROCESSOR_ARCHITEW6432 -eq 'AMD64' -and -not [Environment]::Is64BitProcess) {
    $sysnative = Join-Path $env:WINDIR 'SysNative\WindowsPowerShell\v1.0\powershell.exe'
    if (Test-Path $sysnative) {
        & $sysnative -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath @args
        exit $LASTEXITCODE
    }
}

$ErrorActionPreference = 'Stop'

# --- Configuration (keep in sync across all deployment scripts) ---------------
$CLSID             = '{AF63107A-B6A3-4A8D-A967-4D1F8339161C}'
$ProviderName      = 'LibGuest Credential Provider'
$DllName           = 'LibGuestCredentialProvider.dll'
$ExpectedVersion   = '0.1.0.0'
$InstallDir        = Join-Path $env:ProgramFiles 'UMD Libraries\LibGuestCredentialProvider'
$SentinelKey       = 'HKLM:\SOFTWARE\UMD Libraries\LibGuestCredentialProvider'
$ClsidKey          = "HKLM:\SOFTWARE\Classes\CLSID\$CLSID"
$InprocKey         = "$ClsidKey\InprocServer32"
$CpKey             = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\$CLSID"
$LogDir            = Join-Path $env:ProgramData 'LibGuestCredentialProvider'
$LogPath           = Join-Path $LogDir 'install.log'

# Expected code-signing subject. TODO: set to UMD Libraries' publisher subject
# once the certificate is issued (e.g. 'CN=University of Maryland, O=..., C=US').
# While empty, only signature *validity* is checked, not the publisher identity.
$ExpectedPublisher = ''

# --- Logging (deployment state only) ------------------------------------------
function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $line = '{0} [{1}] {2}' -f (Get-Date -Format 's'), $Level, $Message
    try {
        if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
        Add-Content -Path $LogPath -Value $line -Encoding utf8
    } catch { }
    Write-Host $line
}

function Fail {
    param([string]$Message)
    Write-Log $Message 'ERROR'
    exit 1
}

try {
    Write-Log "Install starting. Target version $ExpectedVersion, CLSID $CLSID."

    $srcDll = Join-Path $PSScriptRoot $DllName
    if (-not (Test-Path $srcDll)) { Fail "DLL not found next to installer: $srcDll" }

    # 1. Signature + publisher verification.
    $sig = Get-AuthenticodeSignature -FilePath $srcDll
    if ($sig.Status -ne 'Valid') {
        if ($AllowUnsigned) {
            Write-Log "Signature status '$($sig.Status)' accepted because -AllowUnsigned was passed. VM TESTING ONLY." 'WARN'
        } else {
            Fail "DLL signature is not valid (status: $($sig.Status)). Refusing to install. Sign the DLL or pass -AllowUnsigned on a test VM."
        }
    } else {
        if ($ExpectedPublisher) {
            $subject = $sig.SignerCertificate.Subject
            if ($subject -ne $ExpectedPublisher) {
                Fail "DLL is signed but by an unexpected publisher: '$subject' (expected '$ExpectedPublisher')."
            }
            Write-Log "Signature valid, publisher matches: $subject"
        } else {
            Write-Log "Signature valid. Publisher check skipped (ExpectedPublisher not configured)." 'WARN'
        }
    }

    # 2. Copy to the protected install directory.
    if (-not (Test-Path $InstallDir)) { New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null }
    $destDll = Join-Path $InstallDir $DllName
    Copy-Item -Path $srcDll -Destination $destDll -Force
    Write-Log "Copied DLL to $destDll"

    # 3. COM CLSID registration.
    #    ThreadingModel = Apartment per README "Registry registration model".
    New-Item -Path $InprocKey -Force | Out-Null
    New-ItemProperty -Path $InprocKey -Name '(default)' -Value $destDll -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $InprocKey -Name 'ThreadingModel' -Value 'Apartment' -PropertyType String -Force | Out-Null
    # A friendly name on the CLSID key itself (cosmetic).
    New-ItemProperty -Path $ClsidKey -Name '(default)' -Value $ProviderName -PropertyType String -Force | Out-Null
    Write-Log "Wrote COM CLSID registration at $ClsidKey"

    # 4. Register the credential provider (this is what makes LogonUI load it).
    #    Written LAST so a partially-registered CLSID is never advertised to
    #    LogonUI. Removal (uninstall/kill) reverses this order.
    New-Item -Path $CpKey -Force | Out-Null
    New-ItemProperty -Path $CpKey -Name '(default)' -Value $ProviderName -PropertyType String -Force | Out-Null
    Write-Log "Registered credential provider at $CpKey"

    # 5. Versioned application sentinel.
    $fileVersion = (Get-Item $destDll).VersionInfo.FileVersion
    if (-not (Test-Path $SentinelKey)) { New-Item -Path $SentinelKey -Force | Out-Null }
    New-ItemProperty -Path $SentinelKey -Name 'Version'     -Value $ExpectedVersion -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $SentinelKey -Name 'FileVersion' -Value $fileVersion     -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $SentinelKey -Name 'DllPath'     -Value $destDll          -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $SentinelKey -Name 'InstallDate' -Value (Get-Date -Format 's') -PropertyType String -Force | Out-Null
    # KillSwitch defaults to 0; the remediation flips this to trigger removal.
    if ($null -eq (Get-ItemProperty -Path $SentinelKey -Name 'KillSwitch' -ErrorAction SilentlyContinue)) {
        New-ItemProperty -Path $SentinelKey -Name 'KillSwitch' -Value 0 -PropertyType DWord -Force | Out-Null
    }
    Write-Log "Wrote sentinel at $SentinelKey (Version $ExpectedVersion, FileVersion $fileVersion)"

    Write-Log "Install completed successfully."
    exit 0
}
catch {
    Fail "Unhandled error: $($_.Exception.Message)"
}
