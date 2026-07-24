# LibGuest Credential Provider — Deployment Package

Scripts to install, detect, uninstall, and remotely kill the LibGuest credential
provider via Intune. See the repo-root `README.md` ("Intune deployment design"
and "Recovery and kill-switch plan") for the design these implement, and
`docs/Secure-Desktop-Test-Plan.md` for the on-VM validation that must pass first.

> [!WARNING]
> Do not package or deploy until the provider has authenticated at the secure
> desktop on an Entra-only VM and the kill switch has been proven there. Deploying
> a secure-desktop DLL to a fleet before that can lock every target machine out of
> sign-in at once.

## Contents

```
CredentialProvider/
├── Install-LibGuestCredentialProvider.ps1     Intune install command
├── Uninstall-LibGuestCredentialProvider.ps1   Intune uninstall command + kill switch
├── Detect-LibGuestCredentialProvider.ps1      Intune Win32 detection rule
├── LibGuestCredentialProvider.dll             <-- COPY IN before packaging (signed)
└── KillSwitch/
    ├── Detect-KillSwitch.ps1                   Intune Remediation: detection
    └── Remediate-KillSwitch.ps1                Intune Remediation: remediation
```

`LibGuestCredentialProvider.dll` is **not** committed (build output, gitignored).
Copy the **signed** Release DLL here before building the `.intunewin`.

## Shared configuration

All scripts hardcode the same values (kept in sync by hand — each is standalone
because Intune runs them as independent processes):

| | |
|---|---|
| CLSID | `{AF63107A-B6A3-4A8D-A967-4D1F8339161C}` |
| Install dir | `C:\Program Files\UMD Libraries\LibGuestCredentialProvider\` |
| Sentinel | `HKLM\SOFTWARE\UMD Libraries\LibGuestCredentialProvider` |
| Version | `0.1.0.0` (matches the DLL `.rc`) |
| Log | `C:\ProgramData\LibGuestCredentialProvider\install.log` |

Before a real (signed) deployment, set `$ExpectedPublisher` in
`Install-LibGuestCredentialProvider.ps1` to UMD Libraries' code-signing subject.
While it is empty, the installer verifies signature *validity* but not publisher
identity.

## Building the `.intunewin`

1. Copy the signed `LibGuestCredentialProvider.dll` into this folder.
2. Run Microsoft's Win32 Content Prep Tool:
   ```
   IntuneWinAppUtil.exe -c <this folder> -s Install-LibGuestCredentialProvider.ps1 -o <output folder>
   ```

## Intune Win32 app settings

- **Install command:**
  `powershell.exe -NoProfile -ExecutionPolicy Bypass -File Install-LibGuestCredentialProvider.ps1`
- **Uninstall command:**
  `powershell.exe -NoProfile -ExecutionPolicy Bypass -File Uninstall-LibGuestCredentialProvider.ps1`
- **Install behavior:** System
- **Detection rule:** Custom script → `Detect-LibGuestCredentialProvider.ps1`
- **Run script in 64-bit:** not required (scripts self-relaunch 64-bit), but fine
  to enable.

Assign only to a **dedicated test-device group with no production public PCs**.

## Kill switch — two independent paths

1. **Immediate uninstall assignment.** Create a second assignment of this same
   app set to *uninstall*, ready to activate. Fast, but only as fast as the app
   sync reaches each device.

2. **Remediation (fastest fleet-wide off switch).** Package `KillSwitch/` as an
   Intune Remediation (detection = `Detect-KillSwitch.ps1`, remediation =
   `Remediate-KillSwitch.ps1`), run as SYSTEM, in 64-bit, on a frequent schedule.
   To fire it, set on the target machines (via a config profile / script / GPO):
   ```
   HKLM\SOFTWARE\UMD Libraries\LibGuestCredentialProvider
       KillSwitch (DWORD) = 1
   ```
   Every machine unregisters the provider on its next Remediation cycle.

Removal always happens **registration-first** (Credential Providers key, then
CLSID, then DLL) so LogonUI stops loading the provider even if a later step fails.

## Local testing on the VM (no Intune)

```powershell
# Install (unsigned DLL on a WDAC-disabled VM):
.\Install-LibGuestCredentialProvider.ps1 -AllowUnsigned

# Detect:
.\Detect-LibGuestCredentialProvider.ps1 -AllowUnsigned; "exit=$LASTEXITCODE"

# Remove / kill:
.\Uninstall-LibGuestCredentialProvider.ps1
```

Registration changes take effect at the next sign-out/reboot. Recovery if a build
wedges the lock screen is in `docs/Secure-Desktop-Test-Plan.md`, Phase 6.
