# Secure-Desktop Test Plan — LibGuest Credential Provider

> [!WARNING]
> This DLL is loaded by **LogonUI on the secure desktop**. A defect can lock
> every user and administrator out of sign-in. Every step below runs on a
> **disposable, snapshotted Entra-only VM** — never on a physical or production
> device until this plan has fully passed and the kill switch has been proven.

## What this plan does and does not cover

This walks through the next milestone after the bench validation already
completed: **register the provider with LogonUI on an Entra-only VM and find out
whether the credential reaches our tile or is intercepted by Entra (CloudAP).**

Already proven on the bench (AD-joined workstation, `LsaLogonUser`, no secure
desktop): the serialization is correct, the UPN principal form
(`libguest115@UMD.EDU`) authenticates, and the resulting token is the local
`libguestN` account. See `harness-output.txt` history and `common.h` dial 2.

**Still unproven, and the entire point of this plan:**
1. Does LogonUI load our DLL and render the tile on an Entra-only device?
2. Does the credential reach our provider, or does CloudAP's typed-UPN discovery
   claim `@umd.edu` and route it to Entra first? (The working principal form is a
   parseable UPN — exactly what CloudAP keys on.)
3. Does the kill switch reliably disable the provider?

## Reference values

| Item | Value |
|---|---|
| Provider CLSID | `{AF63107A-B6A3-4A8D-A967-4D1F8339161C}` |
| Install directory | `C:\Program Files\UMD Libraries\LibGuestCredentialProvider\` |
| DLL name | `LibGuestCredentialProvider.dll` |
| Realm | `UMD.EDU` (MIT — KDCs `pestilence` / `famine` / `war` `.umd.edu:88`) |
| Test account | `libguest115` (or any `1`–`500`) with a live SIMS password |

---

## Phase 0 — Recovery must exist BEFORE the provider is registered

Do not skip. If the provider wedges the lock screen, these are your only ways
back in. Prove each one works **before** Phase 3.

- [ ] **VM snapshot taken while signed out at the lock screen** (not signed in —
      you want to restore to the exact state you're testing). Name it e.g.
      `pre-provider-registration`.
- [ ] **A second working sign-in path confirmed**: a local administrator account
      with a known password, or a LAPS-managed admin. Test that it signs in now.
- [ ] **A Microsoft recovery provider stays visible** (password / PIN tile). This
      provider is additive; it must never hide the built-in tiles.
- [ ] **Console/RDP access to the VM confirmed** independent of the lock screen.
- [ ] **The offline registry-removal procedure rehearsed once** (Phase 6 below),
      so you know it works before you need it under pressure.
- [ ] If the VM uses BitLocker: **recovery key in hand.**

**Do not proceed to Phase 1 until every box above is checked.**

---

## Phase 1 — Stage artifacts on the VM

Copy from the bench build output (`x64\Release\`) to the VM. Both files; the
harness is used for on-VM validation in Phase 2, it is **not** part of any
eventual fleet package.

- [ ] `LibGuestCredentialProvider.dll` → `C:\Temp\` (for now)
- [ ] `LibGuestTestHarness.exe` → `C:\Temp\`
- [ ] PsExec available on the VM (`winget install Microsoft.Sysinternals.PsTools`)

> The Release DLL is currently **unsigned**. That is acceptable on a VM with
> WDAC/App Control **disabled**. If the VM enforces App Control or runs
> CrowdStrike, an unsigned DLL will likely be blocked from loading into LogonUI —
> sign it first (`scripts\Sign-Output.ps1`) or disable enforcement for this test.

---

## Phase 2 — Re-prove the buffer ON the Entra-only VM (before touching LogonUI)

The bench result was on an AD-joined box. Confirm the same buffer authenticates
here first — if it doesn't, registering with LogonUI is pointless.

### 2a. Confirm realm reachability

```powershell
ksetup                                              # is UMD.EDU a known realm?
Resolve-DnsName -Type SRV _kerberos._tcp.UMD.EDU    # do the KDCs resolve?
```

If `UMD.EDU` is not configured, add it (elevated), then **reboot**:

```cmd
ksetup /addkdc UMD.EDU pestilence.umd.edu
ksetup /addkdc UMD.EDU famine.umd.edu
ksetup /addkdc UMD.EDU war.umd.edu
```

### 2b. Sanity-check the credential with runas (normal prompt)

```cmd
runas /user:libguest115@UMD.EDU cmd.exe
```

In the spawned window: `klist` should show `krbtgt/UMD.EDU@UMD.EDU`, `Kdc Called:`
one of pestilence/famine/war. `whoami` should show the **local** `libguest115`.

### 2c. Run the harness as SYSTEM (the real buffer test)

Elevated PowerShell:

```powershell
$pwFile = "C:\Temp\pw.tmp"
Set-Content -Path $pwFile -Value '<SIMS-PASSWORD>' -Encoding utf8 -NoNewline

& 'C:\path\to\PsExec64.exe' -accepteula -nobanner -s `
  C:\Temp\LibGuestTestHarness.exe --probe --logon --guest 115 --password-file $pwFile `
  *> C:\Temp\harness-output.txt

Remove-Item $pwFile -Force
```

**Pass criteria** (in `harness-output.txt`):
- `LsaLogonUser SUCCEEDED -- LSA accepted the serialization`
- `Token identity: <VM-NAME>\libguest115`
- `All checks passed.`

**If this fails here**, stop — fix realm/mapping/credential before LogonUI. Do not
register a provider whose buffer doesn't authenticate on this device.

> Delete the SIMS password file immediately (the command above does). Rotate the
> test account password after testing.

---

## Phase 3 — Register the provider with LogonUI

Snapshot is taken (Phase 0), buffer proven on this VM (Phase 2). Now install.

### 3a. Place the DLL in its protected location

```powershell
New-Item -ItemType Directory -Force "C:\Program Files\UMD Libraries\LibGuestCredentialProvider"
Copy-Item C:\Temp\LibGuestCredentialProvider.dll `
  "C:\Program Files\UMD Libraries\LibGuestCredentialProvider\"
```

### 3b. Write the registration (elevated cmd)

```cmd
reg add "HKLM\SOFTWARE\Classes\CLSID\{AF63107A-B6A3-4A8D-A967-4D1F8339161C}\InprocServer32" /ve /t REG_SZ /d "C:\Program Files\UMD Libraries\LibGuestCredentialProvider\LibGuestCredentialProvider.dll" /f

reg add "HKLM\SOFTWARE\Classes\CLSID\{AF63107A-B6A3-4A8D-A967-4D1F8339161C}\InprocServer32" /v ThreadingModel /t REG_SZ /d "Apartment" /f

reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{AF63107A-B6A3-4A8D-A967-4D1F8339161C}" /ve /t REG_SZ /d "LibGuest Credential Provider" /f
```

### 3c. Get a fresh LogonUI

Sign out (Start → account → Sign out), or reboot for certainty. Signing out is
enough for LogonUI to reload providers, and keeps your admin session available.

---

## Phase 4 — The actual experiment, at the secure desktop

At the lock screen, work through these in order. Record each outcome.

- [ ] **The Microsoft password/PIN tile is still present.** (If not — recovery
      providers were hidden; abort to Phase 6, this is a bug.)
- [ ] **The "Library Guest Sign-In" tile appears.** (If not — the DLL failed to
      load. Check `Event Viewer → Windows Logs → Application/System`. This is a
      loading problem, not a routing problem.)
- [ ] **Select the tile, enter guest number `115` and the SIMS password, submit.**
- [ ] **Observe the outcome:**
  - **Signs into a local `libguest115` desktop** → the premise holds end-to-end.
    Verify in the session: `whoami` = `<VM>\libguest115`, and Task Manager shows
    explorer.exe owned by that account. **This is the success milestone.**
  - **Generic "sign-in failed"** → the credential reached our provider but LSA/KDC
    rejected it. Compare against the Phase 2 result; likely realm/network.
  - **The credential gets routed to Entra / an Entra error / a redirect** → this
    is the CloudAP interception the whole project is about. The provider works but
    LogonUI handed the typed UPN to Entra first. Record exactly what appeared.

- [ ] **Test the failure paths** (each should return to the tile without hanging
      LogonUI): wrong password, guest number `0` and `501`, and — if feasible —
      network disconnected.

> Whatever happens, the lock screen must never hang. If it does, that is itself a
> finding; use Phase 6 to recover.

---

## Phase 5 — Kill switch (prove you can turn it off)

Before trusting this provider at all, prove the online removal works.

### 5a. Registration-first removal (elevated cmd)

Order matters: remove the Credential Providers key **first** so no future LogonUI
loads the DLL, then the CLSID.

```cmd
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{AF63107A-B6A3-4A8D-A967-4D1F8339161C}" /f

reg delete "HKLM\SOFTWARE\Classes\CLSID\{AF63107A-B6A3-4A8D-A967-4D1F8339161C}" /f
```

### 5b. Confirm

- [ ] Sign out / reboot. The Library Guest tile is **gone**.
- [ ] The built-in tiles still work.
- [ ] (Optional) Remove the DLL from `C:\Program Files\UMD Libraries\...` only
      after the registration is gone.

---

## Phase 6 — Offline recovery (rehearse in Phase 0; use if wedged)

If the lock screen is unusable and you cannot remove the registration online:

1. Boot the VM into **WinRE** (Windows Recovery Environment) →
   Troubleshoot → Advanced options → **Command Prompt**.
2. Find the Windows volume (in WinRE it is often **not** `C:`):
   ```cmd
   diskpart
   list volume
   exit
   ```
   Assume it is `D:` below; substitute the real letter.
3. Load the offline SOFTWARE hive and delete the registration:
   ```cmd
   reg load HKLM\OFFLINE D:\Windows\System32\config\SOFTWARE
   reg delete "HKLM\OFFLINE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{AF63107A-B6A3-4A8D-A967-4D1F8339161C}" /f
   reg delete "HKLM\OFFLINE\Classes\CLSID\{AF63107A-B6A3-4A8D-A967-4D1F8339161C}" /f
   reg unload HKLM\OFFLINE
   ```
4. Reboot normally. The provider is gone.
5. If all else fails: **restore the Phase 0 snapshot.**

---

## Exit criteria for this plan

Record the result of Phase 4 against the README acceptance criteria:

- [ ] A live SIMS credential created a true interactive local `libguestN` session.
- [ ] The session token, shell, and child processes belong to the mapped local
      account.
- [ ] Incorrect credentials failed without falling through to Entra.
- [ ] KDC/network failures returned safely to the tile without hanging LogonUI.
- [ ] Microsoft recovery providers stayed available throughout.
- [ ] The kill switch (Phase 5) reliably disabled the provider.

Only after all of the above pass on the VM does deployment engineering (signing,
install/uninstall/detect scripts, `.intunewin`, a dedicated test-device group
with the kill-switch assignment pre-staged) become the next step.

## After every test run

- Restore the snapshot (or re-run Phase 5 removal) to return the VM to a clean
  state before the next iteration.
- Rotate the SIMS test account password — it passed through test files.
- Never leave a SIMS password file on disk.
