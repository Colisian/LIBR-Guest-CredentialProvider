// LibGuest Credential Provider - COM DLL entry points (scaffolding only).
//
// Plain C++ COM boilerplate following Microsoft's credential-provider sample
// pattern (no ATL). No CoClass is implemented or registered yet: Phase 2 (see
// README.md, "Phase 2 - Diagnostic provider") adds the provider class and its
// class factory. Until then DllGetClassObject reports no available class and
// self-registration is intentionally not implemented, so this DLL cannot be
// accidentally registered as a credential provider while it serves nothing.

#include "targetver.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <objbase.h>
#include <initguid.h> // must precede Guid.h so DEFINE_GUID emits definitions
#include "Guid.h"

// Module-wide object/lock count. Phase 2's credential provider, credential,
// and class-factory objects must call DllAddRef/DllRelease in their
// constructors/destructors so DllCanUnloadNow stays accurate.
static LONG g_cRef = 0;

void DllAddRef()
{
    InterlockedIncrement(&g_cRef);
}

void DllRelease()
{
    InterlockedDecrement(&g_cRef);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID /*lpReserved*/)
{
    switch (dwReason)
    {
    case DLL_PROCESS_ATTACH:
        // This DLL is loaded by LogonUI; keep attach work minimal and never
        // fail here for non-fatal reasons.
        DisableThreadLibraryCalls(hModule);
        break;
    case DLL_PROCESS_DETACH:
        break;
    default:
        break;
    }
    return TRUE;
}

__control_entrypoint(DllExport)
STDAPI DllCanUnloadNow()
{
    return (g_cRef > 0) ? S_FALSE : S_OK;
}

_Check_return_
STDAPI DllGetClassObject(_In_ REFCLSID rclsid, _In_ REFIID /*riid*/, _Outptr_ void** ppv)
{
    if (ppv == nullptr)
    {
        return E_POINTER;
    }
    *ppv = nullptr;

    // Phase 2: when rclsid == CLSID_LibGuestCredentialProvider, return the
    // provider's class factory here.
    UNREFERENCED_PARAMETER(rclsid);
    return CLASS_E_CLASSNOTAVAILABLE;
}

STDAPI DllRegisterServer()
{
    // Intentionally not implemented while no CoClass exists. Production
    // registration is performed by the signed Intune installer script (see
    // README.md, "Registry registration model"), not by regsvr32.
    return E_NOTIMPL;
}

STDAPI DllUnregisterServer()
{
    // See DllRegisterServer. The uninstaller/kill switch owns removal.
    return E_NOTIMPL;
}
