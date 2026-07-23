// LibGuest Credential Provider - COM DLL entry points and class factory.
//
// Plain C++ COM following Microsoft's credential-provider sample pattern (no
// ATL). LogonUI instantiates CLSID_LibGuestCredentialProvider through
// DllGetClassObject.

#include "common.h"

// This translation unit is the single place the project's GUIDs are *defined*;
// every other file that includes Guid.h just gets declarations.
#include <initguid.h>
#include "Guid.h"

#include "LibGuestProvider.h"

#include <new>

// Module-wide object count. Every provider and credential object bumps this in
// its constructor and drops it in its destructor so DllCanUnloadNow is honest.
static LONG g_cRef = 0;

void DllAddRef()
{
    InterlockedIncrement(&g_cRef);
}

void DllRelease()
{
    InterlockedDecrement(&g_cRef);
}

// ---------------------------------------------------------------------------
// Class factory
// ---------------------------------------------------------------------------

class CLibGuestClassFactory : public IClassFactory
{
public:
    CLibGuestClassFactory() : _cRef(1) { DllAddRef(); }

    IFACEMETHODIMP_(ULONG) AddRef()
    {
        return InterlockedIncrement(&_cRef);
    }

    IFACEMETHODIMP_(ULONG) Release()
    {
        long cRef = InterlockedDecrement(&_cRef);
        if (cRef == 0)
        {
            delete this;
        }
        return static_cast<ULONG>(cRef);
    }

    IFACEMETHODIMP QueryInterface(_In_ REFIID riid, _COM_Outptr_ void** ppv)
    {
        if (ppv == nullptr)
        {
            return E_POINTER;
        }
        if (riid == IID_IUnknown || riid == IID_IClassFactory)
        {
            *ppv = static_cast<IClassFactory*>(this);
            AddRef();
            return S_OK;
        }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }

    IFACEMETHODIMP CreateInstance(_In_opt_ IUnknown* pUnkOuter, _In_ REFIID riid,
                                  _COM_Outptr_ void** ppv)
    {
        *ppv = nullptr;
        if (pUnkOuter != nullptr)
        {
            return CLASS_E_NOAGGREGATION;
        }
        return CLibGuestProvider::CreateInstance(riid, ppv);
    }

    IFACEMETHODIMP LockServer(BOOL fLock)
    {
        if (fLock)
        {
            DllAddRef();
        }
        else
        {
            DllRelease();
        }
        return S_OK;
    }

private:
    ~CLibGuestClassFactory() { DllRelease(); }

    long _cRef;
};

// ---------------------------------------------------------------------------
// DLL entry points
// ---------------------------------------------------------------------------

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
STDAPI DllGetClassObject(_In_ REFCLSID rclsid, _In_ REFIID riid, _Outptr_ void** ppv)
{
    if (ppv == nullptr)
    {
        return E_POINTER;
    }
    *ppv = nullptr;

    if (rclsid != CLSID_LibGuestCredentialProvider)
    {
        return CLASS_E_CLASSNOTAVAILABLE;
    }

    CLibGuestClassFactory* pFactory = new (std::nothrow) CLibGuestClassFactory();
    if (pFactory == nullptr)
    {
        return E_OUTOFMEMORY;
    }

    HRESULT hr = pFactory->QueryInterface(riid, ppv);
    pFactory->Release();
    return hr;
}

STDAPI DllRegisterServer()
{
    // Intentionally not implemented. Registration is performed by the signed
    // Intune installer script, explicitly and idempotently, not by regsvr32
    // (README.md, "Registry registration model").
    return E_NOTIMPL;
}

STDAPI DllUnregisterServer()
{
    // See DllRegisterServer. The uninstaller/kill switch owns removal, and it
    // must remove the Credential Providers registration before the CLSID.
    return E_NOTIMPL;
}
