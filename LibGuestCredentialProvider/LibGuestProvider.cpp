#include "LibGuestProvider.h"

#include <new>
#include <shlwapi.h>

CLibGuestProvider::CLibGuestProvider()
    : _cRef(1)
    , _cpus(CPUS_INVALID)
    , _fScenarioSupported(false)
    , _pCredential(nullptr)
{
    DllAddRef();
}

CLibGuestProvider::~CLibGuestProvider()
{
    ReleaseCredential();
    DllRelease();
}

void CLibGuestProvider::ReleaseCredential()
{
    if (_pCredential != nullptr)
    {
        _pCredential->Release();
        _pCredential = nullptr;
    }
}

HRESULT CLibGuestProvider::CreateInstance(_In_ REFIID riid, _COM_Outptr_ void** ppv)
{
    *ppv = nullptr;

    CLibGuestProvider* pProvider = new (std::nothrow) CLibGuestProvider();
    if (pProvider == nullptr)
    {
        return E_OUTOFMEMORY;
    }

    HRESULT hr = pProvider->QueryInterface(riid, ppv);
    pProvider->Release();
    return hr;
}

// ---------------------------------------------------------------------------
// IUnknown
// ---------------------------------------------------------------------------

IFACEMETHODIMP_(ULONG) CLibGuestProvider::AddRef()
{
    return InterlockedIncrement(&_cRef);
}

IFACEMETHODIMP_(ULONG) CLibGuestProvider::Release()
{
    long cRef = InterlockedDecrement(&_cRef);
    if (cRef == 0)
    {
        delete this;
    }
    return static_cast<ULONG>(cRef);
}

IFACEMETHODIMP CLibGuestProvider::QueryInterface(_In_ REFIID riid, _COM_Outptr_ void** ppv)
{
    if (ppv == nullptr)
    {
        return E_POINTER;
    }

    if (riid == IID_IUnknown || riid == IID_ICredentialProvider)
    {
        *ppv = static_cast<ICredentialProvider*>(this);
        AddRef();
        return S_OK;
    }

    *ppv = nullptr;
    return E_NOINTERFACE;
}

// ---------------------------------------------------------------------------
// ICredentialProvider
// ---------------------------------------------------------------------------

IFACEMETHODIMP CLibGuestProvider::SetUsageScenario(
    CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, DWORD /*dwFlags*/)
{
    switch (cpus)
    {
    case CPUS_LOGON:
    case CPUS_UNLOCK_WORKSTATION:
        // Modern Windows often routes unlock through the logon flow, but the
        // provider must answer whatever scenario Windows actually sends
        // (README.md, "Provider responsibilities"). The credential adjusts the
        // KERB message type to match.
        _cpus = cpus;
        _fScenarioSupported = true;

        ReleaseCredential();
        return CLibGuestCredential::CreateInstance(cpus, &_pCredential);

    case CPUS_CHANGE_PASSWORD:
    case CPUS_CREDUI:
    case CPUS_PLAP:
        // Intentionally unsupported during the prototype. E_NOTIMPL is the
        // correct way to tell Windows this provider has nothing to offer here;
        // it does not affect the scenarios above.
        _fScenarioSupported = false;
        return E_NOTIMPL;

    default:
        _fScenarioSupported = false;
        return E_INVALIDARG;
    }
}

IFACEMETHODIMP CLibGuestProvider::SetSerialization(
    _In_ const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* /*pcpcs*/)
{
    // This provider never accepts inbound serialized credentials.
    return E_NOTIMPL;
}

IFACEMETHODIMP CLibGuestProvider::Advise(
    _In_ ICredentialProviderEvents* /*pcpe*/, UINT_PTR /*upAdviseContext*/)
{
    // The tile set is static, so there is never anything to notify LogonUI
    // about. Returning S_OK (rather than E_NOTIMPL) keeps LogonUI's bookkeeping
    // simple and costs nothing.
    return S_OK;
}

IFACEMETHODIMP CLibGuestProvider::UnAdvise()
{
    return S_OK;
}

IFACEMETHODIMP CLibGuestProvider::GetFieldDescriptorCount(_Out_ DWORD* pdwCount)
{
    *pdwCount = LGFI_NUM_FIELDS;
    return S_OK;
}

IFACEMETHODIMP CLibGuestProvider::GetFieldDescriptorAt(
    DWORD dwIndex, _Outptr_result_nullonfailure_ CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd)
{
    *ppcpfd = nullptr;
    if (dwIndex >= LGFI_NUM_FIELDS)
    {
        return E_INVALIDARG;
    }

    // LogonUI takes ownership of the copy and frees it with CoTaskMemFree.
    CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* pcpfd =
        static_cast<CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR*>(
            CoTaskMemAlloc(sizeof(CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR)));
    if (pcpfd == nullptr)
    {
        return E_OUTOFMEMORY;
    }

    const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR& rcpfd = s_rgLibGuestFieldDescriptors[dwIndex];
    pcpfd->dwFieldID = rcpfd.dwFieldID;
    pcpfd->cpft = rcpfd.cpft;
    pcpfd->guidFieldType = rcpfd.guidFieldType;
    pcpfd->pszLabel = nullptr;

    HRESULT hr = SHStrDupW(rcpfd.pszLabel ? rcpfd.pszLabel : L"", &pcpfd->pszLabel);
    if (FAILED(hr))
    {
        CoTaskMemFree(pcpfd);
        return hr;
    }

    *ppcpfd = pcpfd;
    return S_OK;
}

IFACEMETHODIMP CLibGuestProvider::GetCredentialCount(
    _Out_ DWORD* pdwCount, _Out_ DWORD* pdwDefault, _Out_ BOOL* pbAutoLogonWithDefault)
{
    *pdwCount = 0;
    *pdwDefault = CREDENTIAL_PROVIDER_NO_DEFAULT;
    *pbAutoLogonWithDefault = FALSE;

    if (!_fScenarioSupported || _pCredential == nullptr)
    {
        return S_OK;
    }

    *pdwCount = 1;

    // Deliberately not the default tile: the built-in providers must stay in
    // front so recovery is never more than one click away, and never auto-logon.
    return S_OK;
}

IFACEMETHODIMP CLibGuestProvider::GetCredentialAt(
    DWORD dwIndex, _Outptr_result_nullonfailure_ ICredentialProviderCredential** ppcpc)
{
    *ppcpc = nullptr;
    if (dwIndex != 0 || _pCredential == nullptr)
    {
        return E_INVALIDARG;
    }
    return _pCredential->QueryInterface(IID_ICredentialProviderCredential,
                                        reinterpret_cast<void**>(ppcpc));
}
