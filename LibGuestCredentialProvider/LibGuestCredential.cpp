#include "LibGuestCredential.h"
#include "GuestAccount.h"
#include "KerbSerialize.h"
#include "Guid.h"

#include <new>
#include <strsafe.h>
#include <shlwapi.h>

#pragma comment(lib, "Shlwapi.lib")

CLibGuestCredential::CLibGuestCredential()
    : _cRef(1)
    , _cpus(CPUS_LOGON)
    , _pcpce(nullptr)
{
    DllAddRef();
    _szGuestNumber[0] = L'\0';
    _szPassword[0] = L'\0';
    _szStatus[0] = L'\0';
}

CLibGuestCredential::~CLibGuestCredential()
{
    ClearAllFields();
    if (_pcpce != nullptr)
    {
        _pcpce->Release();
        _pcpce = nullptr;
    }
    DllRelease();
}

HRESULT CLibGuestCredential::CreateInstance(
    CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
    _Outptr_ CLibGuestCredential** ppCredential)
{
    *ppCredential = nullptr;

    CLibGuestCredential* pCredential = new (std::nothrow) CLibGuestCredential();
    if (pCredential == nullptr)
    {
        return E_OUTOFMEMORY;
    }

    HRESULT hr = pCredential->Initialize(cpus);
    if (SUCCEEDED(hr))
    {
        *ppCredential = pCredential;
    }
    else
    {
        pCredential->Release();
    }
    return hr;
}

HRESULT CLibGuestCredential::Initialize(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus)
{
    _cpus = cpus;
    return S_OK;
}

void CLibGuestCredential::ClearPassword()
{
    SecureZeroMemory(_szPassword, sizeof(_szPassword));
}

void CLibGuestCredential::ClearAllFields()
{
    ClearPassword();
    SecureZeroMemory(_szGuestNumber, sizeof(_szGuestNumber));
    SecureZeroMemory(_szStatus, sizeof(_szStatus));
}

// ---------------------------------------------------------------------------
// IUnknown
// ---------------------------------------------------------------------------

IFACEMETHODIMP_(ULONG) CLibGuestCredential::AddRef()
{
    return InterlockedIncrement(&_cRef);
}

IFACEMETHODIMP_(ULONG) CLibGuestCredential::Release()
{
    long cRef = InterlockedDecrement(&_cRef);
    if (cRef == 0)
    {
        delete this;
    }
    return static_cast<ULONG>(cRef);
}

IFACEMETHODIMP CLibGuestCredential::QueryInterface(_In_ REFIID riid, _COM_Outptr_ void** ppv)
{
    if (ppv == nullptr)
    {
        return E_POINTER;
    }

    if (riid == IID_IUnknown ||
        riid == IID_ICredentialProviderCredential ||
        riid == IID_ICredentialProviderCredential2)
    {
        *ppv = static_cast<ICredentialProviderCredential2*>(this);
        AddRef();
        return S_OK;
    }

    *ppv = nullptr;
    return E_NOINTERFACE;
}

// ---------------------------------------------------------------------------
// ICredentialProviderCredential
// ---------------------------------------------------------------------------

IFACEMETHODIMP CLibGuestCredential::Advise(_In_ ICredentialProviderCredentialEvents* pcpce)
{
    if (_pcpce != nullptr)
    {
        _pcpce->Release();
        _pcpce = nullptr;
    }
    if (pcpce != nullptr)
    {
        _pcpce = pcpce;
        _pcpce->AddRef();

        // Place the submit button next to the password field.
        _pcpce->SetFieldSubmitButton(this, LGFI_SUBMIT_BUTTON, LGFI_PASSWORD);
    }
    return S_OK;
}

IFACEMETHODIMP CLibGuestCredential::UnAdvise()
{
    if (_pcpce != nullptr)
    {
        _pcpce->Release();
        _pcpce = nullptr;
    }
    return S_OK;
}

IFACEMETHODIMP CLibGuestCredential::SetSelected(_Out_ BOOL* pbAutoLogon)
{
    // Never auto-submit; the patron must type a credential.
    *pbAutoLogon = FALSE;
    return S_OK;
}

IFACEMETHODIMP CLibGuestCredential::SetDeselected()
{
    ClearPassword();
    if (_pcpce != nullptr)
    {
        _pcpce->SetFieldString(this, LGFI_PASSWORD, L"");
    }
    return S_OK;
}

IFACEMETHODIMP CLibGuestCredential::GetFieldState(
    DWORD dwFieldID,
    _Out_ CREDENTIAL_PROVIDER_FIELD_STATE* pcpfs,
    _Out_ CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* pcpfis)
{
    if (dwFieldID >= LGFI_NUM_FIELDS)
    {
        return E_INVALIDARG;
    }
    *pcpfs = s_rgLibGuestFieldStates[dwFieldID];
    *pcpfis = s_rgLibGuestFieldInteractiveStates[dwFieldID];
    return S_OK;
}

IFACEMETHODIMP CLibGuestCredential::GetStringValue(
    DWORD dwFieldID, _Outptr_result_nullonfailure_ PWSTR* ppwsz)
{
    *ppwsz = nullptr;
    if (dwFieldID >= LGFI_NUM_FIELDS)
    {
        return E_INVALIDARG;
    }

    switch (dwFieldID)
    {
    case LGFI_GUESTNUMBER:
        return SHStrDupW(_szGuestNumber, ppwsz);
    case LGFI_PASSWORD:
        // Never hand the password back out; LogonUI does not need it and this
        // keeps it out of any caller's allocation.
        return SHStrDupW(L"", ppwsz);
    case LGFI_STATUS:
        return SHStrDupW(_szStatus, ppwsz);
    default:
        return SHStrDupW(s_rgLibGuestFieldDescriptors[dwFieldID].pszLabel, ppwsz);
    }
}

IFACEMETHODIMP CLibGuestCredential::GetBitmapValue(
    DWORD /*dwFieldID*/, _Outptr_result_nullonfailure_ HBITMAP* phbmp)
{
    // No CPFT_TILE_IMAGE field in the diagnostic build (README.md, "Phase 2":
    // no branding until authentication works).
    *phbmp = nullptr;
    return E_NOTIMPL;
}

IFACEMETHODIMP CLibGuestCredential::GetCheckboxValue(
    DWORD /*dwFieldID*/, _Out_ BOOL* pbChecked,
    _Outptr_result_nullonfailure_ PWSTR* ppwszLabel)
{
    *pbChecked = FALSE;
    *ppwszLabel = nullptr;
    return E_NOTIMPL;
}

IFACEMETHODIMP CLibGuestCredential::GetComboBoxValueCount(
    DWORD /*dwFieldID*/, _Out_ DWORD* pcItems, _Out_ DWORD* pdwSelectedItem)
{
    *pcItems = 0;
    *pdwSelectedItem = 0;
    return E_NOTIMPL;
}

IFACEMETHODIMP CLibGuestCredential::GetComboBoxValueAt(
    DWORD /*dwFieldID*/, DWORD /*dwItem*/, _Outptr_result_nullonfailure_ PWSTR* ppwszItem)
{
    *ppwszItem = nullptr;
    return E_NOTIMPL;
}

IFACEMETHODIMP CLibGuestCredential::GetSubmitButtonValue(
    DWORD dwFieldID, _Out_ DWORD* pdwAdjacentTo)
{
    if (dwFieldID != LGFI_SUBMIT_BUTTON)
    {
        *pdwAdjacentTo = 0;
        return E_INVALIDARG;
    }
    *pdwAdjacentTo = LGFI_PASSWORD;
    return S_OK;
}

IFACEMETHODIMP CLibGuestCredential::SetStringValue(DWORD dwFieldID, _In_ PCWSTR pwz)
{
    switch (dwFieldID)
    {
    case LGFI_GUESTNUMBER:
        return StringCchCopyW(_szGuestNumber, ARRAYSIZE(_szGuestNumber), pwz);

    case LGFI_PASSWORD:
        // Zero the previous value before overwriting so no fragment survives.
        ClearPassword();
        return StringCchCopyW(_szPassword, ARRAYSIZE(_szPassword), pwz);

    default:
        return E_INVALIDARG;
    }
}

IFACEMETHODIMP CLibGuestCredential::SetCheckboxValue(DWORD /*dwFieldID*/, BOOL /*bChecked*/)
{
    return E_NOTIMPL;
}

IFACEMETHODIMP CLibGuestCredential::SetComboBoxSelectedValue(
    DWORD /*dwFieldID*/, DWORD /*dwSelectedItem*/)
{
    return E_NOTIMPL;
}

IFACEMETHODIMP CLibGuestCredential::CommandLinkClicked(DWORD /*dwFieldID*/)
{
    return E_NOTIMPL;
}

// ---------------------------------------------------------------------------
// The core of the experiment.
//
// Builds the Kerberos interactive-logon buffer and hands it to Winlogon. This
// provider never calls the KDC and never calls LsaLogonUser -- Winlogon and LSA
// own authentication (README.md, "Provider responsibilities").
// ---------------------------------------------------------------------------

IFACEMETHODIMP CLibGuestCredential::GetSerialization(
    _Out_ CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
    _Out_ CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
    _Outptr_result_maybenull_ PWSTR* ppwszOptionalStatusText,
    _Out_ CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon)
{
    *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
    *ppwszOptionalStatusText = nullptr;
    *pcpsiOptionalStatusIcon = CPSI_NONE;
    ZeroMemory(pcpcs, sizeof(*pcpcs));

    // Validate locally before building anything.
    WCHAR szAccount[64] = {};
    HRESULT hr = GuestAccountParse(_szGuestNumber, szAccount, ARRAYSIZE(szAccount));
    if (FAILED(hr))
    {
        *pcpsiOptionalStatusIcon = CPSI_ERROR;
        SHStrDupW(L"Enter a guest number between 1 and 500.", ppwszOptionalStatusText);
        return S_OK; // handled; tile stays up for a retry
    }

    if (_szPassword[0] == L'\0')
    {
        *pcpsiOptionalStatusIcon = CPSI_ERROR;
        SHStrDupW(L"Enter the password issued by library staff.", ppwszOptionalStatusText);
        return S_OK;
    }

    ULONG ulAuthPackage = 0;
    hr = LibGuestLookupAuthPackage(&ulAuthPackage);
    if (FAILED(hr))
    {
        *pcpsiOptionalStatusIcon = CPSI_ERROR;
        SHStrDupW(LIBGUEST_GENERIC_FAILURE, ppwszOptionalStatusText);
        return S_OK;
    }

    BYTE* rgbSerialization = nullptr;
    ULONG cbSerialization = 0;
    hr = LibGuestBuildKerbLogonBuffer(szAccount, _szPassword, _cpus,
                                      &rgbSerialization, &cbSerialization);

    // The password now lives only inside the serialization blob, which belongs
    // to LogonUI. Drop our copy immediately.
    ClearPassword();
    SecureZeroMemory(szAccount, sizeof(szAccount));

    if (FAILED(hr))
    {
        *pcpsiOptionalStatusIcon = CPSI_ERROR;
        SHStrDupW(LIBGUEST_GENERIC_FAILURE, ppwszOptionalStatusText);
        return S_OK;
    }

    pcpcs->ulAuthenticationPackage = ulAuthPackage;
    pcpcs->clsidCredentialProvider = CLSID_LibGuestCredentialProvider;
    pcpcs->rgbSerialization = rgbSerialization;
    pcpcs->cbSerialization = cbSerialization;

    *pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;
    return S_OK;
}

IFACEMETHODIMP CLibGuestCredential::ReportResult(
    NTSTATUS ntsStatus,
    NTSTATUS /*ntsSubstatus*/,
    _Outptr_result_maybenull_ PWSTR* ppwszOptionalStatusText,
    _Out_ CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon)
{
    *ppwszOptionalStatusText = nullptr;
    *pcpsiOptionalStatusIcon = CPSI_NONE;

    // Always clear the password after an attempt, successful or not.
    ClearPassword();
    if (_pcpce != nullptr)
    {
        _pcpce->SetFieldString(this, LGFI_PASSWORD, L"");
    }

    if (ntsStatus != STATUS_SUCCESS)
    {
        // One message for every failure mode. Do not reveal whether the account
        // exists, whether the password was wrong, or whether the KDC was
        // reachable (README.md, "Proposed user experience").
        *pcpsiOptionalStatusIcon = CPSI_ERROR;
        SHStrDupW(LIBGUEST_GENERIC_FAILURE, ppwszOptionalStatusText);
    }

    return S_OK;
}

// ---------------------------------------------------------------------------
// ICredentialProviderCredential2
// ---------------------------------------------------------------------------

// S_FALSE with a null SID is the documented way to say "this credential is not
// tied to an enumerated user account". The tile stands on its own rather than
// being merged into a specific user's tile, which is what we want: the target
// libguestN account is chosen by what the patron types, not by tile selection.
//
// The interface's _Outptr_result_nullonfailure_ annotation treats S_FALSE as
// success and so demands a non-null result. That annotation cannot express the
// documented S_FALSE contract, so the analyzer is suppressed here rather than
// the behavior being changed.
#pragma warning(suppress: 6387 28196)
IFACEMETHODIMP CLibGuestCredential::GetUserSid(_Outptr_result_nullonfailure_ PWSTR* ppszSid)
{
    *ppszSid = nullptr;
    return S_FALSE;
}
