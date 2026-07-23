#pragma once

#include "common.h"
#include "LibGuestCredential.h"

// The standalone Library Guest credential provider.
//
// Standalone by design: it does not wrap or filter Microsoft's password
// provider, and it never hides a system provider. Every built-in recovery tile
// stays visible (README.md, "Use a standalone V2 provider").
class CLibGuestProvider : public ICredentialProvider
{
public:
    static HRESULT CreateInstance(_In_ REFIID riid, _COM_Outptr_ void** ppv);

    // IUnknown
    IFACEMETHODIMP_(ULONG) AddRef();
    IFACEMETHODIMP_(ULONG) Release();
    IFACEMETHODIMP QueryInterface(_In_ REFIID riid, _COM_Outptr_ void** ppv);

    // ICredentialProvider
    IFACEMETHODIMP SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, DWORD dwFlags);
    IFACEMETHODIMP SetSerialization(
        _In_ const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs);
    IFACEMETHODIMP Advise(_In_ ICredentialProviderEvents* pcpe, UINT_PTR upAdviseContext);
    IFACEMETHODIMP UnAdvise();
    IFACEMETHODIMP GetFieldDescriptorCount(_Out_ DWORD* pdwCount);
    IFACEMETHODIMP GetFieldDescriptorAt(
        DWORD dwIndex, _Outptr_result_nullonfailure_ CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd);
    IFACEMETHODIMP GetCredentialCount(_Out_ DWORD* pdwCount, _Out_ DWORD* pdwDefault,
                                      _Out_ BOOL* pbAutoLogonWithDefault);
    IFACEMETHODIMP GetCredentialAt(DWORD dwIndex,
                                   _Outptr_result_nullonfailure_ ICredentialProviderCredential** ppcpc);

private:
    CLibGuestProvider();
    ~CLibGuestProvider();

    void ReleaseCredential();

    long                                _cRef;
    CREDENTIAL_PROVIDER_USAGE_SCENARIO  _cpus;
    bool                                _fScenarioSupported;
    CLibGuestCredential*                _pCredential;
};
