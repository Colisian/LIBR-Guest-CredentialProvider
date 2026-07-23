#include "KerbSerialize.h"

#include <strsafe.h>
#include <intsafe.h>

#pragma comment(lib, "Secur32.lib")

namespace
{
    // Points a UNICODE_STRING at an existing null-terminated string without
    // copying. The UNICODE_STRING borrows the caller's storage.
    HRESULT UnicodeStringInitWithString(_In_ PWSTR pwz, _Out_ UNICODE_STRING* pus)
    {
        ZeroMemory(pus, sizeof(*pus));
        if (pwz == nullptr)
        {
            return S_OK; // empty string; Length 0, Buffer null
        }

        size_t cch = 0;
        HRESULT hr = StringCchLengthW(pwz, USHRT_MAX / sizeof(WCHAR), &cch);
        if (FAILED(hr))
        {
            return hr;
        }

        pus->Length = static_cast<USHORT>(cch * sizeof(WCHAR));
        pus->MaximumLength = static_cast<USHORT>((cch + 1) * sizeof(WCHAR));
        pus->Buffer = pwz;
        return S_OK;
    }

    // Copies one UNICODE_STRING's characters into the packed blob at pbBuffer
    // and fills out the destination descriptor.
    //
    // Takes BYTE* rather than PWSTR deliberately: the packed form is a counted
    // string with no terminator, so string-typed parameters would be a lie.
    void PackedUnicodeStringCopy(
        const UNICODE_STRING& rus,
        _Out_writes_bytes_all_(rus.Length) BYTE* pbBuffer,
        _Out_ UNICODE_STRING* pusOut)
    {
        pusOut->Length = rus.Length;
        pusOut->MaximumLength = rus.Length;
        pusOut->Buffer = reinterpret_cast<PWSTR>(pbBuffer);
        if (rus.Length != 0)
        {
            CopyMemory(pbBuffer, rus.Buffer, rus.Length);
        }
    }

    // Serializes a KERB_INTERACTIVE_UNLOCK_LOGON, converting each string's
    // Buffer pointer into an offset relative to the start of the structure.
    HRESULT KerbInteractiveUnlockLogonPack(
        const KERB_INTERACTIVE_UNLOCK_LOGON& rkiulIn,
        _Outptr_result_bytebuffer_(*pcb) BYTE** prgb,
        _Out_ ULONG* pcb)
    {
        *prgb = nullptr;
        *pcb = 0;

        const KERB_INTERACTIVE_LOGON* pkilIn = &rkiulIn.Logon;

        ULONG cb = 0;
        HRESULT hr = ULongAdd(static_cast<ULONG>(sizeof(rkiulIn)), pkilIn->LogonDomainName.Length, &cb);
        if (SUCCEEDED(hr)) { hr = ULongAdd(cb, pkilIn->UserName.Length, &cb); }
        if (SUCCEEDED(hr)) { hr = ULongAdd(cb, pkilIn->Password.Length, &cb); }
        if (FAILED(hr))
        {
            return hr;
        }

        KERB_INTERACTIVE_UNLOCK_LOGON* pkiulOut =
            static_cast<KERB_INTERACTIVE_UNLOCK_LOGON*>(CoTaskMemAlloc(cb));
        if (pkiulOut == nullptr)
        {
            return E_OUTOFMEMORY;
        }
        ZeroMemory(pkiulOut, cb);

        // LSA fills in the logon ID for the unlock case; always start zeroed.
        ZeroMemory(&pkiulOut->LogonId, sizeof(LUID));
        pkiulOut->Logon.MessageType = pkilIn->MessageType;

        BYTE* pbBuffer = reinterpret_cast<BYTE*>(pkiulOut) + sizeof(*pkiulOut);

        PackedUnicodeStringCopy(pkilIn->LogonDomainName, pbBuffer,
                                &pkiulOut->Logon.LogonDomainName);
        pbBuffer += pkiulOut->Logon.LogonDomainName.Length;

        PackedUnicodeStringCopy(pkilIn->UserName, pbBuffer,
                                &pkiulOut->Logon.UserName);
        pbBuffer += pkiulOut->Logon.UserName.Length;

        PackedUnicodeStringCopy(pkilIn->Password, pbBuffer,
                                &pkiulOut->Logon.Password);

        // Convert absolute addresses to offsets from the start of the blob.
        BYTE* pbBase = reinterpret_cast<BYTE*>(pkiulOut);
        pkiulOut->Logon.LogonDomainName.Buffer =
            reinterpret_cast<PWSTR>(reinterpret_cast<BYTE*>(pkiulOut->Logon.LogonDomainName.Buffer) - pbBase);
        pkiulOut->Logon.UserName.Buffer =
            reinterpret_cast<PWSTR>(reinterpret_cast<BYTE*>(pkiulOut->Logon.UserName.Buffer) - pbBase);
        pkiulOut->Logon.Password.Buffer =
            reinterpret_cast<PWSTR>(reinterpret_cast<BYTE*>(pkiulOut->Logon.Password.Buffer) - pbBase);

        *prgb = reinterpret_cast<BYTE*>(pkiulOut);
        *pcb = cb;
        return S_OK;
    }
}

HRESULT LibGuestLookupAuthPackage(_Out_ ULONG* pulAuthPackage)
{
    *pulAuthPackage = 0;

    HANDLE hLsa = nullptr;
    NTSTATUS status = LsaConnectUntrusted(&hLsa);
    if (status != STATUS_SUCCESS)
    {
        return HRESULT_FROM_WIN32(LsaNtStatusToWinError(status));
    }

    // LSA_STRING is ANSI; the package name constants are ANSI by definition.
    CHAR szPackage[] = LIBGUEST_AUTH_PACKAGE_NAME;
    LSA_STRING lsaName;
    lsaName.Buffer = szPackage;
    lsaName.Length = static_cast<USHORT>(strlen(szPackage));
    lsaName.MaximumLength = static_cast<USHORT>(sizeof(szPackage));

    ULONG ulPackage = 0;
    status = LsaLookupAuthenticationPackage(hLsa, &lsaName, &ulPackage);

    LsaDeregisterLogonProcess(hLsa);

    if (status != STATUS_SUCCESS)
    {
        return HRESULT_FROM_WIN32(LsaNtStatusToWinError(status));
    }

    *pulAuthPackage = ulPackage;
    return S_OK;
}

HRESULT LibGuestBuildKerbLogonBuffer(
    _In_ PCWSTR pwszAccount,
    _In_ PCWSTR pwszPassword,
    CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
    _Outptr_result_bytebuffer_(*pcbSerialization) BYTE** prgbSerialization,
    _Out_ ULONG* pcbSerialization)
{
    *prgbSerialization = nullptr;
    *pcbSerialization = 0;

    if (pwszAccount == nullptr || pwszPassword == nullptr)
    {
        return E_INVALIDARG;
    }

    // Scratch copies so the UNICODE_STRINGs have writable storage to borrow.
    WCHAR szDomain[64] = {};
    WCHAR szUser[128] = {};
    HRESULT hr;

    if constexpr (LIBGUEST_PRINCIPAL_FORMAT_ACTIVE == LGPF_SPLIT_DOMAIN_AND_USER)
    {
        hr = StringCchCopyW(szDomain, ARRAYSIZE(szDomain), LIBGUEST_REALM);
        if (SUCCEEDED(hr))
        {
            hr = StringCchCopyW(szUser, ARRAYSIZE(szUser), pwszAccount);
        }
    }
    else
    {
        szDomain[0] = L'\0';
        hr = StringCchPrintfW(szUser, ARRAYSIZE(szUser), L"%s@%s", pwszAccount, LIBGUEST_REALM);
    }
    if (FAILED(hr))
    {
        return hr;
    }

    KERB_INTERACTIVE_UNLOCK_LOGON kiul = {};

    // Winlogon sends CPUS_UNLOCK_WORKSTATION for the unlock path; the message
    // type must match or LSA rejects the buffer.
    kiul.Logon.MessageType = (cpus == CPUS_UNLOCK_WORKSTATION)
        ? KerbWorkstationUnlockLogon
        : KerbInteractiveLogon;

    hr = UnicodeStringInitWithString(szDomain, &kiul.Logon.LogonDomainName);
    if (SUCCEEDED(hr))
    {
        hr = UnicodeStringInitWithString(szUser, &kiul.Logon.UserName);
    }
    if (SUCCEEDED(hr))
    {
        hr = UnicodeStringInitWithString(const_cast<PWSTR>(pwszPassword), &kiul.Logon.Password);
    }
    if (SUCCEEDED(hr))
    {
        hr = KerbInteractiveUnlockLogonPack(kiul, prgbSerialization, pcbSerialization);
    }

    // Scratch buffers held identity material, not the password (which was
    // borrowed from the caller), but clear them anyway.
    SecureZeroMemory(szDomain, sizeof(szDomain));
    SecureZeroMemory(szUser, sizeof(szUser));
    SecureZeroMemory(&kiul, sizeof(kiul));

    return hr;
}
