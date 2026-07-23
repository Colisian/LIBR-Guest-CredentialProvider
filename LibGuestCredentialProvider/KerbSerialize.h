#pragma once

#include "common.h"

// Resolves the numeric LSA authentication package ID for
// LIBGUEST_AUTH_PACKAGE_NAME at runtime. Never hardcode this value
// (README.md, "Provider responsibilities").
//
// Uses LsaConnectUntrusted, which is available to LogonUI and does not require
// SeTcbPrivilege. This only looks the package up; it never authenticates.
HRESULT LibGuestLookupAuthPackage(_Out_ ULONG* pulAuthPackage);

// Builds the KERB_INTERACTIVE_UNLOCK_LOGON blob that Winlogon/LSA expect.
//
// The returned buffer is CoTaskMemAlloc'd; ownership transfers to the caller,
// which hands it to LogonUI in CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION.
// Inside the blob the UNICODE_STRING Buffer pointers are byte offsets relative
// to the start of the structure, not addresses -- that is what LSA expects for
// a serialized logon buffer.
//
// The password is copied into the blob. Callers must treat the blob as
// credential material: never log it, and zero any copy they retain.
HRESULT LibGuestBuildKerbLogonBuffer(
    _In_ PCWSTR pwszAccount,
    _In_ PCWSTR pwszPassword,
    CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
    _Outptr_result_bytebuffer_(*pcbSerialization) BYTE** prgbSerialization,
    _Out_ ULONG* pcbSerialization);
