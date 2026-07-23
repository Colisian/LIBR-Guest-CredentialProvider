#pragma once

// GUIDs owned by UMD Libraries for the LibGuest credential provider.
//
// CLSID_LibGuestCredentialProvider is the provider's COM class ID. It is:
//   - the CoClass LogonUI instantiates,
//   - the key written under HKLM\...\Authentication\Credential Providers,
//   - the value returned in CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION
//     .clsidCredentialProvider by GetSerialization() (see README.md,
//     "Provider responsibilities").
//
// Freshly generated for this project on 2026-07-23; not copied from any
// Microsoft sample. Never reuse a sample CLSID.

// {AF63107A-B6A3-4A8D-A967-4D1F8339161C}
DEFINE_GUID(CLSID_LibGuestCredentialProvider,
    0xaf63107a, 0xb6a3, 0x4a8d, 0xa9, 0x67, 0x4d, 0x1f, 0x83, 0x39, 0x16, 0x1c);

// Phase 2 (diagnostic provider) will add here, each freshly generated:
//   - no additional GUIDs are strictly required (the credential object and
//     class factory are internal C++ classes, not registered CoClasses), but
//     if a field-descriptor GUID or tile icon resource GUID becomes useful,
//     declare it in this file so all project GUIDs live in one place.
