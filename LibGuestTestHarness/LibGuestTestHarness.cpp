// LibGuest credential provider test harness.
//
// Drives the provider's COM interfaces from an ordinary desktop process so the
// interface lifecycle and the Kerberos serialization can be debugged without
// involving LogonUI. Nothing here runs on the secure desktop, so a bug costs
// you a failed run rather than a machine you cannot sign in to.
//
// By default the DLL is loaded straight from the build output with LoadLibrary
// + DllGetClassObject, so no registry entries are needed or written. Pass
// --registered to exercise the CoCreateInstance path instead, once the provider
// really is registered.
//
// Usage:
//   LibGuestTestHarness.exe [options]
//     --dll <path>      Provider DLL (default: LibGuestCredentialProvider.dll
//                       next to this exe, then ..\..\x64\Release\)
//     --guest <n>       Guest number or account name (default: prompt)
//     --unlock          Use CPUS_UNLOCK_WORKSTATION instead of CPUS_LOGON
//     --registered      CoCreateInstance via the registered CLSID
//     --logon           Additionally submit the buffer to LsaLogonUser.
//                       Requires SeTcbPrivilege: run as SYSTEM. TEST VMs ONLY.
//     --password-file <path>
//                       Read the password from the first line of <path> instead
//                       of prompting. REQUIRED when running under PsExec -s:
//                       PsExec launches the harness through a service and piped
//                       stdin does not reach the child, so the interactive
//                       prompt always sees an empty password. A file the child
//                       opens itself crosses that boundary. Handles UTF-8,
//                       UTF-8-BOM, and UTF-16LE-BOM files; strips the trailing
//                       newline. TEST VMs ONLY -- delete the file afterward.
//     --no-password     Skip the password prompt (serialization will fail
//                       validation; useful for checking the field plumbing)

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <credentialprovider.h>
#include <ntsecapi.h>
#include <initguid.h>
#include <stdio.h>
#include <strsafe.h>

#pragma comment(lib, "Secur32.lib")
#pragma comment(lib, "Ole32.lib")
#pragma comment(lib, "Advapi32.lib")

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

// Must match Guid.h in the provider project.
// {AF63107A-B6A3-4A8D-A967-4D1F8339161C}
DEFINE_GUID(CLSID_LibGuestCredentialProvider,
    0xaf63107a, 0xb6a3, 0x4a8d, 0xa9, 0x67, 0x4d, 0x1f, 0x83, 0x39, 0x16, 0x1c);

// Mirrors LIBGUEST_FIELD_ID in the provider's common.h.
enum
{
    LGFI_LABEL = 0,
    LGFI_GUESTNUMBER = 1,
    LGFI_PASSWORD = 2,
    LGFI_SUBMIT_BUTTON = 3,
    LGFI_NOTE = 4,
    LGFI_STATUS = 5,
};

typedef HRESULT(STDAPICALLTYPE* PFN_DllGetClassObject)(REFCLSID, REFIID, void**);

namespace
{
    int g_failures = 0;

    void Ok(PCSTR fmt, ...)
    {
        va_list args;
        va_start(args, fmt);
        printf("  [ ok ] ");
        vprintf(fmt, args);
        printf("\n");
        va_end(args);
    }

    void Fail(PCSTR fmt, ...)
    {
        va_list args;
        va_start(args, fmt);
        printf("  [FAIL] ");
        vprintf(fmt, args);
        printf("\n");
        va_end(args);
        g_failures++;
    }

    void Info(PCSTR fmt, ...)
    {
        va_list args;
        va_start(args, fmt);
        printf("         ");
        vprintf(fmt, args);
        printf("\n");
        va_end(args);
    }

    void Section(PCSTR title)
    {
        printf("\n== %s ==\n", title);
    }

    PCSTR FieldTypeName(CREDENTIAL_PROVIDER_FIELD_TYPE t)
    {
        switch (t)
        {
        case CPFT_INVALID:       return "INVALID";
        case CPFT_LARGE_TEXT:    return "LARGE_TEXT";
        case CPFT_SMALL_TEXT:    return "SMALL_TEXT";
        case CPFT_COMMAND_LINK:  return "COMMAND_LINK";
        case CPFT_EDIT_TEXT:     return "EDIT_TEXT";
        case CPFT_PASSWORD_TEXT: return "PASSWORD_TEXT";
        case CPFT_TILE_IMAGE:    return "TILE_IMAGE";
        case CPFT_CHECKBOX:      return "CHECKBOX";
        case CPFT_COMBOBOX:      return "COMBOBOX";
        case CPFT_SUBMIT_BUTTON: return "SUBMIT_BUTTON";
        default:                 return "?";
        }
    }

    // Reads a password without echoing it. The buffer is the caller's to zero.
    bool ReadPasswordNoEcho(_Out_writes_(cch) PWSTR pwszOut, size_t cch)
    {
        pwszOut[0] = L'\0';

        HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);
        DWORD dwModeOld = 0;
        bool fConsole = (GetConsoleMode(hIn, &dwModeOld) != FALSE);
        if (fConsole)
        {
            SetConsoleMode(hIn, dwModeOld & ~static_cast<DWORD>(ENABLE_ECHO_INPUT));
        }

        bool fResult = (fgetws(pwszOut, static_cast<int>(cch), stdin) != nullptr);

        if (fConsole)
        {
            SetConsoleMode(hIn, dwModeOld);
            printf("\n");
        }

        if (fResult)
        {
            size_t len = wcslen(pwszOut);
            while (len > 0 && (pwszOut[len - 1] == L'\n' || pwszOut[len - 1] == L'\r'))
            {
                pwszOut[--len] = L'\0';
            }

            // When stdin is a pipe rather than a console, a UTF-8 BOM arrives as
            // three literal characters and would silently corrupt the password --
            // which during the real test looks indistinguishable from a wrong
            // password. Strip it in both the wide and raw-byte forms.
            size_t cchSkip = 0;
            if (len >= 1 && pwszOut[0] == 0xFEFF)
            {
                cchSkip = 1;
            }
            else if (len >= 3 && pwszOut[0] == 0x00EF && pwszOut[1] == 0x00BB &&
                     pwszOut[2] == 0x00BF)
            {
                cchSkip = 3;
            }
            if (cchSkip != 0)
            {
                memmove(pwszOut, pwszOut + cchSkip, (len - cchSkip + 1) * sizeof(WCHAR));
            }
        }
        return fResult;
    }

    // Reads a password from the first line of a file. This is the only input
    // method that survives PsExec's SYSTEM hand-off: the child opens the file
    // itself rather than depending on inherited stdin. Handles the encodings a
    // tester is likely to produce (plain UTF-8, UTF-8 with BOM, UTF-16LE with
    // BOM) and strips the trailing newline. The caller zeroes the buffer.
    bool ReadPasswordFromFile(_In_ PCWSTR pwszPath,
                              _Out_writes_(cch) PWSTR pwszOut, size_t cch)
    {
        pwszOut[0] = L'\0';

        HANDLE hFile = CreateFileW(pwszPath, GENERIC_READ, FILE_SHARE_READ, nullptr,
                                   OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile == INVALID_HANDLE_VALUE)
        {
            Fail("could not open password file (error %lu): %ls", GetLastError(), pwszPath);
            return false;
        }

        BYTE rgb[1024] = {};
        DWORD cbRead = 0;
        BOOL fRead = ReadFile(hFile, rgb, sizeof(rgb) - sizeof(WCHAR), &cbRead, nullptr);
        CloseHandle(hFile);
        if (!fRead)
        {
            Fail("could not read password file (error %lu)", GetLastError());
            return false;
        }

        if (cbRead >= 2 && rgb[0] == 0xFF && rgb[1] == 0xFE)
        {
            // UTF-16LE with BOM: the bytes are already wide characters.
            size_t cchData = (cbRead - 2) / sizeof(WCHAR);
            if (cchData > cch - 1) { cchData = cch - 1; }
            memcpy(pwszOut, rgb + 2, cchData * sizeof(WCHAR));
            pwszOut[cchData] = L'\0';
        }
        else
        {
            // UTF-8, with or without a BOM. Plain ASCII is valid UTF-8, so this
            // path also covers ANSI files that hold only ASCII.
            const BYTE* pb = rgb;
            DWORD cb = cbRead;
            if (cb >= 3 && pb[0] == 0xEF && pb[1] == 0xBB && pb[2] == 0xBF)
            {
                pb += 3;
                cb -= 3;
            }
            int cchConv = MultiByteToWideChar(CP_UTF8, 0,
                                              reinterpret_cast<LPCCH>(pb), static_cast<int>(cb),
                                              pwszOut, static_cast<int>(cch - 1));
            pwszOut[(cchConv > 0) ? cchConv : 0] = L'\0';
        }

        // Keep only the first line; drop any trailing CR/LF.
        for (size_t i = 0; pwszOut[i] != L'\0'; i++)
        {
            if (pwszOut[i] == L'\r' || pwszOut[i] == L'\n')
            {
                pwszOut[i] = L'\0';
                break;
            }
        }

        if (pwszOut[0] == L'\0')
        {
            Fail("password file was empty: %ls", pwszPath);
            return false;
        }
        return true;
    }

    // Decodes the packed KERB_INTERACTIVE_UNLOCK_LOGON so the domain/username
    // split is visible as ground truth rather than assumed. The password is
    // never printed -- only its length, which is enough to prove it was packed.
    void DumpKerbBuffer(const BYTE* pb, ULONG cb)
    {
        if (cb < sizeof(KERB_INTERACTIVE_UNLOCK_LOGON))
        {
            Fail("buffer is %lu bytes, smaller than KERB_INTERACTIVE_UNLOCK_LOGON (%zu)",
                 cb, sizeof(KERB_INTERACTIVE_UNLOCK_LOGON));
            return;
        }

        const KERB_INTERACTIVE_UNLOCK_LOGON* pkiul =
            reinterpret_cast<const KERB_INTERACTIVE_UNLOCK_LOGON*>(pb);

        PCSTR pszType = "?";
        switch (pkiul->Logon.MessageType)
        {
        case KerbInteractiveLogon:        pszType = "KerbInteractiveLogon"; break;
        case KerbWorkstationUnlockLogon:  pszType = "KerbWorkstationUnlockLogon"; break;
        default: break;
        }
        Info("MessageType     : %s (%d)", pszType, static_cast<int>(pkiul->Logon.MessageType));
        Info("LogonId         : 0x%08lx:0x%08lx",
             pkiul->LogonId.HighPart, pkiul->LogonId.LowPart);

        struct { PCSTR name; const UNICODE_STRING* pus; bool secret; } fields[] =
        {
            { "LogonDomainName", &pkiul->Logon.LogonDomainName, false },
            { "UserName",        &pkiul->Logon.UserName,        false },
            { "Password",        &pkiul->Logon.Password,        true  },
        };

        for (const auto& f : fields)
        {
            // Buffer holds an offset from the start of the blob, not a pointer.
            ULONG_PTR offset = reinterpret_cast<ULONG_PTR>(f.pus->Buffer);
            USHORT len = f.pus->Length;

            if (len == 0)
            {
                Info("%-16s: (empty)", f.name);
                continue;
            }
            if (offset + len > cb)
            {
                Fail("%s offset %llu + length %u runs past the %lu-byte buffer",
                     f.name, static_cast<unsigned long long>(offset), len, cb);
                continue;
            }

            if (f.secret)
            {
                Info("%-16s: <%u bytes, %u chars> at offset %llu (value not printed)",
                     f.name, len, static_cast<unsigned>(len / sizeof(WCHAR)),
                     static_cast<unsigned long long>(offset));
            }
            else
            {
                WCHAR sz[256] = {};
                size_t cchAvail = static_cast<size_t>(len / sizeof(WCHAR));
                size_t cch = (cchAvail < ARRAYSIZE(sz) - 1) ? cchAvail : ARRAYSIZE(sz) - 1;
                memcpy(sz, pb + offset, cch * sizeof(WCHAR));
                Info("%-16s: \"%ls\" (%u chars) at offset %llu",
                     f.name, sz, static_cast<unsigned>(len / sizeof(WCHAR)),
                     static_cast<unsigned long long>(offset));
            }
        }
    }

    // Diagnostic: authenticate the same credential via LogonUser() using each
    // candidate principal shape. This is roughly what `runas` does internally,
    // and it needs no SeTcbPrivilege -- so it isolates "is the credential good"
    // and "which shape does the KDC accept" from the serialization question,
    // without SYSTEM or the secure desktop.
    //
    // If the split shape fails here but the UPN shape succeeds, the fix is
    // LIBGUEST_PRINCIPAL_FORMAT_ACTIVE in the provider's common.h.
    void ProbeLogonUser(_In_ PCWSTR pwszAccount, _In_ PCWSTR pwszPassword)
    {
        Section("LogonUser probe (which principal shape does the KDC accept?)");

        WCHAR szUpn[192] = {};
        StringCchPrintfW(szUpn, ARRAYSIZE(szUpn), L"%s@%s", pwszAccount, L"UMD.EDU");

        struct { PCWSTR user; PCWSTR domain; PCSTR desc; } shapes[] =
        {
            { pwszAccount, L"UMD.EDU", "split  : user=\"%ls\" domain=\"UMD.EDU\"  (dial 2 = LGPF_SPLIT_DOMAIN_AND_USER, current)" },
            { szUpn,       nullptr,    "upn    : user=\"%ls\" domain=NULL        (dial 2 = LGPF_UPN_IN_USERNAME)" },
        };

        for (const auto& s : shapes)
        {
            Info(s.desc, s.user);

            HANDLE hToken = nullptr;
            BOOL fOk = LogonUserW(s.user, s.domain, pwszPassword,
                                  LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT,
                                  &hToken);
            if (fOk)
            {
                Ok("  LogonUser SUCCEEDED");

                BYTE rgbUser[SECURITY_MAX_SID_SIZE + sizeof(TOKEN_USER) + 64] = {};
                DWORD cbUser = sizeof(rgbUser);
                if (GetTokenInformation(hToken, TokenUser, rgbUser, cbUser, &cbUser))
                {
                    TOKEN_USER* ptu = reinterpret_cast<TOKEN_USER*>(rgbUser);
                    WCHAR szName[256] = {};
                    WCHAR szDomain[256] = {};
                    DWORD cchName = ARRAYSIZE(szName);
                    DWORD cchDomain = ARRAYSIZE(szDomain);
                    SID_NAME_USE use;
                    if (LookupAccountSidW(nullptr, ptu->User.Sid, szName, &cchName,
                                          szDomain, &cchDomain, &use))
                    {
                        Ok("  Token identity: %ls\\%ls", szDomain, szName);
                    }
                }
                CloseHandle(hToken);
            }
            else
            {
                DWORD dwErr = GetLastError();
                PCSTR pszMeaning = "";
                switch (dwErr)
                {
                case 1326: pszMeaning = " (ERROR_LOGON_FAILURE - bad user or password)"; break;
                case 1311: pszMeaning = " (ERROR_NO_LOGON_SERVERS - no KDC reachable)"; break;
                case 1317: pszMeaning = " (ERROR_NO_SUCH_USER)"; break;
                case 1385: pszMeaning = " (ERROR_LOGON_TYPE_NOT_GRANTED)"; break;
                case 1327: pszMeaning = " (ERROR_ACCOUNT_RESTRICTION - e.g. blank password)"; break;
                default: break;
                }
                Info("  LogonUser failed: Win32 %lu%s", dwErr, pszMeaning);
            }
        }
    }

    // Optional: submit the serialization to LSA exactly as Winlogon would.
    // This is the only part of the harness that can answer the core question
    // -- whether LSA accepts the buffer -- without touching the secure desktop.
    // Requires SeTcbPrivilege, so it must run as SYSTEM.
    void TryLsaLogon(ULONG ulAuthPackageFromProvider, const BYTE* pb, ULONG cb)
    {
        Section("LsaLogonUser submission (opt-in)");

        HANDLE hLsa = nullptr;
        LSA_STRING lsaProcName;
        CHAR szProcName[] = "LibGuestTestHarness";
        lsaProcName.Buffer = szProcName;
        lsaProcName.Length = static_cast<USHORT>(strlen(szProcName));
        lsaProcName.MaximumLength = static_cast<USHORT>(sizeof(szProcName));

        LSA_OPERATIONAL_MODE mode = 0;
        NTSTATUS status = LsaRegisterLogonProcess(&lsaProcName, &hLsa, &mode);
        if (status != STATUS_SUCCESS)
        {
            Fail("LsaRegisterLogonProcess failed: NTSTATUS 0x%08lx (Win32 %lu)",
                 static_cast<unsigned long>(status), LsaNtStatusToWinError(status));
            Info("This almost always means the harness is not running as SYSTEM.");
            Info("Retry with:  psexec -s -i LibGuestTestHarness.exe --logon ...");
            Info("or via a scheduled task configured to run as SYSTEM.");
            return;
        }
        Ok("LsaRegisterLogonProcess succeeded (SeTcbPrivilege present)");

        LSA_STRING lsaOrigin;
        CHAR szOrigin[] = "LibGuest";
        lsaOrigin.Buffer = szOrigin;
        lsaOrigin.Length = static_cast<USHORT>(strlen(szOrigin));
        lsaOrigin.MaximumLength = static_cast<USHORT>(sizeof(szOrigin));

        TOKEN_SOURCE tokenSource = {};
        memcpy(tokenSource.SourceName, "LibGuest", 8);
        AllocateLocallyUniqueId(&tokenSource.SourceIdentifier);

        void* pvProfile = nullptr;
        ULONG cbProfile = 0;
        LUID logonId = {};
        HANDLE hToken = nullptr;
        QUOTA_LIMITS quotas = {};
        NTSTATUS substatus = STATUS_SUCCESS;

        status = LsaLogonUser(
            hLsa,
            &lsaOrigin,
            Interactive,
            ulAuthPackageFromProvider,
            const_cast<BYTE*>(pb),
            cb,
            nullptr,
            &tokenSource,
            &pvProfile,
            &cbProfile,
            &logonId,
            &hToken,
            &quotas,
            &substatus);

        if (status == STATUS_SUCCESS)
        {
            Ok("LsaLogonUser SUCCEEDED -- LSA accepted the serialization");
            Info("LogonId: 0x%08lx:0x%08lx", logonId.HighPart, logonId.LowPart);

            // Report which account the resulting token actually belongs to.
            // This is the acceptance criterion from README.md: the session must
            // belong to the mapped local libguestN account.
            if (hToken != nullptr)
            {
                BYTE rgbUser[SECURITY_MAX_SID_SIZE + sizeof(TOKEN_USER) + 64] = {};
                DWORD cbUser = sizeof(rgbUser);
                if (GetTokenInformation(hToken, TokenUser, rgbUser, cbUser, &cbUser))
                {
                    TOKEN_USER* ptu = reinterpret_cast<TOKEN_USER*>(rgbUser);
                    WCHAR szName[256] = {};
                    WCHAR szDomain[256] = {};
                    DWORD cchName = ARRAYSIZE(szName);
                    DWORD cchDomain = ARRAYSIZE(szDomain);
                    SID_NAME_USE use;
                    if (LookupAccountSidW(nullptr, ptu->User.Sid, szName, &cchName,
                                          szDomain, &cchDomain, &use))
                    {
                        Ok("Token identity: %ls\\%ls", szDomain, szName);
                    }
                    else
                    {
                        Info("LookupAccountSid failed: %lu", GetLastError());
                    }
                }
                CloseHandle(hToken);
            }
        }
        else
        {
            Fail("LsaLogonUser failed: NTSTATUS 0x%08lx, substatus 0x%08lx (Win32 %lu)",
                 static_cast<unsigned long>(status),
                 static_cast<unsigned long>(substatus),
                 LsaNtStatusToWinError(status));
            Info("0xC000006D = STATUS_LOGON_FAILURE (bad credential, or the KDC");
            Info("             rejected the principal)");
            Info("0xC000005E = STATUS_NO_LOGON_SERVERS (no KDC reachable)");
            Info("0xC0000064 = STATUS_NO_SUCH_USER");
            Info("0xC000018B = STATUS_NO_TRUST_SAM_ACCOUNT");
        }

        if (pvProfile != nullptr)
        {
            SecureZeroMemory(pvProfile, cbProfile);
            LsaFreeReturnBuffer(pvProfile);
        }
        LsaDeregisterLogonProcess(hLsa);
    }
}

int wmain(int argc, wchar_t** argv)
{
    PCWSTR pwszDll = nullptr;
    PCWSTR pwszGuest = nullptr;
    PCWSTR pwszPasswordFile = nullptr;
    bool fUnlock = false;
    bool fRegistered = false;
    bool fLsaLogon = false;
    bool fProbe = false;
    bool fNoPassword = false;

    for (int i = 1; i < argc; i++)
    {
        if (_wcsicmp(argv[i], L"--dll") == 0 && i + 1 < argc)          { pwszDll = argv[++i]; }
        else if (_wcsicmp(argv[i], L"--guest") == 0 && i + 1 < argc)   { pwszGuest = argv[++i]; }
        else if (_wcsicmp(argv[i], L"--password-file") == 0 && i + 1 < argc) { pwszPasswordFile = argv[++i]; }
        else if (_wcsicmp(argv[i], L"--unlock") == 0)                  { fUnlock = true; }
        else if (_wcsicmp(argv[i], L"--registered") == 0)              { fRegistered = true; }
        else if (_wcsicmp(argv[i], L"--logon") == 0)                   { fLsaLogon = true; }
        else if (_wcsicmp(argv[i], L"--probe") == 0)                   { fProbe = true; }
        else if (_wcsicmp(argv[i], L"--no-password") == 0)             { fNoPassword = true; }
        else
        {
            wprintf(L"Unrecognized argument: %s\n", argv[i]);
            return 2;
        }
    }

    printf("LibGuest credential provider test harness\n");
    printf("Scenario: %s\n", fUnlock ? "CPUS_UNLOCK_WORKSTATION" : "CPUS_LOGON");

    HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if (FAILED(hr))
    {
        printf("CoInitializeEx failed: 0x%08lx\n", static_cast<unsigned long>(hr));
        return 1;
    }

    // ---- Obtain the provider -------------------------------------------
    Section("Provider instantiation");

    ICredentialProvider* pProvider = nullptr;
    HMODULE hDll = nullptr;

    if (fRegistered)
    {
        hr = CoCreateInstance(CLSID_LibGuestCredentialProvider, nullptr, CLSCTX_INPROC_SERVER,
                              IID_ICredentialProvider, reinterpret_cast<void**>(&pProvider));
        if (FAILED(hr))
        {
            Fail("CoCreateInstance failed: 0x%08lx (is the CLSID registered?)",
                 static_cast<unsigned long>(hr));
            CoUninitialize();
            return 1;
        }
        Ok("CoCreateInstance via registered CLSID");
    }
    else
    {
        WCHAR szDll[MAX_PATH] = {};
        if (pwszDll != nullptr)
        {
            StringCchCopyW(szDll, ARRAYSIZE(szDll), pwszDll);
        }
        else
        {
            // Next to the harness first, then the shared build output.
            GetModuleFileNameW(nullptr, szDll, ARRAYSIZE(szDll));
            PWSTR pwzSlash = wcsrchr(szDll, L'\\');
            if (pwzSlash != nullptr) { *(pwzSlash + 1) = L'\0'; }
            StringCchCatW(szDll, ARRAYSIZE(szDll), L"LibGuestCredentialProvider.dll");

            if (GetFileAttributesW(szDll) == INVALID_FILE_ATTRIBUTES)
            {
                GetModuleFileNameW(nullptr, szDll, ARRAYSIZE(szDll));
                pwzSlash = wcsrchr(szDll, L'\\');
                if (pwzSlash != nullptr) { *(pwzSlash + 1) = L'\0'; }
                StringCchCatW(szDll, ARRAYSIZE(szDll),
                              L"..\\..\\x64\\Release\\LibGuestCredentialProvider.dll");
            }
        }

        wprintf(L"         DLL: %s\n", szDll);
        hDll = LoadLibraryW(szDll);
        if (hDll == nullptr)
        {
            Fail("LoadLibrary failed: %lu", GetLastError());
            CoUninitialize();
            return 1;
        }

        PFN_DllGetClassObject pfn = reinterpret_cast<PFN_DllGetClassObject>(
            reinterpret_cast<void*>(GetProcAddress(hDll, "DllGetClassObject")));
        if (pfn == nullptr)
        {
            Fail("DllGetClassObject export not found");
            FreeLibrary(hDll);
            CoUninitialize();
            return 1;
        }

        IClassFactory* pFactory = nullptr;
        hr = pfn(CLSID_LibGuestCredentialProvider, IID_IClassFactory,
                 reinterpret_cast<void**>(&pFactory));
        if (FAILED(hr))
        {
            Fail("DllGetClassObject failed: 0x%08lx", static_cast<unsigned long>(hr));
            FreeLibrary(hDll);
            CoUninitialize();
            return 1;
        }
        Ok("DllGetClassObject returned a class factory (no registry involved)");

        hr = pFactory->CreateInstance(nullptr, IID_ICredentialProvider,
                                      reinterpret_cast<void**>(&pProvider));
        pFactory->Release();
        if (FAILED(hr))
        {
            Fail("IClassFactory::CreateInstance failed: 0x%08lx",
                 static_cast<unsigned long>(hr));
            FreeLibrary(hDll);
            CoUninitialize();
            return 1;
        }
        Ok("ICredentialProvider created");
    }

    // ---- Scenario negotiation ------------------------------------------
    Section("SetUsageScenario");

    CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus = fUnlock ? CPUS_UNLOCK_WORKSTATION : CPUS_LOGON;
    hr = pProvider->SetUsageScenario(cpus, 0);
    if (FAILED(hr))
    {
        Fail("SetUsageScenario(%s) returned 0x%08lx",
             fUnlock ? "CPUS_UNLOCK_WORKSTATION" : "CPUS_LOGON",
             static_cast<unsigned long>(hr));
    }
    else
    {
        Ok("SetUsageScenario accepted");
    }

    // Scenarios the provider must decline rather than half-support.
    struct { CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus; PCSTR name; } declined[] =
    {
        { CPUS_CHANGE_PASSWORD, "CPUS_CHANGE_PASSWORD" },
        { CPUS_CREDUI,          "CPUS_CREDUI" },
        { CPUS_PLAP,            "CPUS_PLAP" },
    };
    for (const auto& d : declined)
    {
        ICredentialProvider* pTmp = nullptr;
        HRESULT hrTmp;
        if (fRegistered)
        {
            hrTmp = CoCreateInstance(CLSID_LibGuestCredentialProvider, nullptr,
                                     CLSCTX_INPROC_SERVER, IID_ICredentialProvider,
                                     reinterpret_cast<void**>(&pTmp));
        }
        else
        {
            PFN_DllGetClassObject pfn = reinterpret_cast<PFN_DllGetClassObject>(
                reinterpret_cast<void*>(GetProcAddress(hDll, "DllGetClassObject")));
            IClassFactory* pFactory = nullptr;
            hrTmp = pfn(CLSID_LibGuestCredentialProvider, IID_IClassFactory,
                        reinterpret_cast<void**>(&pFactory));
            if (SUCCEEDED(hrTmp))
            {
                hrTmp = pFactory->CreateInstance(nullptr, IID_ICredentialProvider,
                                                 reinterpret_cast<void**>(&pTmp));
                pFactory->Release();
            }
        }
        if (SUCCEEDED(hrTmp) && pTmp != nullptr)
        {
            HRESULT hrScenario = pTmp->SetUsageScenario(d.cpus, 0);
            if (hrScenario == E_NOTIMPL)
            {
                Ok("%s declined with E_NOTIMPL", d.name);
            }
            else
            {
                Fail("%s returned 0x%08lx, expected E_NOTIMPL",
                     d.name, static_cast<unsigned long>(hrScenario));
            }
            pTmp->Release();
        }
    }

    // ---- Field descriptors ---------------------------------------------
    Section("Field descriptors");

    DWORD dwFieldCount = 0;
    hr = pProvider->GetFieldDescriptorCount(&dwFieldCount);
    if (FAILED(hr))
    {
        Fail("GetFieldDescriptorCount failed: 0x%08lx", static_cast<unsigned long>(hr));
    }
    else
    {
        Ok("%lu fields", dwFieldCount);
        for (DWORD i = 0; i < dwFieldCount; i++)
        {
            CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* pcpfd = nullptr;
            if (SUCCEEDED(pProvider->GetFieldDescriptorAt(i, &pcpfd)) && pcpfd != nullptr)
            {
                Info("[%lu] %-14s \"%ls\"", pcpfd->dwFieldID,
                     FieldTypeName(pcpfd->cpft), pcpfd->pszLabel ? pcpfd->pszLabel : L"");
                CoTaskMemFree(pcpfd->pszLabel);
                CoTaskMemFree(pcpfd);
            }
            else
            {
                Fail("GetFieldDescriptorAt(%lu) failed", i);
            }
        }

        // Out-of-range must be rejected, not tolerated.
        CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* pBad = nullptr;
        if (pProvider->GetFieldDescriptorAt(dwFieldCount, &pBad) == E_INVALIDARG)
        {
            Ok("GetFieldDescriptorAt(out of range) rejected");
        }
        else
        {
            Fail("GetFieldDescriptorAt(out of range) was not rejected");
        }
    }

    // ---- Credential enumeration ----------------------------------------
    Section("Credential enumeration");

    DWORD dwCount = 0, dwDefault = 0;
    BOOL fAutoLogon = FALSE;
    hr = pProvider->GetCredentialCount(&dwCount, &dwDefault, &fAutoLogon);
    if (FAILED(hr))
    {
        Fail("GetCredentialCount failed: 0x%08lx", static_cast<unsigned long>(hr));
    }
    else
    {
        Ok("%lu credential(s), default=%s, autoLogon=%s",
           dwCount,
           dwDefault == CREDENTIAL_PROVIDER_NO_DEFAULT ? "none" : "set",
           fAutoLogon ? "TRUE" : "FALSE");
        if (fAutoLogon)
        {
            Fail("autoLogon must be FALSE -- the patron has to type a credential");
        }
        if (dwDefault != CREDENTIAL_PROVIDER_NO_DEFAULT)
        {
            Fail("this tile must not be the default; recovery tiles stay in front");
        }
    }

    ICredentialProviderCredential* pCred = nullptr;
    hr = pProvider->GetCredentialAt(0, &pCred);
    if (FAILED(hr) || pCred == nullptr)
    {
        Fail("GetCredentialAt(0) failed: 0x%08lx", static_cast<unsigned long>(hr));
        if (pProvider) pProvider->Release();
        if (hDll) FreeLibrary(hDll);
        CoUninitialize();
        return 1;
    }
    Ok("GetCredentialAt(0) returned a credential");

    ICredentialProviderCredential2* pCred2 = nullptr;
    hr = pCred->QueryInterface(IID_ICredentialProviderCredential2,
                               reinterpret_cast<void**>(&pCred2));
    if (FAILED(hr))
    {
        Fail("QueryInterface(ICredentialProviderCredential2) failed: 0x%08lx -- "
             "this is required for a V2 provider", static_cast<unsigned long>(hr));
    }
    else
    {
        Ok("ICredentialProviderCredential2 supported");
        PWSTR pszSid = nullptr;
        HRESULT hrSid = pCred2->GetUserSid(&pszSid);
        if (hrSid == S_FALSE && pszSid == nullptr)
        {
            Ok("GetUserSid returned S_FALSE (tile not bound to an enumerated user)");
        }
        else
        {
            Info("GetUserSid returned 0x%08lx, sid=%ls",
                 static_cast<unsigned long>(hrSid), pszSid ? pszSid : L"(null)");
            CoTaskMemFree(pszSid);
        }
        pCred2->Release();
    }

    // ---- Guest number validation ---------------------------------------
    Section("Guest number validation");

    struct { PCWSTR input; bool shouldPass; } cases[] =
    {
        { L"1",            true  },
        { L"500",          true  },
        { L"42",           true  },
        { L"libguest42",   true  },
        { L"LIBGUEST42",   true  },
        { L"  42  ",       true  },
        { L"0",            false },
        { L"501",          false },
        { L"-1",           false },
        { L"",             false },
        { L"abc",          false },
        { L"42abc",        false },
        { L"4 2",          false },
        { L"libguest",     false },
        { L"99999999999",  false },
    };

    for (const auto& c : cases)
    {
        pCred->SetStringValue(LGFI_GUESTNUMBER, c.input);
        pCred->SetStringValue(LGFI_PASSWORD, L"placeholder-not-a-real-password");

        CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE cpgsr;
        CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION cpcs = {};
        PWSTR pwszStatus = nullptr;
        CREDENTIAL_PROVIDER_STATUS_ICON icon;

        HRESULT hrSer = pCred->GetSerialization(&cpgsr, &cpcs, &pwszStatus, &icon);
        bool passed = SUCCEEDED(hrSer) && cpgsr == CPGSR_RETURN_CREDENTIAL_FINISHED;

        if (passed == c.shouldPass)
        {
            Ok("\"%ls\" -> %s", c.input, passed ? "accepted" : "rejected");
        }
        else
        {
            Fail("\"%ls\" -> %s, expected %s", c.input,
                 passed ? "accepted" : "rejected",
                 c.shouldPass ? "accepted" : "rejected");
        }

        if (cpcs.rgbSerialization != nullptr)
        {
            SecureZeroMemory(cpcs.rgbSerialization, cpcs.cbSerialization);
            CoTaskMemFree(cpcs.rgbSerialization);
        }
        CoTaskMemFree(pwszStatus);
    }

    // A missing password must be rejected even with a valid guest number.
    {
        pCred->SetStringValue(LGFI_GUESTNUMBER, L"42");
        pCred->SetStringValue(LGFI_PASSWORD, L"");
        CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE cpgsr;
        CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION cpcs = {};
        PWSTR pwszStatus = nullptr;
        CREDENTIAL_PROVIDER_STATUS_ICON icon;
        pCred->GetSerialization(&cpgsr, &cpcs, &pwszStatus, &icon);
        if (cpgsr != CPGSR_RETURN_CREDENTIAL_FINISHED)
        {
            Ok("empty password rejected");
        }
        else
        {
            Fail("empty password was accepted");
        }
        if (cpcs.rgbSerialization != nullptr) { CoTaskMemFree(cpcs.rgbSerialization); }
        CoTaskMemFree(pwszStatus);
    }

    // ---- Real serialization --------------------------------------------
    Section("Serialization");

    WCHAR szGuest[64] = {};
    WCHAR szPassword[256] = {};

    if (pwszGuest != nullptr)
    {
        StringCchCopyW(szGuest, ARRAYSIZE(szGuest), pwszGuest);
    }
    else
    {
        printf("         Guest number (1-500): ");
        if (fgetws(szGuest, ARRAYSIZE(szGuest), stdin) != nullptr)
        {
            size_t len = wcslen(szGuest);
            while (len > 0 && (szGuest[len - 1] == L'\n' || szGuest[len - 1] == L'\r'))
            {
                szGuest[--len] = L'\0';
            }
        }
    }

    if (fNoPassword)
    {
        // leave password empty on purpose
    }
    else if (pwszPasswordFile != nullptr)
    {
        if (ReadPasswordFromFile(pwszPasswordFile, szPassword, ARRAYSIZE(szPassword)))
        {
            Ok("password read from file (%zu chars)", wcslen(szPassword));
        }
    }
    else
    {
        printf("         Password (not echoed): ");
        ReadPasswordNoEcho(szPassword, ARRAYSIZE(szPassword));

        // Running as SYSTEM under PsExec means stdin came from a service
        // hand-off and is empty no matter what the caller piped in. Say so
        // plainly rather than letting it look like a rejected credential.
        if (szPassword[0] == L'\0' && fLsaLogon)
        {
            Fail("no password arrived on stdin");
            Info("Under PsExec -s, stdin does not reach the child process.");
            Info("Use --password-file <path> instead; the child opens it directly.");
        }
    }

    // Probe before serialization, while the password is still in hand.
    if (fProbe && szPassword[0] != L'\0')
    {
        // Normalize whatever was typed into the bare account name.
        WCHAR szAccount[64] = {};
        PCWSTR pwz = szGuest;
        while (*pwz == L' ' || *pwz == L'\t') { pwz++; }
        if (_wcsnicmp(pwz, L"libguest", 8) == 0) { pwz += 8; }
        WCHAR szDigits[32] = {};
        size_t d = 0;
        while (*pwz >= L'0' && *pwz <= L'9' && d < ARRAYSIZE(szDigits) - 1)
        {
            szDigits[d++] = *pwz++;
        }
        StringCchPrintfW(szAccount, ARRAYSIZE(szAccount), L"libguest%s", szDigits);
        ProbeLogonUser(szAccount, szPassword);
    }

    pCred->SetStringValue(LGFI_GUESTNUMBER, szGuest);
    pCred->SetStringValue(LGFI_PASSWORD, szPassword);

    CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE cpgsr;
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION cpcs = {};
    PWSTR pwszStatus = nullptr;
    CREDENTIAL_PROVIDER_STATUS_ICON icon = CPSI_NONE;

    hr = pCred->GetSerialization(&cpgsr, &cpcs, &pwszStatus, &icon);
    SecureZeroMemory(szPassword, sizeof(szPassword));

    if (FAILED(hr))
    {
        Fail("GetSerialization failed: 0x%08lx", static_cast<unsigned long>(hr));
    }
    else if (cpgsr != CPGSR_RETURN_CREDENTIAL_FINISHED)
    {
        // With --no-password there is nothing to serialize, so refusing is the
        // correct outcome rather than a failure.
        if (fNoPassword)
        {
            Ok("no credential produced, as expected with --no-password");
        }
        else
        {
            Fail("GetSerialization did not produce a credential (response %d)",
                 static_cast<int>(cpgsr));
        }
        if (pwszStatus != nullptr)
        {
            Info("status text: %ls", pwszStatus);
        }
    }
    else
    {
        Ok("CPGSR_RETURN_CREDENTIAL_FINISHED, %lu bytes", cpcs.cbSerialization);

        Info("authPackage: %lu (looked up at runtime, not hardcoded)",
             cpcs.ulAuthenticationPackage);
        if (cpcs.ulAuthenticationPackage == 0)
        {
            Fail("authentication package is 0 -- lookup did not happen");
        }

        if (IsEqualGUID(cpcs.clsidCredentialProvider, CLSID_LibGuestCredentialProvider))
        {
            Ok("clsidCredentialProvider matches the provider's own CLSID");
        }
        else
        {
            Fail("clsidCredentialProvider does not match the provider's CLSID");
        }

        DumpKerbBuffer(cpcs.rgbSerialization, cpcs.cbSerialization);

        // Confirm the credential dropped its copy of the password.
        PWSTR pwszEcho = nullptr;
        if (SUCCEEDED(pCred->GetStringValue(LGFI_PASSWORD, &pwszEcho)))
        {
            if (pwszEcho == nullptr || pwszEcho[0] == L'\0')
            {
                Ok("password field is empty after serialization");
            }
            else
            {
                Fail("password field still holds %zu characters after serialization",
                     wcslen(pwszEcho));
            }
            CoTaskMemFree(pwszEcho);
        }

        if (fLsaLogon)
        {
            TryLsaLogon(cpcs.ulAuthenticationPackage,
                        cpcs.rgbSerialization, cpcs.cbSerialization);
        }
        else
        {
            Info("");
            Info("Pass --logon (as SYSTEM) to submit this buffer to LsaLogonUser");
            Info("and find out whether LSA accepts it.");
        }
    }

    if (cpcs.rgbSerialization != nullptr)
    {
        SecureZeroMemory(cpcs.rgbSerialization, cpcs.cbSerialization);
        CoTaskMemFree(cpcs.rgbSerialization);
    }
    CoTaskMemFree(pwszStatus);

    // ---- Generic failure text ------------------------------------------
    Section("ReportResult");

    {
        // STATUS_LOGON_FAILURE and STATUS_NO_SUCH_USER must be indistinguishable
        // to the patron (README.md, "Proposed user experience").
        PWSTR pwszA = nullptr, pwszB = nullptr;
        CREDENTIAL_PROVIDER_STATUS_ICON iconA, iconB;
        pCred->ReportResult(static_cast<NTSTATUS>(0xC000006DL), 0, &pwszA, &iconA);
        pCred->ReportResult(static_cast<NTSTATUS>(0xC0000064L), 0, &pwszB, &iconB);

        if (pwszA != nullptr && pwszB != nullptr && wcscmp(pwszA, pwszB) == 0)
        {
            Ok("bad password and unknown account produce identical text");
            Info("\"%ls\"", pwszA);
        }
        else
        {
            Fail("failure text differs between bad password and unknown account");
            Info("bad password : %ls", pwszA ? pwszA : L"(null)");
            Info("unknown user : %ls", pwszB ? pwszB : L"(null)");
        }
        CoTaskMemFree(pwszA);
        CoTaskMemFree(pwszB);
    }

    // ---- Teardown -------------------------------------------------------
    Section("Teardown");

    pCred->Release();
    pProvider->Release();

    if (hDll != nullptr)
    {
        typedef HRESULT(STDAPICALLTYPE * PFN_DllCanUnloadNow)();
        PFN_DllCanUnloadNow pfnCanUnload = reinterpret_cast<PFN_DllCanUnloadNow>(
            reinterpret_cast<void*>(GetProcAddress(hDll, "DllCanUnloadNow")));
        if (pfnCanUnload != nullptr)
        {
            HRESULT hrUnload = pfnCanUnload();
            if (hrUnload == S_OK)
            {
                Ok("DllCanUnloadNow returned S_OK -- no objects leaked");
            }
            else
            {
                Fail("DllCanUnloadNow returned S_FALSE -- objects still outstanding");
            }
        }
        FreeLibrary(hDll);
    }

    CoUninitialize();

    printf("\n");
    if (g_failures == 0)
    {
        printf("All checks passed.\n");
        return 0;
    }
    printf("%d check(s) failed.\n", g_failures);
    return 1;
}
