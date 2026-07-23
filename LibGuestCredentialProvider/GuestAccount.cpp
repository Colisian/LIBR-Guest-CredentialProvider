#include "GuestAccount.h"

#include <strsafe.h>

namespace
{
    const WCHAR c_szPrefix[] = L"libguest";
    const size_t c_cchPrefix = ARRAYSIZE(c_szPrefix) - 1;

    bool IsSpace(WCHAR ch)
    {
        return ch == L' ' || ch == L'\t';
    }
}

HRESULT GuestAccountParse(
    _In_opt_ PCWSTR pwszInput,
    _Out_writes_(cchAccount) PWSTR pwszAccountOut,
    size_t cchAccount)
{
    if (pwszAccountOut == nullptr || cchAccount < 32)
    {
        return E_INVALIDARG;
    }
    *pwszAccountOut = L'\0';

    if (pwszInput == nullptr)
    {
        return E_INVALIDARG;
    }

    PCWSTR pwz = pwszInput;
    while (IsSpace(*pwz))
    {
        pwz++;
    }

    // Optional "libguest" prefix.
    if (CompareStringOrdinal(pwz, static_cast<int>(c_cchPrefix), c_szPrefix,
                             static_cast<int>(c_cchPrefix), TRUE) == CSTR_EQUAL)
    {
        pwz += c_cchPrefix;
    }

    // Require at least one digit, and digits only from here to trailing space.
    if (*pwz < L'0' || *pwz > L'9')
    {
        return E_INVALIDARG;
    }

    unsigned int value = 0;
    while (*pwz >= L'0' && *pwz <= L'9')
    {
        // Bounded well below overflow by the max check below, but keep the
        // accumulator from running away on a long digit string.
        if (value > LIBGUEST_MAX_NUMBER)
        {
            return E_INVALIDARG;
        }
        value = (value * 10) + static_cast<unsigned int>(*pwz - L'0');
        pwz++;
    }

    while (IsSpace(*pwz))
    {
        pwz++;
    }
    if (*pwz != L'\0')
    {
        return E_INVALIDARG;
    }

    if (value < LIBGUEST_MIN_NUMBER || value > LIBGUEST_MAX_NUMBER)
    {
        return E_INVALIDARG;
    }

    return StringCchPrintfW(pwszAccountOut, cchAccount, L"%s%u", c_szPrefix, value);
}
