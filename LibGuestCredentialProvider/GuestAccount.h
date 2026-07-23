#pragma once

#include "common.h"

// Parses and validates what the patron typed into the guest-number field.
//
// Accepts either a bare number ("42") or the full account name ("libguest42"),
// case-insensitively, with surrounding whitespace tolerated. Anything else is
// rejected, including negative numbers, embedded signs, non-digits, and values
// outside LIBGUEST_MIN_NUMBER..LIBGUEST_MAX_NUMBER.
//
// On success writes the account name (e.g. L"libguest42") to pwszAccountOut.
// cchAccount must be at least 32.
HRESULT GuestAccountParse(
    _In_opt_ PCWSTR pwszInput,
    _Out_writes_(cchAccount) PWSTR pwszAccountOut,
    size_t cchAccount);
