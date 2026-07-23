#pragma once

#include "targetver.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <credentialprovider.h>
#include <ntsecapi.h>

// ntstatus.h collides with the subset of status codes windows.h already
// declares, so define the one value we need rather than fighting header order.
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

// Module reference counting (defined in dllmain.cpp).
void DllAddRef();
void DllRelease();

// ---------------------------------------------------------------------------
// Experiment dials
//
// These two constants encode the open question from README.md: can a standalone
// provider hand LSA a Kerberos interactive-logon serialization without CloudAP's
// typed-UPN discovery claiming the credential first? If the first configuration
// fails on the secure desktop, these are the knobs to turn. The test harness
// decodes the packed buffer so you can see empirically which shape is in effect.
// ---------------------------------------------------------------------------

// DIAL 1: which LSA authentication package receives the buffer.
//
// MICROSOFT_KERBEROS_NAME_A ("Kerberos") targets the Kerberos SSP directly and
// is the default because it is the least likely to be re-routed. NEGOSSP_NAME_A
// ("Negotiate") also accepts KERB_INTERACTIVE_UNLOCK_LOGON but lets SPNEGO pick
// the provider, which is the path that could hand the credential to CloudAP.
//
// Never hardcode the resulting numeric package ID; it is looked up at runtime
// (see KerbSerialize.cpp, README.md "Provider responsibilities").
#define LIBGUEST_AUTH_PACKAGE_NAME MICROSOFT_KERBEROS_NAME_A

// DIAL 2: how the principal is split across the KERB_INTERACTIVE_LOGON fields.
enum LIBGUEST_PRINCIPAL_FORMAT
{
    // LogonDomainName = L"UMD.EDU", UserName = L"libguest42".
    // Empirically REJECTED by the MIT UMD.EDU KDC: on the test device this form
    // returns 1326 / STATUS_LOGON_FAILURE via both LogonUser and LsaLogonUser.
    // MIT UMD.EDU is a bare Kerberos realm, not a Windows domain, so there is no
    // NetBIOS-style "UMD.EDU" domain for LSA to resolve the split form against.
    LGPF_SPLIT_DOMAIN_AND_USER = 0,

    // LogonDomainName = L"", UserName = L"libguest42@UMD.EDU".
    // The shape that works: `runas /user:libguest42@UMD.EDU` uses exactly this
    // (UPN in the username, no separate domain) and gets a genuine
    // krbtgt/UMD.EDU@UMD.EDU TGT from an MIT KDC (famine.umd.edu). Confirmed on
    // the AD.UMD.EDU-joined test workstation 2026-07-23.
    LGPF_UPN_IN_USERNAME = 1,
};

// Set to the UPN form after the split form was proven to fail against the MIT
// KDC (see the enum comments). NOTE: this presents a parseable "@UMD.EDU" UPN,
// which is precisely what CloudAP's typed-UPN discovery keys on -- so on an
// Entra-only device this raises the original README question of whether LogonUI
// routes the credential to us or to Entra first. That is the secure-desktop
// test, separate from whether LSA accepts the buffer (which this dial fixes).
#define LIBGUEST_PRINCIPAL_FORMAT_ACTIVE LGPF_UPN_IN_USERNAME

// The only realm this provider will ever authenticate against. Never accept a
// user-supplied realm (README.md, "Security boundaries").
#define LIBGUEST_REALM L"UMD.EDU"

// Guest account bounds, inclusive.
#define LIBGUEST_MIN_NUMBER 1
#define LIBGUEST_MAX_NUMBER 500

// ---------------------------------------------------------------------------
// Tile field layout
// ---------------------------------------------------------------------------

// No CPFT_TILE_IMAGE field yet: branding waits until a live SIMS credential
// produces a real interactive session (README.md, "Phase 2").
enum LIBGUEST_FIELD_ID
{
    LGFI_LABEL         = 0,
    LGFI_GUESTNUMBER   = 1,
    LGFI_PASSWORD      = 2,
    LGFI_SUBMIT_BUTTON = 3,
    LGFI_NOTE          = 4,
    LGFI_STATUS        = 5,
    LGFI_NUM_FIELDS    = 6,
};

static const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR s_rgLibGuestFieldDescriptors[LGFI_NUM_FIELDS] =
{
    { LGFI_LABEL,         CPFT_LARGE_TEXT,    const_cast<PWSTR>(L"Library Guest Sign-In") },
    { LGFI_GUESTNUMBER,   CPFT_EDIT_TEXT,     const_cast<PWSTR>(L"Guest number") },
    { LGFI_PASSWORD,      CPFT_PASSWORD_TEXT, const_cast<PWSTR>(L"Password") },
    { LGFI_SUBMIT_BUTTON, CPFT_SUBMIT_BUTTON, const_cast<PWSTR>(L"Sign in") },
    { LGFI_NOTE,          CPFT_SMALL_TEXT,    const_cast<PWSTR>(L"Credentials are issued by library staff.") },
    { LGFI_STATUS,        CPFT_SMALL_TEXT,    const_cast<PWSTR>(L"") },
};

static const CREDENTIAL_PROVIDER_FIELD_STATE s_rgLibGuestFieldStates[LGFI_NUM_FIELDS] =
{
    CPFS_DISPLAY_IN_BOTH,          // label
    CPFS_DISPLAY_IN_SELECTED_TILE, // guest number
    CPFS_DISPLAY_IN_SELECTED_TILE, // password
    CPFS_DISPLAY_IN_SELECTED_TILE, // submit
    CPFS_DISPLAY_IN_SELECTED_TILE, // note
    CPFS_DISPLAY_IN_SELECTED_TILE, // status
};

static const CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE s_rgLibGuestFieldInteractiveStates[LGFI_NUM_FIELDS] =
{
    CPFIS_NONE,    // label
    CPFIS_FOCUSED, // guest number
    CPFIS_NONE,    // password
    CPFIS_NONE,    // submit
    CPFIS_NONE,    // note
    CPFIS_NONE,    // status
};

// Single generic failure string. Deliberately does not distinguish an unknown
// account from a bad password (README.md, "Proposed user experience").
#define LIBGUEST_GENERIC_FAILURE \
    L"Sign-in failed. Check your guest number and password, or ask library staff for help."
