#pragma once

// Target Windows 10/11. The provider is only deployed to current Entra-only
// Windows 11 devices (see README.md), but 0x0A00 is the correct floor for the
// credential-provider V2 interfaces used here.
#include <winsdkver.h>

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00 // Windows 10+
#endif

#include <sdkddkver.h>
