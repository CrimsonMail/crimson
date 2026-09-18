// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef CRIMSON_PLATFORM_WINDOWS_NET_WIN_SECURITY_H
#define CRIMSON_PLATFORM_WINDOWS_NET_WIN_SECURITY_H

// The single owner of SSPI and Schannel include order, as win_sockets.h is for
// Winsock. Nothing else includes <sspi.h>, <schannel.h> or <wincrypt.h>
// directly.
//
// Three things have to be true, in this order, and each one fails in a way
// that does not name its cause:
//
//   1. windows.h, arriving through win_sockets.h so Winsock's own ordering
//      rule is respected.
//
//   2. SECURITY_WIN32 defined before <sspi.h>. sspi.h serves user mode and
//      kernel mode and refuses to guess which it is in.
//
//   3. SCHANNEL_USE_BLACKLISTS defined before <schannel.h>, with UNICODE_STRING
//      already declared. Without the macro, SCH_CREDENTIALS and TLS_PARAMETERS
//      simply do not exist, and the only visible credential structure is the
//      deprecated SCHANNEL_CRED — the one that cannot express "disable these
//      protocols" and therefore cannot let newer TLS versions arrive on their
//      own. The macro's name is historical; it has nothing to do with lists of
//      anything. UNICODE_STRING comes from <winternl.h>.

#include "platform/windows/net/win_sockets.h"

#include <winternl.h>  // UNICODE_STRING, required by schannel.h below

#ifndef SECURITY_WIN32
#define SECURITY_WIN32
#endif
#include <sspi.h>

#include <wincrypt.h>

#ifndef SCHANNEL_USE_BLACKLISTS
#define SCHANNEL_USE_BLACKLISTS
#endif
#include <schannel.h>

// secur32.lib and crypt32.lib are linked via build/Crimson.Common.props.

#endif  // CRIMSON_PLATFORM_WINDOWS_NET_WIN_SECURITY_H
