// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef CRIMSON_PLATFORM_WINDOWS_NET_WIN_SOCKETS_H
#define CRIMSON_PLATFORM_WINDOWS_NET_WIN_SOCKETS_H

// The single owner of Winsock include order for the whole of Crimson.
//
// Nothing else in the tree includes <winsock2.h>, <ws2tcpip.h>, <mstcpip.h> or
// <windows.h> directly. Centralizing it makes the classic ordering bug
// unrepeatable rather than merely unlikely.
//
// The ordering problem: windows.h transitively includes the original
// <winsock.h>, whose declarations collide with Winsock 2. If windows.h is
// included first you get a wall of redefinition errors for sockaddr_in,
// fd_set and friends. winsock2.h must come first, and WIN32_LEAN_AND_MEAN
// suppresses much of what would otherwise drag winsock.h in.
//
// These macros are also set in build/Crimson.Common.props. They are repeated
// here defensively so this header is correct even when compiled outside that
// build, and because getting NOMINMAX wrong produces an error message that
// points nowhere near the cause.

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

// windows.h defines min and max as macros, which breaks std::min and
// std::numeric_limits<int>::max(). Both are needed by the recv/send length
// clamp, since those take an int count while Crimson works in size_t.
#ifndef NOMINMAX
#define NOMINMAX
#endif

// Windows 10/11. Required for WSAPoll and the TCP_KEEP* socket options.
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif

#include <winsock2.h>   // must precede windows.h
#include <ws2tcpip.h>   // GetAddrInfoW, GetNameInfoW, IPV6_V6ONLY
#include <mstcpip.h>    // SIO_TCP_INITIAL_RTO, keepalive structures
#include <windows.h>

// ws2_32.lib is linked via Crimson.Common.props, not a #pragma comment here.

#endif  // CRIMSON_PLATFORM_WINDOWS_NET_WIN_SOCKETS_H
