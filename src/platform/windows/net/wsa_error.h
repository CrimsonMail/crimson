// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef CRIMSON_PLATFORM_WINDOWS_NET_WSA_ERROR_H
#define CRIMSON_PLATFORM_WINDOWS_NET_WSA_ERROR_H

#include <string>

#include "core/net/net_error.h"

// Translation from Winsock and GetAddrInfoW codes into crimson::net::NetError.
// The only place in Crimson that knows what WSAECONNRESET means.

namespace crimson::net::win {

// Captures WSAGetLastError() for the operation that just failed.
//
// Call this as the FIRST statement of a failure path, before closesocket(),
// before logging, before anything that allocates.
//
// WSAGetLastError() is literally GetLastError(): the per-thread Win32 last-error
// slot, not a separate Winsock one. Any intervening Win32 or CRT call can
// overwrite it, so the usual cleanup-then-report ordering silently reports the
// error from closesocket() rather than from the call that actually failed.
[[nodiscard]] NetError from_wsa(NetOp op) noexcept;

// As above, for a code already captured (for example from getsockopt(SO_ERROR),
// which reports a failed non-blocking connect without touching the last-error
// slot).
[[nodiscard]] NetError from_wsa_code(NetOp op, int code) noexcept;

// For a GetAddrInfoW return value.
//
// On Windows the EAI_* constants are the WSA error codes, numerically:
// EAI_NONAME, WSAHOST_NOT_FOUND and 11001 are the same value. Storing them in
// the same int is therefore fine, but the number alone cannot say which API
// produced it, which is why NetError carries NetCat::gai separately.
[[nodiscard]] NetError from_gai(NetOp op, int code) noexcept;

// Who could usefully retry, given a Winsock code. See crimson::net::Retry.
[[nodiscard]] Retry classify_wsa(int code) noexcept;

// A human-readable rendering of the native code, for diagnostics only.
//
// FormatMessageW does resolve the 10000-range Winsock codes, even though
// std::system_category does not map them to std::errc. Returns a short
// placeholder rather than failing if the system has no message for the code.
[[nodiscard]] std::string describe(const NetError& error);

// The stable symbolic name, for structured logs: "WSAECONNREFUSED".
// Falls back to the decimal number for codes Crimson does not name.
[[nodiscard]] std::string symbolic_name(int code);

}  // namespace crimson::net::win

#endif  // CRIMSON_PLATFORM_WINDOWS_NET_WSA_ERROR_H
