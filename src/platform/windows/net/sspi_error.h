// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef CRIMSON_PLATFORM_WINDOWS_NET_SSPI_ERROR_H
#define CRIMSON_PLATFORM_WINDOWS_NET_SSPI_ERROR_H

#include <string>

#include "core/net/net_error.h"

// Translation from Schannel's SECURITY_STATUS codes into NetError, in the same
// shape as wsa_error.h. The status is taken as a plain long (SECURITY_STATUS is
// LONG) so this header needs no SSPI headers of its own.

namespace crimson::net::win {

// Wraps a failing SECURITY_STATUS. Unlike Winsock, SSPI returns its status
// directly rather than through the last-error slot, so there is nothing to
// capture before cleanup.
[[nodiscard]] NetError from_sspi(NetOp op, long status) noexcept;

// Who could usefully retry.
//
// Certificate failures are permanent: an expired or untrusted certificate will
// be exactly as expired and untrusted on the next attempt, and hammering a
// server about it helps nobody. They need a person — the user or the server's
// administrator. Corrupted or unexpected records, by contrast, are worth a
// fresh connection.
[[nodiscard]] Retry classify_sspi(long status) noexcept;

// True when the failure is about the server's certificate — expired, untrusted,
// issued for a different name, revoked. The interface will want to say
// something specific about these rather than "couldn't connect".
[[nodiscard]] bool is_certificate_error(const NetError& error) noexcept;

// "SEC_E_UNTRUSTED_ROOT", or the hex value for codes Crimson does not name.
[[nodiscard]] std::string sspi_symbolic_name(long status);

// The symbolic name of any NetError's native code, whichever API produced it.
[[nodiscard]] std::string error_name(const NetError& error);

}  // namespace crimson::net::win

#endif  // CRIMSON_PLATFORM_WINDOWS_NET_SSPI_ERROR_H
