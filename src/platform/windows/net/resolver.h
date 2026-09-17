// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef CRIMSON_PLATFORM_WINDOWS_NET_RESOLVER_H
#define CRIMSON_PLATFORM_WINDOWS_NET_RESOLVER_H

#include <expected>
#include <vector>

#include "core/net/endpoint.h"
#include "core/net/net_error.h"
#include "platform/windows/net/win_sockets.h"

// Hostname resolution.
//
// The resolver returns CANDIDATES and nothing more. It does not attempt a
// connection and does not decide which address is best. Deciding that belongs
// to the connector, which is the only component that can actually find out.
// Keeping the two apart is what makes fast IPv6-to-IPv4 fallback possible.

namespace crimson::net::win {

// One resolved socket address, copied out of the ADDRINFOW list so it owns its
// storage and outlives the list.
//
// The whole sockaddr_storage is retained along with its length, rather than
// just the address bytes. sockaddr_in6::sin6_scope_id is load-bearing for
// link-local addresses, and dropping it produces connections that work on some
// networks and fail mysteriously on others.
struct ResolvedAddress {
    sockaddr_storage storage{};
    int length = 0;
    int family = 0;
    int socket_type = 0;
    int protocol = 0;

    [[nodiscard]] const sockaddr* address() const noexcept {
        return reinterpret_cast<const sockaddr*>(&storage);
    }
};

// Resolves a hostname and port into TCP candidates, in the order Windows
// returns them (which already reflects the system's address-selection policy).
//
// Accepts DNS names, IPv4 literals, and IPv6 literals with or without square
// brackets. Internationalized names are handled because this uses GetAddrInfoW:
// the wide version applies IDN-to-punycode encoding itself, which a mail client
// needs the first time somebody types an address at a host like "müller.de".
//
// Not noexcept: it allocates the candidate vector.
[[nodiscard]] std::expected<std::vector<ResolvedAddress>, NetError> resolve(
    const Endpoint& endpoint);

// Formats a socket address as a numeric string for diagnostics.
//
// Uses GetNameInfoW with NI_NUMERICHOST, never inet_ntoa (IPv4 only, and not
// thread-safe) or WSAAddressToString (deprecated, and would fail the build
// under /WX).
[[nodiscard]] std::expected<PeerAddress, NetError> describe_address(
    const sockaddr* address, int length);

// Maps a Winsock AF_* constant onto the SDK-free enum in core.
[[nodiscard]] AddressFamily to_address_family(int winsock_family) noexcept;

}  // namespace crimson::net::win

#endif  // CRIMSON_PLATFORM_WINDOWS_NET_RESOLVER_H
