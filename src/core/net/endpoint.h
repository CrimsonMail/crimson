// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef CRIMSON_CORE_NET_ENDPOINT_H
#define CRIMSON_CORE_NET_ENDPOINT_H

#include <cstdint>
#include <string>
#include <string_view>

// No Windows headers here either. In particular there is no sockaddr in this
// file: a resolved socket address is a platform concept and lives in
// platform/windows/net/resolver.h as ResolvedAddress.
//
// The split is the one Step 1 asks for. `Endpoint` is what a user or a
// configuration file expresses ("imap.example.com", 993). `ResolvedAddress` is
// what the operating system hands back, and there are usually several of them
// for one Endpoint.

namespace crimson::net {

enum class AddressFamily : std::uint8_t {
    unspecified,
    ipv4,
    ipv6,
};

[[nodiscard]] constexpr std::string_view to_string(AddressFamily family) noexcept {
    switch (family) {
        case AddressFamily::unspecified: return "unspecified";
        case AddressFamily::ipv4:        return "ipv4";
        case AddressFamily::ipv6:        return "ipv6";
    }
    return "unknown";
}

// A host and port to connect to, before name resolution.
//
// `host` may be a DNS name, an IPv4 literal, or an IPv6 literal. Bracketed
// IPv6 forms such as "[::1]" are accepted here because users and configuration
// files contain them; the resolver strips the brackets, since GetAddrInfoW
// rejects them.
//
// `port` is a uint16_t because that is what the wire carries. Resolution needs
// a service string, and the resolver converts.
struct Endpoint {
    std::string host;
    std::uint16_t port = 0;

    [[nodiscard]] bool empty() const noexcept { return host.empty(); }
};

// Where a connection actually landed, for diagnostics.
//
// Deliberately a formatted numeric string rather than a socket address: this
// crosses into logging and, eventually, the interface, neither of which should
// need the Windows SDK. It answers the questions Step 1 §24 and §44 ask —
// which address, which family, which port — and is non-sensitive, so it is safe
// to log.
struct PeerAddress {
    std::string address;
    std::uint16_t port = 0;
    AddressFamily family = AddressFamily::unspecified;
};

}  // namespace crimson::net

#endif  // CRIMSON_CORE_NET_ENDPOINT_H
