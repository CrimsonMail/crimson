// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#include "platform/windows/net/resolver.h"

#include "platform/windows/net/net_log.h"
#include "platform/windows/net/wsa_error.h"

#include <chrono>
#include <cstring>
#include <memory>
#include <string>
#include <string_view>

namespace crimson::net::win {

namespace {

// ADDRINFOW lists must be released with FreeAddrInfoW on every path, including
// the early returns in the copy loop below. An owning pointer removes the
// possibility of forgetting.
struct AddrInfoDeleter {
    void operator()(ADDRINFOW* list) const noexcept {
        if (list != nullptr) {
            ::FreeAddrInfoW(list);
        }
    }
};

using AddrInfoPtr = std::unique_ptr<ADDRINFOW, AddrInfoDeleter>;

[[nodiscard]] std::wstring to_wide(std::string_view utf8) {
    if (utf8.empty()) {
        return std::wstring{};
    }
    const int needed = ::MultiByteToWideChar(
        CP_UTF8, 0, utf8.data(), static_cast<int>(utf8.size()), nullptr, 0);
    if (needed <= 0) {
        return std::wstring{};
    }
    std::wstring wide(static_cast<std::size_t>(needed), L'\0');
    const int converted = ::MultiByteToWideChar(
        CP_UTF8, 0, utf8.data(), static_cast<int>(utf8.size()), wide.data(), needed);
    if (converted <= 0) {
        return std::wstring{};
    }
    wide.resize(static_cast<std::size_t>(converted));
    return wide;
}

[[nodiscard]] std::string to_utf8(const wchar_t* wide) {
    if (wide == nullptr || wide[0] == L'\0') {
        return std::string{};
    }
    const int needed =
        ::WideCharToMultiByte(CP_UTF8, 0, wide, -1, nullptr, 0, nullptr, nullptr);
    if (needed <= 1) {
        return std::string{};
    }
    // `needed` includes the terminating null because the input length was -1.
    std::string utf8(static_cast<std::size_t>(needed - 1), '\0');
    const int converted = ::WideCharToMultiByte(
        CP_UTF8, 0, wide, -1, utf8.data(), needed, nullptr, nullptr);
    if (converted <= 1) {
        return std::string{};
    }
    utf8.resize(static_cast<std::size_t>(converted - 1));
    return utf8;
}

// GetAddrInfoW rejects the bracketed IPv6 form, but users type it and
// configuration files contain it, so accept "[::1]" and hand on "::1".
[[nodiscard]] std::string_view strip_ipv6_brackets(std::string_view host) noexcept {
    if (host.size() >= 2 && host.front() == '[' && host.back() == ']') {
        return host.substr(1, host.size() - 2);
    }
    return host;
}

}  // namespace

AddressFamily to_address_family(int winsock_family) noexcept {
    switch (winsock_family) {
        case AF_INET:
            return AddressFamily::ipv4;
        case AF_INET6:
            return AddressFamily::ipv6;
        default:
            return AddressFamily::unspecified;
    }
}

std::expected<std::vector<ResolvedAddress>, NetError> resolve(const Endpoint& endpoint) {
    if (endpoint.host.empty()) {
        return std::unexpected(NetError::logic(NetOp::resolve));
    }

    const std::wstring host = to_wide(strip_ipv6_brackets(endpoint.host));
    if (host.empty()) {
        return std::unexpected(NetError::logic(NetOp::resolve));
    }
    const std::wstring service = std::to_wstring(endpoint.port);

    ADDRINFOW hints{};
    hints.ai_family = AF_UNSPEC;  // both families; the connector sorts it out
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    // AI_NUMERICSERV because the service is always a number here, which avoids
    // a pointless lookup in the services file.
    //
    // AI_ADDRCONFIG is deliberately NOT set. It looks like exactly what a
    // dual-stack client wants — omit families the host has no address for — but
    // on Windows a host with only loopback IPv6 can fail to qualify as
    // "IPv6 configured", which makes resolving ::1 fail outright and would
    // break the IPv6 loopback tests. Crimson does not need it anyway: the
    // connector's per-candidate deadline already discards an unreachable
    // candidate in milliseconds rather than the 21 seconds a blocking connect
    // would take.
    hints.ai_flags = AI_NUMERICSERV;

    // Resolution is timed because it is a common and easily misattributed
    // source of connection latency: a slow or unreachable resolver looks
    // exactly like a slow server from the outside. Step 1 §24 asks for this.
    const auto resolve_started = std::chrono::steady_clock::now();

    ADDRINFOW* raw = nullptr;
    const int status = ::GetAddrInfoW(host.c_str(), service.c_str(), &hints, &raw);
    const auto resolve_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                std::chrono::steady_clock::now() - resolve_started)
                                .count();
    if (status != 0) {
        // GetAddrInfoW reports through its return value, so there is no
        // last-error slot to race with here.
        const NetError error = from_gai(NetOp::resolve, status);
        log_event(LogLevel::warn, "dns_failed",
                  {{"host", endpoint.host},
                   {"port", std::to_string(endpoint.port)},
                   {"code", symbolic_name(status)},
                   {"elapsed_ms", std::to_string(resolve_ms)}});
        return std::unexpected(error);
    }
    const AddrInfoPtr list{raw};

    std::vector<ResolvedAddress> candidates;
    for (const ADDRINFOW* entry = list.get(); entry != nullptr; entry = entry->ai_next) {
        if (entry->ai_addr == nullptr || entry->ai_addrlen == 0) {
            continue;
        }
        if (entry->ai_addrlen > sizeof(sockaddr_storage)) {
            continue;  // cannot happen for AF_INET/AF_INET6; skip rather than truncate
        }

        ResolvedAddress candidate;
        std::memcpy(&candidate.storage, entry->ai_addr, entry->ai_addrlen);
        candidate.length = static_cast<int>(entry->ai_addrlen);
        candidate.family = entry->ai_family;
        candidate.socket_type = entry->ai_socktype;
        candidate.protocol = entry->ai_protocol;
        candidates.push_back(candidate);
    }

    if (candidates.empty()) {
        // A successful lookup that yielded nothing usable. WSANO_DATA is the
        // closest honest code: the name exists but has no address of a kind we
        // can use.
        return std::unexpected(from_gai(NetOp::resolve, WSANO_DATA));
    }

    log_event(LogLevel::info, "dns_resolved",
              {{"host", endpoint.host},
               {"port", std::to_string(endpoint.port)},
               {"candidates", std::to_string(candidates.size())},
               {"elapsed_ms", std::to_string(resolve_ms)}});

    return candidates;
}

std::expected<PeerAddress, NetError> describe_address(const sockaddr* address,
                                                      int length) {
    if (address == nullptr || length <= 0) {
        return std::unexpected(NetError::logic(NetOp::getname));
    }

    wchar_t host[NI_MAXHOST] = {};
    wchar_t service[NI_MAXSERV] = {};

    const int status = ::GetNameInfoW(address, length, host, NI_MAXHOST, service,
                                      NI_MAXSERV, NI_NUMERICHOST | NI_NUMERICSERV);
    if (status != 0) {
        return std::unexpected(from_wsa(NetOp::getname));
    }

    PeerAddress peer;
    peer.address = to_utf8(host);
    peer.family = to_address_family(address->sa_family);

    const std::string port_text = to_utf8(service);
    if (!port_text.empty()) {
        // NI_NUMERICSERV guarantees digits, but a hostile or broken provider
        // should not be able to throw out of a diagnostic path.
        unsigned long parsed = 0;
        for (const char digit : port_text) {
            if (digit < '0' || digit > '9') {
                parsed = 0;
                break;
            }
            parsed = parsed * 10 + static_cast<unsigned long>(digit - '0');
            if (parsed > 65535) {
                parsed = 0;
                break;
            }
        }
        peer.port = static_cast<std::uint16_t>(parsed);
    }

    return peer;
}

}  // namespace crimson::net::win
