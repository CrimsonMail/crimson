// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef CRIMSON_CORE_NET_NET_ERROR_H
#define CRIMSON_CORE_NET_NET_ERROR_H

#include <cstdint>
#include <string_view>
#include <type_traits>

// This header deliberately includes NO Windows headers.
//
// `native` is a plain int rather than a Winsock typedef, which keeps every
// consumer of the byte-stream abstraction free of <winsock2.h>. That matters
// well beyond tidiness: the IMAP tokenizer and its fake-stream tests must be
// compilable and testable without the Windows SDK (see ADR 0005).
//
// Translating a Winsock or getaddrinfo code into a NetError is the job of
// platform/windows/net/wsa_error.h, which is the only place that knows what
// WSAECONNRESET means.

namespace crimson::net {

// Which operation failed. Carried so a diagnostic can say "DNS resolution
// failed for imap.example.com" rather than the useless "connect failed".
enum class NetOp : std::uint8_t {
    startup,
    resolve,
    socket,
    sockopt,
    bind,
    connect,
    poll,
    recv,
    send,
    shutdown,
    close,
    getname,
    ioctl,
};

// Where the code in `native` came from, and hence how to interpret it.
//
// The distinction between `wsa` and `gai` is not pedantry: on Windows the
// getaddrinfo EAI_* values numerically collide with Winsock error codes
// (EAI_NONAME == WSAHOST_NOT_FOUND == 11001), so the number alone is ambiguous.
enum class NetCat : std::uint8_t {
    wsa,        // native is a WSAGetLastError() code
    gai,        // native is a GetAddrInfoW() return value
    timeout,    // our own deadline expired; native is unset
    cancelled,  // a CancelHandle was triggered; native is unset
    truncated,  // peer closed before the required bytes arrived
    logic,      // a contract violation or impossible provider result
};

// Who, if anyone, could usefully retry.
//
// A single `bool retryable` is too coarse. WSAEWOULDBLOCK and WSAECONNREFUSED
// are both "retryable", but the first means poll this same socket again and the
// second means try a different address entirely. Collapsing them forces the
// caller to re-derive the difference from `native`, which defeats the point of
// having a structured error at all.
enum class Retry : std::uint8_t {
    no,              // permanent; retrying changes nothing
    same_socket,     // transient; the existing socket is still usable
    new_connection,  // reconnect to the same endpoint
    new_candidate,   // this address is unusable; try the next resolved one
};

struct NetError {
    int native = 0;
    NetOp op = NetOp::recv;
    NetCat cat = NetCat::wsa;
    Retry retry = Retry::no;

    [[nodiscard]] constexpr bool retryable() const noexcept {
        return retry != Retry::no;
    }

    // Errors Crimson raises itself, where there is no operating system code to
    // carry. Winsock- and getaddrinfo-derived errors are built by wsa_error.h.
    [[nodiscard]] static constexpr NetError timed_out(NetOp op) noexcept {
        return NetError{0, op, NetCat::timeout, Retry::new_connection};
    }
    [[nodiscard]] static constexpr NetError cancelled(NetOp op) noexcept {
        return NetError{0, op, NetCat::cancelled, Retry::no};
    }
    [[nodiscard]] static constexpr NetError truncated(NetOp op) noexcept {
        return NetError{0, op, NetCat::truncated, Retry::new_connection};
    }
    [[nodiscard]] static constexpr NetError logic(NetOp op) noexcept {
        return NetError{0, op, NetCat::logic, Retry::no};
    }
};

// Passed and copied constantly, including through std::expected's error
// channel, so it must stay cheap and allocation-free.
static_assert(std::is_trivially_copyable_v<NetError>);
static_assert(sizeof(NetError) <= 8);

[[nodiscard]] constexpr std::string_view to_string(NetOp op) noexcept {
    switch (op) {
        case NetOp::startup:  return "startup";
        case NetOp::resolve:  return "resolve";
        case NetOp::socket:   return "socket";
        case NetOp::sockopt:  return "sockopt";
        case NetOp::bind:     return "bind";
        case NetOp::connect:  return "connect";
        case NetOp::poll:     return "poll";
        case NetOp::recv:     return "recv";
        case NetOp::send:     return "send";
        case NetOp::shutdown: return "shutdown";
        case NetOp::close:    return "close";
        case NetOp::getname:  return "getname";
        case NetOp::ioctl:    return "ioctl";
    }
    return "unknown";
}

[[nodiscard]] constexpr std::string_view to_string(NetCat cat) noexcept {
    switch (cat) {
        case NetCat::wsa:       return "wsa";
        case NetCat::gai:       return "gai";
        case NetCat::timeout:   return "timeout";
        case NetCat::cancelled: return "cancelled";
        case NetCat::truncated: return "truncated";
        case NetCat::logic:     return "logic";
    }
    return "unknown";
}

[[nodiscard]] constexpr std::string_view to_string(Retry retry) noexcept {
    switch (retry) {
        case Retry::no:             return "no";
        case Retry::same_socket:    return "same_socket";
        case Retry::new_connection: return "new_connection";
        case Retry::new_candidate:  return "new_candidate";
    }
    return "unknown";
}

}  // namespace crimson::net

#endif  // CRIMSON_CORE_NET_NET_ERROR_H
