// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#include "platform/windows/net/winsock_runtime.h"

#include "platform/windows/net/win_sockets.h"

#include <utility>

namespace crimson::net::win {

std::expected<WinsockScope, NetError> WinsockScope::create() noexcept {
    WSADATA data{};
    // Winsock 2.2. WSAStartup returns the error code directly; the last-error
    // slot is not usable yet at this point.
    const int result = ::WSAStartup(MAKEWORD(2, 2), &data);
    if (result != 0) {
        return std::unexpected(NetError{result, NetOp::startup, NetCat::wsa, Retry::no});
    }

    // A provider is allowed to return a version lower than requested. Crimson
    // needs 2.2 for getaddrinfo and WSAPoll, so a lower version is fatal
    // rather than something to work around.
    if (LOBYTE(data.wVersion) != 2 || HIBYTE(data.wVersion) != 2) {
        ::WSACleanup();
        return std::unexpected(
            NetError{WSAVERNOTSUPPORTED, NetOp::startup, NetCat::wsa, Retry::no});
    }

    WinsockScope scope;
    scope.active_ = true;
    return scope;
}

WinsockScope::~WinsockScope() noexcept {
    if (active_) {
        ::WSACleanup();
        active_ = false;
    }
}

WinsockScope::WinsockScope(WinsockScope&& other) noexcept
    : active_(std::exchange(other.active_, false)) {}

WinsockScope& WinsockScope::operator=(WinsockScope&& other) noexcept {
    if (this != &other) {
        if (active_) {
            ::WSACleanup();
        }
        active_ = std::exchange(other.active_, false);
    }
    return *this;
}

}  // namespace crimson::net::win
