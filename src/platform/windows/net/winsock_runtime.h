// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef CRIMSON_PLATFORM_WINDOWS_NET_WINSOCK_RUNTIME_H
#define CRIMSON_PLATFORM_WINDOWS_NET_WINSOCK_RUNTIME_H

#include <expected>

#include "core/net/net_error.h"

namespace crimson::net::win {

// Owns the process's Winsock initialization.
//
// Construct exactly one of these in main() and let it outlive every thread
// that touches a socket:
//
//     int main() {
//         auto winsock = WinsockScope::create();
//         if (!winsock) { ...report...; return 1; }
//         run();                  // workers start and are joined inside
//     }                           // WSACleanup happens here
//
// Two shapes that look convenient and are not:
//
//   - A function-local static. It is destroyed during exit, which can run
//     WSACleanup while a detached worker is still blocked in recv.
//   - Per-object or per-connection WSAStartup/WSACleanup pairs. The calls are
//     reference counted, so the final WSACleanup invalidates every socket in
//     the process. One connection closing must not be able to do that.
//
// Note that WSAGetLastError() is meaningless before a successful WSAStartup,
// which is why WSAStartup returns its error code directly and create() uses
// that value rather than calling from_wsa().
class WinsockScope {
public:
    [[nodiscard]] static std::expected<WinsockScope, NetError> create() noexcept;

    ~WinsockScope() noexcept;

    WinsockScope(const WinsockScope&) = delete;
    WinsockScope& operator=(const WinsockScope&) = delete;

    WinsockScope(WinsockScope&& other) noexcept;
    WinsockScope& operator=(WinsockScope&& other) noexcept;

    [[nodiscard]] bool active() const noexcept { return active_; }

private:
    WinsockScope() noexcept = default;

    bool active_ = false;
};

}  // namespace crimson::net::win

#endif  // CRIMSON_PLATFORM_WINDOWS_NET_WINSOCK_RUNTIME_H
