// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef CRIMSON_PLATFORM_WINDOWS_NET_SOCKET_HANDLE_H
#define CRIMSON_PLATFORM_WINDOWS_NET_SOCKET_HANDLE_H

#include "platform/windows/net/win_sockets.h"

namespace crimson::net::win {

// Sole owner of one Winsock SOCKET.
//
// Move-only: a socket has exactly one owner, and that owner closes it. Shared
// ownership would make shutdown ordering ambiguous, which for sockets is not a
// tidiness question — see the handle-reuse hazard documented on CancelHandle.
//
// Two Windows details this exists to encapsulate:
//
//   - SOCKET is UINT_PTR, i.e. unsigned. The POSIX habit of testing `fd < 0`
//     is always false here. The invalid value is INVALID_SOCKET ((SOCKET)~0).
//   - socket() and the rest report failure differently: socket() returns
//     INVALID_SOCKET while connect/recv/send return SOCKET_ERROR (-1). They are
//     routinely interchanged, and the resulting bug is silent.
class SocketHandle {
public:
    SocketHandle() noexcept = default;

    explicit SocketHandle(SOCKET socket) noexcept : socket_(socket) {}

    ~SocketHandle() noexcept { reset(); }

    SocketHandle(const SocketHandle&) = delete;
    SocketHandle& operator=(const SocketHandle&) = delete;

    SocketHandle(SocketHandle&& other) noexcept : socket_(other.socket_) {
        other.socket_ = INVALID_SOCKET;
    }

    SocketHandle& operator=(SocketHandle&& other) noexcept {
        if (this != &other) {
            reset();  // closing first is what stops move-assignment leaking
            socket_ = other.socket_;
            other.socket_ = INVALID_SOCKET;
        }
        return *this;
    }

    [[nodiscard]] bool valid() const noexcept { return socket_ != INVALID_SOCKET; }

    [[nodiscard]] SOCKET get() const noexcept { return socket_; }

    // Gives up ownership without closing. For handing the descriptor to
    // something else that will close it.
    [[nodiscard]] SOCKET release() noexcept {
        const SOCKET released = socket_;
        socket_ = INVALID_SOCKET;
        return released;
    }

    // Closes any currently held socket and optionally adopts another.
    //
    // closesocket's return value is deliberately discarded. There is no useful
    // recovery from a failed close, and this runs from destructors where
    // throwing is not an option. A close error is also not the same thing as a
    // failed graceful shutdown, which the caller performs beforehand.
    void reset(SOCKET socket = INVALID_SOCKET) noexcept {
        if (socket_ != INVALID_SOCKET) {
            ::closesocket(socket_);
        }
        socket_ = socket;
    }

private:
    SOCKET socket_ = INVALID_SOCKET;
};

}  // namespace crimson::net::win

#endif  // CRIMSON_PLATFORM_WINDOWS_NET_SOCKET_HANDLE_H
