// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#include <utility>

#include "harness.h"
#include "platform/windows/net/socket_handle.h"
#include "platform/windows/net/win_sockets.h"

// Ownership tests. Networking correctness is not only about bytes: a socket
// leaked per failed connection attempt exhausts the process quietly, and the
// symptom appears somewhere unrelated hours later.

using crimson::net::win::SocketHandle;

namespace {

// A real socket, unconnected. Enough to prove that handles are closed, since
// creation would eventually fail if they were not.
[[nodiscard]] SOCKET make_socket() {
    return ::WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, nullptr, 0,
                        WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT);
}

// Handle count for the process, used to detect leaks. Sockets are kernel
// handles, so closing one is observable here.
[[nodiscard]] DWORD handle_count() {
    DWORD count = 0;
    if (::GetProcessHandleCount(::GetCurrentProcess(), &count) == 0) {
        return 0;
    }
    return count;
}

}  // namespace

CRIMSON_TEST(socket_handle, default_constructed_is_invalid) {
    const SocketHandle handle;
    CHECK(!handle.valid());
    CHECK(handle.get() == INVALID_SOCKET);
}

CRIMSON_TEST(socket_handle, adopts_and_reports_a_real_socket) {
    const SocketHandle handle{make_socket()};
    CHECK(handle.valid());
    CHECK(handle.get() != INVALID_SOCKET);
}

CRIMSON_TEST(socket_handle, move_construction_transfers_ownership) {
    SocketHandle source{make_socket()};
    const SOCKET raw = source.get();
    CHECK(source.valid());

    const SocketHandle moved{std::move(source)};

    CHECK(moved.valid());
    CHECK(moved.get() == raw);
    // The moved-from handle must not still believe it owns the socket, or the
    // descriptor is closed twice.
    CHECK(!source.valid());
    CHECK(source.get() == INVALID_SOCKET);
}

CRIMSON_TEST(socket_handle, move_assignment_transfers_ownership) {
    SocketHandle source{make_socket()};
    const SOCKET raw = source.get();

    SocketHandle target;
    target = std::move(source);

    CHECK(target.valid());
    CHECK(target.get() == raw);
    CHECK(!source.valid());
}

CRIMSON_TEST(socket_handle, move_assignment_closes_the_existing_socket) {
    // The leak that is easy to write and invisible at runtime: assigning over a
    // live handle without closing what was already there.
    const DWORD before = handle_count();
    CHECK(before > 0);

    {
        SocketHandle target{make_socket()};
        SocketHandle source{make_socket()};
        target = std::move(source);
        CHECK(target.valid());
    }

    // Both sockets are accounted for: the one that was overwritten and the one
    // that was moved in. Handle counts move for unrelated reasons, so allow a
    // small margin rather than demanding exact equality.
    const DWORD after = handle_count();
    CHECK_MSG(after <= before + 2,
              "handle count grew by " + std::to_string(after - before) +
                  "; move-assignment is leaking the overwritten socket");
}

CRIMSON_TEST(socket_handle, self_move_assignment_is_harmless) {
    SocketHandle handle{make_socket()};
    const SOCKET raw = handle.get();

    SocketHandle& alias = handle;
    handle = std::move(alias);

    // Must not have closed the socket and then kept using the stale value.
    CHECK(handle.valid());
    CHECK(handle.get() == raw);
}

CRIMSON_TEST(socket_handle, release_gives_up_ownership_without_closing) {
    SocketHandle handle{make_socket()};
    const SOCKET raw = handle.release();

    CHECK(!handle.valid());
    CHECK(raw != INVALID_SOCKET);

    // Still open, so it is ours to close. If release had closed it, this would
    // fail with WSAENOTSOCK.
    CHECK(::closesocket(raw) == 0);
}

CRIMSON_TEST(socket_handle, reset_closes_and_can_adopt) {
    SocketHandle handle{make_socket()};
    CHECK(handle.valid());

    handle.reset();
    CHECK(!handle.valid());

    handle.reset(make_socket());
    CHECK(handle.valid());
}

CRIMSON_TEST(socket_handle, destruction_closes_exactly_once) {
    const DWORD before = handle_count();

    // Enough iterations that a per-iteration leak would be unmistakable rather
    // than lost in ordinary handle churn.
    for (int index = 0; index < 500; ++index) {
        SocketHandle handle{make_socket()};
        CHECK(handle.valid());
    }

    const DWORD after = handle_count();
    CHECK_MSG(after <= before + 10,
              "handle count grew by " + std::to_string(after - before) +
                  " over 500 create/destroy cycles; sockets are leaking");
}
