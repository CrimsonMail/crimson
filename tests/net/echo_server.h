// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef CRIMSON_TESTS_NET_ECHO_SERVER_H
#define CRIMSON_TESTS_NET_ECHO_SERVER_H

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

#include "core/net/net_error.h"

// A scripted loopback server, for deterministic stream tests.
//
// The behaviours that matter for a protocol client — a response arriving one
// byte at a time, a peer vanishing mid-message, an abortive reset — are
// impossible to provoke reliably against a real mail server and awkward to
// provoke at all against a plain echo server. Scripting them makes the tests
// deterministic instead of hopeful.
//
// ANTI-FLAKE DESIGN. start() performs socket, bind, listen and getsockname on
// the CALLING thread and only then spawns the acceptor. The listen backlog
// therefore exists before start() returns, so a client may connect immediately.
// There is no readiness handshake, no condition variable and no Sleep(100) — the
// usual sources of rot in this kind of fixture.
//
// The server binds to 127.0.0.1 or ::1 specifically, never the wildcard
// address. A wildcard bind raises a Windows Defender Firewall prompt, which
// blocks interactively on a developer machine and silently drops packets in CI.

namespace crimson::test {

// Send a buffer in one call.
struct Send {
    std::vector<std::byte> data;
};

// Send a buffer in `chunk`-sized pieces, pausing `gap` between them.
//
// This is the fragmentation case: TCP guarantees ordered bytes and nothing
// about how they are grouped, and a client that assumes one read yields one
// protocol message will work perfectly until it does not.
struct SendFragmented {
    std::vector<std::byte> data;
    std::size_t chunk = 1;
    std::chrono::milliseconds gap{0};
};

// Read exactly `count` bytes and send them back. Small payloads only: see the
// deadlock note on DrainToEof.
struct EchoBytes {
    std::size_t count = 0;
};

// Read until the client closes its sending side, counting the bytes.
//
// This is how the large-write test must be shaped. A bidirectional echo of a
// megabyte against a single-threaded blocking client deadlocks: loopback send
// buffers are around 64 KB, so the client fills its send buffer while the
// server fills its own, and neither side is reading. Draining in one direction
// still proves partial writes and the FIN path, without the hang.
struct DrainToEof {};

// Do nothing for a while, holding the connection open. Used for the
// cancellation and read-timeout tests.
struct Idle {
    std::chrono::milliseconds duration{0};
};

// shutdown(SD_SEND): the client should observe a clean end of stream.
struct HalfClose {};

// SO_LINGER{1, 0} then closesocket, which emits a TCP RST.
//
// The only reliable way to get WSAECONNRESET into a test. Without it that error
// path is only ever reached by accident, and its classification would go
// unverified.
struct AbortNow {};

using Action = std::variant<Send, SendFragmented, EchoBytes, DrainToEof, Idle,
                            HalfClose, AbortNow>;
using Script = std::vector<Action>;

// Convenience for building a Send or SendFragmented payload from text.
[[nodiscard]] std::vector<std::byte> bytes(std::string_view text);

class TestServer {
public:
    // `family` is AF_INET or AF_INET6. The script runs from the start for each
    // accepted connection, so a test may connect more than once.
    [[nodiscard]] static std::expected<TestServer, crimson::net::NetError> start(
        int family, Script script);

    ~TestServer();

    TestServer(const TestServer&) = delete;
    TestServer& operator=(const TestServer&) = delete;
    TestServer(TestServer&&) noexcept;
    TestServer& operator=(TestServer&&) noexcept;

    // The ephemeral port the system assigned, read via getsockname before the
    // acceptor started.
    [[nodiscard]] std::uint16_t port() const noexcept;

    // "127.0.0.1" or "::1", matching the family.
    [[nodiscard]] std::string host() const;

    // Bytes counted by DrainToEof across all connections.
    [[nodiscard]] std::size_t bytes_drained() const noexcept;

    // Connections accepted so far.
    [[nodiscard]] std::size_t connections() const noexcept;

    // Stops accepting and joins the worker. Called by the destructor; exposed
    // so a test can tear the server down early.
    void stop() noexcept;

private:
    struct State;
    std::unique_ptr<State> state_;

    explicit TestServer(std::unique_ptr<State> state) noexcept;
};

}  // namespace crimson::test

#endif  // CRIMSON_TESTS_NET_ECHO_SERVER_H
