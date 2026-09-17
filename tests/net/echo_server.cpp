// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#include "net/echo_server.h"

#include "platform/windows/net/socket_handle.h"
#include "platform/windows/net/win_sockets.h"
#include "platform/windows/net/wsa_error.h"

#include <algorithm>
#include <cstring>
#include <limits>
#include <span>
#include <thread>

namespace crimson::test {

namespace {

using crimson::net::NetError;
using crimson::net::NetOp;
using crimson::net::win::from_wsa;
using crimson::net::win::SocketHandle;

// Bound on any single blocking call inside the server thread, so a
// misbehaving test cannot leave the worker parked forever and make the
// destructor's join hang. The harness watchdog is the backstop; this keeps the
// server itself from being the cause.
constexpr DWORD kServerIoTimeoutMs = 2000;

// How long the accept loop waits before re-checking the stop flag.
constexpr int kAcceptPollMs = 100;

[[nodiscard]] bool set_option(SOCKET socket, int level, int name, const void* value,
                              int size) noexcept {
    return ::setsockopt(socket, level, name, static_cast<const char*>(value), size) !=
           SOCKET_ERROR;
}

void send_all(SOCKET socket, std::span<const std::byte> data) noexcept {
    std::size_t offset = 0;
    while (offset < data.size()) {
        const int chunk = static_cast<int>(
            std::min<std::size_t>(data.size() - offset,
                                  static_cast<std::size_t>(std::numeric_limits<int>::max())));
        const int sent = ::send(socket, reinterpret_cast<const char*>(data.data() + offset),
                                chunk, 0);
        if (sent <= 0) {
            return;  // client vanished; the test will observe that on its side
        }
        offset += static_cast<std::size_t>(sent);
    }
}

}  // namespace

std::vector<std::byte> bytes(std::string_view text) {
    const auto* first = reinterpret_cast<const std::byte*>(text.data());
    return std::vector<std::byte>{first, first + text.size()};
}

struct TestServer::State {
    SocketHandle listener;
    std::thread worker;
    std::atomic<bool> stopping{false};
    std::atomic<std::size_t> drained{0};
    std::atomic<std::size_t> connections{0};
    Script script;
    std::uint16_t port = 0;
    int family = AF_INET;

    void serve(SOCKET client) noexcept;
    void run() noexcept;
};

void TestServer::State::serve(SOCKET client) noexcept {
    // Bounded blocking on both directions. SO_SNDTIMEO is unsafe for a real
    // connection because a timed-out send leaves it in an indeterminate state,
    // but here that is exactly what we want: give up and drop the connection
    // rather than wedge the worker.
    const DWORD timeout = kServerIoTimeoutMs;
    (void)set_option(client, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    (void)set_option(client, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

    std::vector<char> buffer(64 * 1024);

    for (const Action& action : script) {
        if (stopping.load(std::memory_order_acquire)) {
            return;
        }

        if (const auto* send_action = std::get_if<Send>(&action)) {
            send_all(client, send_action->data);
        } else if (const auto* fragmented = std::get_if<SendFragmented>(&action)) {
            const std::size_t chunk = fragmented->chunk == 0 ? 1 : fragmented->chunk;
            for (std::size_t offset = 0; offset < fragmented->data.size(); offset += chunk) {
                const std::size_t count =
                    std::min(chunk, fragmented->data.size() - offset);
                send_all(client, std::span{fragmented->data}.subspan(offset, count));
                if (fragmented->gap.count() > 0) {
                    std::this_thread::sleep_for(fragmented->gap);
                }
                if (stopping.load(std::memory_order_acquire)) {
                    return;
                }
            }
        } else if (const auto* echo = std::get_if<EchoBytes>(&action)) {
            std::size_t remaining = echo->count;
            while (remaining > 0) {
                const int want = static_cast<int>(std::min(buffer.size(), remaining));
                const int got = ::recv(client, buffer.data(), want, 0);
                if (got <= 0) {
                    return;
                }
                send_all(client, std::span{reinterpret_cast<const std::byte*>(buffer.data()),
                                           static_cast<std::size_t>(got)});
                remaining -= static_cast<std::size_t>(got);
            }
        } else if (std::get_if<DrainToEof>(&action) != nullptr) {
            for (;;) {
                const int got = ::recv(client, buffer.data(),
                                       static_cast<int>(buffer.size()), 0);
                if (got == 0) {
                    break;  // client half-closed, which is the expected end
                }
                if (got < 0) {
                    return;
                }
                drained.fetch_add(static_cast<std::size_t>(got), std::memory_order_relaxed);
            }
        } else if (const auto* pause = std::get_if<Idle>(&action)) {
            // Slice the wait so teardown does not have to wait it out.
            const auto deadline = std::chrono::steady_clock::now() + pause->duration;
            while (std::chrono::steady_clock::now() < deadline) {
                if (stopping.load(std::memory_order_acquire)) {
                    return;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds{10});
            }
        } else if (std::get_if<HalfClose>(&action) != nullptr) {
            ::shutdown(client, SD_SEND);
        } else if (std::get_if<AbortNow>(&action) != nullptr) {
            // Zero linger turns closesocket into an RST rather than a FIN,
            // which is what produces WSAECONNRESET on the client.
            ::linger abort_linger{};
            abort_linger.l_onoff = 1;
            abort_linger.l_linger = 0;
            (void)set_option(client, SOL_SOCKET, SO_LINGER, &abort_linger,
                             sizeof(abort_linger));
            return;  // caller closes, now abortively
        }
    }
}

void TestServer::State::run() noexcept {
    // Non-blocking listener polled in slices. Closing the listener from the
    // test thread to break a blocking accept would hit exactly the handle-reuse
    // hazard documented in cancel.h, so the stop flag is polled instead.
    u_long non_blocking = 1;
    (void)::ioctlsocket(listener.get(), FIONBIO, &non_blocking);

    while (!stopping.load(std::memory_order_acquire)) {
        WSAPOLLFD entry{};
        entry.fd = listener.get();
        entry.events = POLLRDNORM;

        const int ready = ::WSAPoll(&entry, 1, kAcceptPollMs);
        if (ready <= 0) {
            continue;  // timed out, or the listener is going away
        }

        SocketHandle client{::accept(listener.get(), nullptr, nullptr)};
        if (!client.valid()) {
            continue;
        }

        // The accepted socket inherits non-blocking mode from the listener on
        // Windows; the script logic is written against blocking calls.
        u_long blocking = 0;
        (void)::ioctlsocket(client.get(), FIONBIO, &blocking);

        connections.fetch_add(1, std::memory_order_relaxed);
        serve(client.get());
        // client closes here; abortively if the script ended with AbortNow.
    }
}

TestServer::TestServer(std::unique_ptr<State> state) noexcept : state_(std::move(state)) {}

TestServer::TestServer(TestServer&&) noexcept = default;
TestServer& TestServer::operator=(TestServer&&) noexcept = default;

TestServer::~TestServer() { stop(); }

std::expected<TestServer, NetError> TestServer::start(int family, Script script) {
    auto state = std::make_unique<State>();
    state->script = std::move(script);
    state->family = family;

    state->listener.reset(::WSASocketW(family, SOCK_STREAM, IPPROTO_TCP, nullptr, 0,
                                       WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT));
    if (!state->listener.valid()) {
        return std::unexpected(from_wsa(NetOp::socket));
    }

    // SO_EXCLUSIVEADDRUSE, never SO_REUSEADDR. Windows' SO_REUSEADDR does not
    // mean what it means on POSIX: it allows another process to bind the same
    // address and hijack the port.
    const BOOL exclusive = TRUE;
    if (!set_option(state->listener.get(), SOL_SOCKET, SO_EXCLUSIVEADDRUSE, &exclusive,
                    sizeof(exclusive))) {
        return std::unexpected(from_wsa(NetOp::sockopt));
    }

    sockaddr_storage storage{};
    int address_length = 0;
    if (family == AF_INET6) {
        auto* address = reinterpret_cast<sockaddr_in6*>(&storage);
        address->sin6_family = AF_INET6;
        address->sin6_addr = in6addr_loopback;
        address->sin6_port = 0;
        address_length = static_cast<int>(sizeof(sockaddr_in6));
    } else {
        auto* address = reinterpret_cast<sockaddr_in*>(&storage);
        address->sin_family = AF_INET;
        address->sin_addr.s_addr = ::htonl(INADDR_LOOPBACK);
        address->sin_port = 0;
        address_length = static_cast<int>(sizeof(sockaddr_in));
    }

    if (::bind(state->listener.get(), reinterpret_cast<const sockaddr*>(&storage),
               address_length) == SOCKET_ERROR) {
        return std::unexpected(from_wsa(NetOp::bind));
    }
    if (::listen(state->listener.get(), SOMAXCONN) == SOCKET_ERROR) {
        return std::unexpected(from_wsa(NetOp::bind));
    }

    // Read the assigned port BEFORE the acceptor starts. Because the backlog
    // already exists at this point, a client can connect the instant start()
    // returns, with no readiness handshake and no race.
    sockaddr_storage bound{};
    int bound_length = static_cast<int>(sizeof(bound));
    if (::getsockname(state->listener.get(), reinterpret_cast<sockaddr*>(&bound),
                      &bound_length) == SOCKET_ERROR) {
        return std::unexpected(from_wsa(NetOp::getname));
    }
    state->port = ::ntohs(family == AF_INET6
                              ? reinterpret_cast<const sockaddr_in6*>(&bound)->sin6_port
                              : reinterpret_cast<const sockaddr_in*>(&bound)->sin_port);

    State* raw = state.get();
    state->worker = std::thread{[raw] { raw->run(); }};

    return TestServer{std::move(state)};
}

void TestServer::stop() noexcept {
    if (state_ == nullptr) {
        return;
    }
    state_->stopping.store(true, std::memory_order_release);
    if (state_->worker.joinable()) {
        state_->worker.join();
    }
    state_->listener.reset();
}

std::uint16_t TestServer::port() const noexcept {
    return state_ == nullptr ? 0 : state_->port;
}

std::string TestServer::host() const {
    if (state_ != nullptr && state_->family == AF_INET6) {
        return "::1";
    }
    return "127.0.0.1";
}

std::size_t TestServer::bytes_drained() const noexcept {
    return state_ == nullptr ? 0
                             : state_->drained.load(std::memory_order_relaxed);
}

std::size_t TestServer::connections() const noexcept {
    return state_ == nullptr ? 0
                             : state_->connections.load(std::memory_order_relaxed);
}

}  // namespace crimson::test
