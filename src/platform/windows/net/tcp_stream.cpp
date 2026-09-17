// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#include "platform/windows/net/tcp_stream.h"

#include "platform/windows/net/net_log.h"
#include "platform/windows/net/resolver.h"
#include "platform/windows/net/wsa_error.h"

#include <algorithm>
#include <limits>
#include <string>
#include <utility>

namespace crimson::net::win {

namespace {

using Clock = std::chrono::steady_clock;

// recv and send take an int count while Crimson works in size_t. Clamping
// rather than casting keeps a large buffer from wrapping to a negative length.
[[nodiscard]] int clamp_to_int(std::size_t value) noexcept {
    constexpr std::size_t kMax = static_cast<std::size_t>(std::numeric_limits<int>::max());
    return static_cast<int>(std::min(value, kMax));
}

// How much a failure tells us, used to pick which candidate's error to report
// when every candidate fails.
//
// Recency is the wrong criterion. "Connection refused" from the IPv4 address
// means a host actually answered and declined, which is far more useful to a
// user than "network unreachable" from an IPv6 address their router never
// supported.
[[nodiscard]] int definiteness(const NetError& error) noexcept {
    if (error.cat == NetCat::cancelled) {
        return 100;  // the user asked; nothing else matters
    }
    if (error.cat == NetCat::timeout) {
        return 40;
    }
    switch (error.native) {
        case WSAECONNREFUSED:
            return 50;
        case WSAETIMEDOUT:
            return 40;
        case WSAEHOSTUNREACH:
        case WSAENETUNREACH:
        case WSAEHOSTDOWN:
            return 30;
        case WSAEAFNOSUPPORT:
        case WSAEADDRNOTAVAIL:
            return 10;
        default:
            return 20;
    }
}

[[nodiscard]] bool set_socket_option(SOCKET socket, int level, int name,
                                     const void* value, int size) noexcept {
    return ::setsockopt(socket, level, name, static_cast<const char*>(value), size) !=
           SOCKET_ERROR;
}

// Applies Crimson's socket policy. See ConnectOptions for why each one.
[[nodiscard]] std::expected<void, NetError> apply_options(
    SOCKET socket, const ConnectOptions& options) noexcept {
    if (options.no_delay) {
        const BOOL enabled = TRUE;
        if (!set_socket_option(socket, IPPROTO_TCP, TCP_NODELAY, &enabled,
                               sizeof(enabled))) {
            return std::unexpected(from_wsa(NetOp::sockopt));
        }
    }
    if (options.keep_alive) {
        const BOOL enabled = TRUE;
        if (!set_socket_option(socket, SOL_SOCKET, SO_KEEPALIVE, &enabled,
                               sizeof(enabled))) {
            return std::unexpected(from_wsa(NetOp::sockopt));
        }
    }
    if (options.read_timeout.count() > 0) {
        const DWORD milliseconds = static_cast<DWORD>(
            std::min<long long>(options.read_timeout.count(),
                                static_cast<long long>(std::numeric_limits<DWORD>::max())));
        if (!set_socket_option(socket, SOL_SOCKET, SO_RCVTIMEO, &milliseconds,
                               sizeof(milliseconds))) {
            return std::unexpected(from_wsa(NetOp::sockopt));
        }
    }
    // SO_SNDTIMEO is intentionally never set; see ConnectOptions.
    return {};
}

// Connects with an explicit deadline, and without blocking past it.
//
// Non-blocking connect, then WSAPoll for writability in short slices, then
// getsockopt(SO_ERROR) to find out what actually happened, then back to
// blocking mode for the caller.
[[nodiscard]] std::expected<void, NetError> connect_with_deadline(
    SOCKET socket, const sockaddr* address, int address_length,
    Clock::time_point deadline, const CancelHandle& cancel) noexcept {
    u_long non_blocking = 1;
    if (::ioctlsocket(socket, FIONBIO, &non_blocking) == SOCKET_ERROR) {
        return std::unexpected(from_wsa(NetOp::ioctl));
    }

    bool connected = false;
    if (::connect(socket, address, address_length) == SOCKET_ERROR) {
        const int immediate = ::WSAGetLastError();  // capture before anything else
        if (immediate != WSAEWOULDBLOCK) {
            return std::unexpected(from_wsa_code(NetOp::connect, immediate));
        }

        // Poll in slices rather than one long wait. shutdown() does not
        // reliably interrupt a pending connect, so re-checking the cancel flag
        // between short waits is what makes a connect cancellable at all. The
        // slice bounds cancellation latency to ~200 ms.
        constexpr long long kSliceMs = 200;
        while (!connected) {
            if (cancel.cancel_requested()) {
                return std::unexpected(NetError::cancelled(NetOp::connect));
            }

            const auto remaining = deadline - Clock::now();
            if (remaining <= std::chrono::milliseconds::zero()) {
                return std::unexpected(NetError::timed_out(NetOp::connect));
            }
            const long long remaining_ms =
                std::chrono::duration_cast<std::chrono::milliseconds>(remaining).count();
            const int slice = static_cast<int>(std::min(kSliceMs, remaining_ms));

            WSAPOLLFD poll_entry{};
            poll_entry.fd = socket;
            poll_entry.events = POLLWRNORM;

            const int ready = ::WSAPoll(&poll_entry, 1, slice);
            if (ready == SOCKET_ERROR) {
                return std::unexpected(from_wsa(NetOp::poll));
            }
            if (ready == 0) {
                continue;  // slice expired; re-check cancellation and deadline
            }

            // Writability alone does not mean success. A failed connect can
            // report POLLWRNORM together with POLLERR and POLLHUP, so SO_ERROR
            // is the only reliable answer. Skipping it yields a socket that
            // looks connected and fails on the first recv.
            int socket_error = 0;
            int size = static_cast<int>(sizeof(socket_error));
            if (::getsockopt(socket, SOL_SOCKET, SO_ERROR,
                             reinterpret_cast<char*>(&socket_error), &size) ==
                SOCKET_ERROR) {
                return std::unexpected(from_wsa(NetOp::sockopt));
            }
            if (socket_error != 0) {
                return std::unexpected(from_wsa_code(NetOp::connect, socket_error));
            }
            connected = true;
        }
    }

    // Back to blocking for the caller. FIONBIO cannot be queried, so the mode
    // is tracked by construction: every socket leaves this function blocking.
    u_long blocking = 0;
    if (::ioctlsocket(socket, FIONBIO, &blocking) == SOCKET_ERROR) {
        return std::unexpected(from_wsa(NetOp::ioctl));
    }
    return {};
}

[[nodiscard]] PeerAddress local_address_of(SOCKET socket) {
    sockaddr_storage storage{};
    int length = static_cast<int>(sizeof(storage));
    if (::getsockname(socket, reinterpret_cast<sockaddr*>(&storage), &length) ==
        SOCKET_ERROR) {
        return PeerAddress{};  // diagnostics only; not worth failing a connection
    }
    auto described = describe_address(reinterpret_cast<const sockaddr*>(&storage), length);
    if (!described) {
        return PeerAddress{};
    }
    return *described;
}

}  // namespace

TcpStream::TcpStream(SocketHandle socket, CancelHandle cancel, PeerAddress peer,
                     PeerAddress local) noexcept
    : socket_(std::move(socket)),
      cancel_(std::move(cancel)),
      peer_(std::move(peer)),
      local_(std::move(local)) {}

TcpStream::TcpStream(TcpStream&& other) noexcept
    : socket_(std::move(other.socket_)),
      cancel_(std::move(other.cancel_)),
      peer_(std::move(other.peer_)),
      local_(std::move(other.local_)) {}

TcpStream& TcpStream::operator=(TcpStream&& other) noexcept {
    if (this != &other) {
        close();  // closing first is what stops move-assignment leaking
        socket_ = std::move(other.socket_);
        cancel_ = std::move(other.cancel_);
        peer_ = std::move(other.peer_);
        local_ = std::move(other.local_);
    }
    return *this;
}

TcpStream::~TcpStream() { close(); }

std::expected<TcpStream, NetError> TcpStream::connect(const Endpoint& endpoint,
                                                      const ConnectOptions& options,
                                                      const CancelHandle& cancel) {
    const Clock::time_point started = Clock::now();
    const Clock::time_point overall_deadline = started + options.overall_timeout;

    auto candidates = resolve(endpoint);
    if (!candidates) {
        return std::unexpected(candidates.error());
    }

    // A handle is always created, so every returned stream is cancellable even
    // when the caller did not ask for one.
    const CancelHandle handle = cancel.valid() ? cancel : make_cancel_handle();

    NetError best_error = NetError::timed_out(NetOp::connect);
    int best_rank = -1;
    std::size_t attempt = 0;

    for (const ResolvedAddress& candidate : *candidates) {
        ++attempt;

        if (handle.cancel_requested()) {
            return std::unexpected(NetError::cancelled(NetOp::connect));
        }
        if (Clock::now() >= overall_deadline) {
            return std::unexpected(NetError::timed_out(NetOp::connect));
        }

        // WSASocketW rather than socket(): plain socket() returns an
        // INHERITABLE handle, so any process Crimson spawns later (a crash
        // reporter, an updater) would hold mail connections open after they
        // were closed here. WSA_FLAG_OVERLAPPED does not prevent blocking use
        // and keeps overlapped I/O available later.
        SocketHandle socket{::WSASocketW(candidate.family, candidate.socket_type,
                                         candidate.protocol, nullptr, 0,
                                         WSA_FLAG_OVERLAPPED |
                                             WSA_FLAG_NO_HANDLE_INHERIT)};
        if (!socket.valid()) {
            const NetError error = from_wsa(NetOp::socket);
            if (definiteness(error) > best_rank) {
                best_rank = definiteness(error);
                best_error = error;
            }
            continue;
        }

        if (auto configured = apply_options(socket.get(), options); !configured) {
            const NetError error = configured.error();
            if (definiteness(error) > best_rank) {
                best_rank = definiteness(error);
                best_error = error;
            }
            continue;  // SocketHandle closes on scope exit
        }

        // Attach before connecting so a cancel during this attempt is seen.
        if (handle.valid() &&
            !detail::attach_cancel_socket(*handle.state(),
                                          static_cast<std::uintptr_t>(socket.get()))) {
            return std::unexpected(NetError::cancelled(NetOp::connect));
        }

        const Clock::time_point candidate_deadline =
            std::min(Clock::now() + options.candidate_timeout, overall_deadline);

        auto connected = connect_with_deadline(socket.get(), candidate.address(),
                                               candidate.length, candidate_deadline,
                                               handle);

        auto described = describe_address(candidate.address(), candidate.length);
        const PeerAddress peer = described ? *described : PeerAddress{};

        if (!connected) {
            if (handle.valid()) {
                detail::detach_cancel_socket(*handle.state());
            }
            const NetError error = connected.error();
            log_event(LogLevel::debug, "tcp_candidate_failed",
                      {{"host", endpoint.host},
                       {"attempt", std::to_string(attempt)},
                       {"address", peer.address},
                       {"family", std::string{to_string(peer.family)}},
                       {"reason", std::string{to_string(error.cat)}},
                       {"code", symbolic_name(error.native)}});

            if (error.cat == NetCat::cancelled) {
                return std::unexpected(error);
            }
            if (definiteness(error) > best_rank) {
                best_rank = definiteness(error);
                best_error = error;
            }
            continue;
        }

        const PeerAddress local = local_address_of(socket.get());
        const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            Clock::now() - started);

        log_event(LogLevel::info, "tcp_connected",
                  {{"host", endpoint.host},
                   {"address", peer.address},
                   {"family", std::string{to_string(peer.family)}},
                   {"port", std::to_string(peer.port)},
                   {"attempt", std::to_string(attempt)},
                   {"candidates", std::to_string(candidates->size())},
                   {"elapsed_ms", std::to_string(elapsed.count())}});

        return TcpStream{std::move(socket), handle, peer, local};
    }

    log_event(LogLevel::warn, "tcp_connect_failed",
              {{"host", endpoint.host},
               {"port", std::to_string(endpoint.port)},
               {"candidates", std::to_string(candidates->size())},
               {"code", symbolic_name(best_error.native)},
               {"reason", std::string{to_string(best_error.cat)}}});

    return std::unexpected(best_error);
}

ReadOutcome TcpStream::read(std::span<std::byte> dst) noexcept {
    if (!socket_.valid()) {
        return std::unexpected(NetError::logic(NetOp::recv));
    }
    if (dst.empty()) {
        return ReadResult{0, false};
    }

    const int received = ::recv(socket_.get(), reinterpret_cast<char*>(dst.data()),
                                clamp_to_int(dst.size()), 0);
    if (received > 0) {
        return ReadResult{static_cast<std::size_t>(received), false};
    }

    if (received == 0) {
        // Orderly shutdown by the peer. A cancellation also lands here, because
        // shutdown(SD_BOTH) from another thread ends the read the same way, so
        // check which it was before reporting a clean end of stream.
        if (cancel_.cancel_requested()) {
            return std::unexpected(NetError::cancelled(NetOp::recv));
        }
        return ReadResult{0, true};
    }

    const NetError error = from_wsa(NetOp::recv);  // capture FIRST
    if (cancel_.cancel_requested()) {
        return std::unexpected(NetError::cancelled(NetOp::recv));
    }
    return std::unexpected(error);
}

WriteOutcome TcpStream::write_some(std::span<const std::byte> src) noexcept {
    if (!socket_.valid()) {
        return std::unexpected(NetError::logic(NetOp::send));
    }
    if (src.empty()) {
        return std::size_t{0};
    }

    const int sent = ::send(socket_.get(), reinterpret_cast<const char*>(src.data()),
                            clamp_to_int(src.size()), 0);
    if (sent == SOCKET_ERROR) {
        const NetError error = from_wsa(NetOp::send);  // capture FIRST
        if (cancel_.cancel_requested()) {
            return std::unexpected(NetError::cancelled(NetOp::send));
        }
        return std::unexpected(error);
    }
    return static_cast<std::size_t>(sent);
}

VoidOutcome TcpStream::shutdown_send() noexcept {
    if (!socket_.valid()) {
        return std::unexpected(NetError::logic(NetOp::shutdown));
    }
    if (::shutdown(socket_.get(), SD_SEND) == SOCKET_ERROR) {
        const NetError error = from_wsa(NetOp::shutdown);
        // WSAENOTCONN means the peer already tore the connection down, which is
        // the ordinary case when they closed first. Reporting it would make
        // every such teardown look like a failure.
        if (error.native == WSAENOTCONN) {
            return {};
        }
        return std::unexpected(error);
    }
    return {};
}

void TcpStream::close() noexcept {
    // Take the descriptor out of the shared cancel state first. Once this
    // returns, no other thread can be inside shutdown() on it and none can
    // start, so closesocket cannot race a cancel and the value cannot be
    // recycled underneath one. See cancel.h.
    if (cancel_.valid()) {
        (void)detail::take_cancel_socket(*cancel_.state());
    }
    socket_.reset();
}

}  // namespace crimson::net::win
