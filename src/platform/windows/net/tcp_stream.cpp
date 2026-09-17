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
#include <vector>

namespace crimson::net::win {

namespace {

using Clock = std::chrono::steady_clock;

// Upper bound on how long a single WSAPoll may block, so cancellation is
// observed promptly even when nothing else is due.
constexpr long long kPollSliceMs = 200;

// recv and send take an int count while Crimson works in size_t. Clamping
// rather than casting keeps a large buffer from wrapping to a negative length.
[[nodiscard]] int clamp_to_int(std::size_t value) noexcept {
    constexpr std::size_t kMax = static_cast<std::size_t>(std::numeric_limits<int>::max());
    return static_cast<int>(std::min(value, kMax));
}

// How much a failure tells us, used to pick which attempt's error to report
// when every attempt fails.
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

// Reorders candidates so address families alternate, per RFC 8305.
//
// The first entry is preserved as-is, because the system's resolver already
// ordered the list by its own address-selection policy and that preference
// should be honoured. From there families alternate, so a broken family cannot
// occupy every early slot. Relative order within each family is kept.
[[nodiscard]] std::vector<ResolvedAddress> interleave_by_family(
    const std::vector<ResolvedAddress>& candidates) {
    std::vector<ResolvedAddress> primary;
    std::vector<ResolvedAddress> secondary;
    if (candidates.empty()) {
        return {};
    }

    const int preferred_family = candidates.front().family;
    for (const ResolvedAddress& candidate : candidates) {
        if (candidate.family == preferred_family) {
            primary.push_back(candidate);
        } else {
            secondary.push_back(candidate);
        }
    }

    std::vector<ResolvedAddress> ordered;
    ordered.reserve(candidates.size());
    std::size_t first = 0;
    std::size_t second = 0;
    while (first < primary.size() || second < secondary.size()) {
        if (first < primary.size()) {
            ordered.push_back(primary[first++]);
        }
        if (second < secondary.size()) {
            ordered.push_back(secondary[second++]);
        }
    }
    return ordered;
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

// One connection attempt in flight.
struct Attempt {
    SocketHandle socket;
    ResolvedAddress address;
    PeerAddress described;
    Clock::time_point deadline;
    std::size_t ordinal = 0;
    bool failed = false;
};

struct StartedAttempt {
    SocketHandle socket;
    bool already_connected = false;
};

// Creates a non-blocking socket and begins connecting. Does not wait.
[[nodiscard]] std::expected<StartedAttempt, NetError> begin_attempt(
    const ResolvedAddress& candidate, const ConnectOptions& options) noexcept {
    // WSASocketW rather than socket(): plain socket() returns an INHERITABLE
    // handle, so any process Crimson spawns later (a crash reporter, an
    // updater) would hold mail connections open after they were closed here.
    // WSA_FLAG_OVERLAPPED does not prevent blocking use and keeps overlapped
    // I/O available later.
    SocketHandle socket{::WSASocketW(candidate.family, candidate.socket_type,
                                     candidate.protocol, nullptr, 0,
                                     WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT)};
    if (!socket.valid()) {
        return std::unexpected(from_wsa(NetOp::socket));
    }

    if (auto configured = apply_options(socket.get(), options); !configured) {
        return std::unexpected(configured.error());
    }

    u_long non_blocking = 1;
    if (::ioctlsocket(socket.get(), FIONBIO, &non_blocking) == SOCKET_ERROR) {
        return std::unexpected(from_wsa(NetOp::ioctl));
    }

    if (::connect(socket.get(), candidate.address(), candidate.length) != SOCKET_ERROR) {
        // Completed synchronously, which happens on loopback.
        return StartedAttempt{std::move(socket), true};
    }

    const int pending = ::WSAGetLastError();  // capture before anything else
    if (pending != WSAEWOULDBLOCK) {
        return std::unexpected(from_wsa_code(NetOp::connect, pending));
    }
    return StartedAttempt{std::move(socket), false};
}

// Returns the socket to blocking mode for the caller. FIONBIO cannot be
// queried, so the mode is tracked by construction: every socket handed back
// from connect() has been through here.
[[nodiscard]] std::expected<void, NetError> restore_blocking(SOCKET socket) noexcept {
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

[[nodiscard]] PeerAddress describe_or_empty(const ResolvedAddress& candidate) {
    auto described = describe_address(candidate.address(), candidate.length);
    return described ? *described : PeerAddress{};
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

    auto resolved = resolve(endpoint);
    if (!resolved) {
        return std::unexpected(resolved.error());
    }
    const std::vector<ResolvedAddress> candidates = interleave_by_family(*resolved);

    // A handle is always created, so every returned stream is cancellable even
    // when the caller did not ask for one.
    const CancelHandle handle = cancel.valid() ? cancel : make_cancel_handle();

    NetError best_error = NetError::timed_out(NetOp::connect);
    int best_rank = -1;
    const auto remember = [&](const NetError& error) {
        const int rank = definiteness(error);
        if (rank > best_rank) {
            best_rank = rank;
            best_error = error;
        }
    };

    std::vector<Attempt> in_flight;
    std::size_t next_candidate = 0;
    std::size_t started_count = 0;
    Clock::time_point next_start = started;

    // Takes ownership of a winning socket, closes everything else, and builds
    // the stream.
    const auto finish = [&](Attempt winner) -> std::expected<TcpStream, NetError> {
        in_flight.clear();  // SocketHandle closes each loser

        if (auto restored = restore_blocking(winner.socket.get()); !restored) {
            return std::unexpected(restored.error());
        }
        if (handle.valid() &&
            !detail::attach_cancel_socket(
                *handle.state(), static_cast<std::uintptr_t>(winner.socket.get()))) {
            return std::unexpected(NetError::cancelled(NetOp::connect));
        }

        const PeerAddress local = local_address_of(winner.socket.get());
        const auto elapsed =
            std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - started);

        log_event(LogLevel::info, "tcp_connected",
                  {{"host", endpoint.host},
                   {"address", winner.described.address},
                   {"family", std::string{to_string(winner.described.family)}},
                   {"port", std::to_string(winner.described.port)},
                   {"winner", std::to_string(winner.ordinal)},
                   {"started", std::to_string(started_count)},
                   {"candidates", std::to_string(candidates.size())},
                   {"elapsed_ms", std::to_string(elapsed.count())}});

        return TcpStream{std::move(winner.socket), handle, winner.described, local};
    };

    for (;;) {
        if (handle.cancel_requested()) {
            return std::unexpected(NetError::cancelled(NetOp::connect));
        }

        Clock::time_point now = Clock::now();
        if (now >= overall_deadline) {
            remember(NetError::timed_out(NetOp::connect));
            break;
        }

        // Start the next attempt when its stagger has elapsed, without giving
        // up on anything already pending. This overlap is the whole point.
        if (next_candidate < candidates.size() && in_flight.size() < options.max_in_flight &&
            (in_flight.empty() || now >= next_start)) {
            const ResolvedAddress& candidate = candidates[next_candidate];
            const std::size_t ordinal = ++next_candidate;

            auto begun = begin_attempt(candidate, options);
            ++started_count;
            next_start = now + options.attempt_delay;

            if (!begun) {
                remember(begun.error());
                log_event(LogLevel::debug, "tcp_attempt_failed",
                          {{"host", endpoint.host},
                           {"attempt", std::to_string(ordinal)},
                           {"stage", std::string{to_string(begun.error().op)}},
                           {"code", symbolic_name(begun.error().native)}});
                continue;
            }

            Attempt attempt;
            attempt.socket = std::move(begun->socket);
            attempt.address = candidate;
            attempt.described = describe_or_empty(candidate);
            attempt.deadline =
                std::min(now + options.candidate_timeout, overall_deadline);
            attempt.ordinal = ordinal;

            log_event(LogLevel::debug, "tcp_attempt_started",
                      {{"host", endpoint.host},
                       {"attempt", std::to_string(ordinal)},
                       {"address", attempt.described.address},
                       {"family", std::string{to_string(attempt.described.family)}}});

            if (begun->already_connected) {
                return finish(std::move(attempt));
            }
            in_flight.push_back(std::move(attempt));
            continue;  // try to start another immediately if its stagger allows
        }

        if (in_flight.empty()) {
            if (next_candidate >= candidates.size()) {
                break;  // nothing pending and nothing left to try
            }
            // Nothing in flight but the next stagger has not elapsed. This only
            // happens when every attempt so far failed to even start.
            const auto wait = next_start - now;
            const long long wait_ms =
                std::chrono::duration_cast<std::chrono::milliseconds>(wait).count();
            ::Sleep(static_cast<DWORD>(std::clamp<long long>(wait_ms, 0, kPollSliceMs)));
            continue;
        }

        // Poll every pending attempt together.
        std::vector<WSAPOLLFD> poll_set;
        poll_set.reserve(in_flight.size());
        for (const Attempt& attempt : in_flight) {
            WSAPOLLFD entry{};
            entry.fd = attempt.socket.get();
            entry.events = POLLWRNORM;
            poll_set.push_back(entry);
        }

        // Wake for whichever comes first: the next stagger, the earliest
        // attempt deadline, the overall deadline, or the cancellation slice.
        Clock::time_point wake = now + std::chrono::milliseconds{kPollSliceMs};
        if (next_candidate < candidates.size()) {
            wake = std::min(wake, next_start);
        }
        for (const Attempt& attempt : in_flight) {
            wake = std::min(wake, attempt.deadline);
        }
        wake = std::min(wake, overall_deadline);
        const long long wake_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                      wake - now)
                                      .count();
        const int timeout = static_cast<int>(std::clamp<long long>(wake_ms, 0, kPollSliceMs));

        const int ready = ::WSAPoll(poll_set.data(), static_cast<ULONG>(poll_set.size()),
                                    timeout);
        if (ready == SOCKET_ERROR) {
            remember(from_wsa(NetOp::poll));
            break;
        }

        now = Clock::now();

        if (ready > 0) {
            for (std::size_t index = 0; index < poll_set.size(); ++index) {
                if (poll_set[index].revents == 0) {
                    continue;
                }

                // Writability alone does not mean success. A failed connect can
                // report POLLWRNORM together with POLLERR and POLLHUP, so
                // SO_ERROR is the only reliable answer. Trusting revents here
                // yields a socket that looks connected and fails on first recv.
                Attempt& attempt = in_flight[index];
                int socket_error = 0;
                int size = static_cast<int>(sizeof(socket_error));
                if (::getsockopt(attempt.socket.get(), SOL_SOCKET, SO_ERROR,
                                 reinterpret_cast<char*>(&socket_error), &size) ==
                    SOCKET_ERROR) {
                    remember(from_wsa(NetOp::sockopt));
                    socket_error = WSAENOTCONN;  // fall through to the failure path
                }

                if (socket_error == 0) {
                    Attempt winner = std::move(attempt);
                    return finish(std::move(winner));
                }

                const NetError error = from_wsa_code(NetOp::connect, socket_error);
                remember(error);
                log_event(LogLevel::debug, "tcp_attempt_failed",
                          {{"host", endpoint.host},
                           {"attempt", std::to_string(attempt.ordinal)},
                           {"address", attempt.described.address},
                           {"family", std::string{to_string(attempt.described.family)}},
                           {"code", symbolic_name(socket_error)}});
                attempt.failed = true;
            }
        }

        // Drop attempts that failed or ran out of time. A blackholed SYN never
        // reports anything at all, so only its deadline retires it.
        for (auto it = in_flight.begin(); it != in_flight.end();) {
            if (it->failed) {
                it = in_flight.erase(it);  // SocketHandle closes
            } else if (it->deadline <= now) {
                remember(NetError::timed_out(NetOp::connect));
                log_event(LogLevel::debug, "tcp_attempt_timed_out",
                          {{"host", endpoint.host},
                           {"attempt", std::to_string(it->ordinal)},
                           {"address", it->described.address},
                           {"family", std::string{to_string(it->described.family)}}});
                it = in_flight.erase(it);
            } else {
                ++it;
            }
        }
    }

    in_flight.clear();  // close anything still pending

    log_event(LogLevel::warn, "tcp_connect_failed",
              {{"host", endpoint.host},
               {"port", std::to_string(endpoint.port)},
               {"candidates", std::to_string(candidates.size())},
               {"started", std::to_string(started_count)},
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

    // Checked before the call, not only after. CancelIoEx can only cancel an
    // operation that is already pending, so a cancel arriving just before this
    // point would otherwise go unnoticed until the SO_RCVTIMEO safety net
    // expired. See the race note in cancel.h.
    if (cancel_.cancel_requested()) {
        return std::unexpected(NetError::cancelled(NetOp::recv));
    }

    const int received = ::recv(socket_.get(), reinterpret_cast<char*>(dst.data()),
                                clamp_to_int(dst.size()), 0);
    if (received > 0) {
        return ReadResult{static_cast<std::size_t>(received), false};
    }

    if (received == 0) {
        return ReadResult{0, true};  // orderly shutdown by the peer
    }

    const NetError error = from_wsa(NetOp::recv);  // capture FIRST
    // A cancelled read surfaces as WSAEINTR or WSA_OPERATION_ABORTED, depending
    // on how far the operation had progressed. Report the cause rather than the
    // symptom, so callers do not have to know which.
    if (cancel_.cancel_requested() || error.native == WSAEINTR ||
        error.native == WSA_OPERATION_ABORTED) {
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

    if (cancel_.cancel_requested()) {
        return std::unexpected(NetError::cancelled(NetOp::send));
    }

    const int sent = ::send(socket_.get(), reinterpret_cast<const char*>(src.data()),
                            clamp_to_int(src.size()), 0);
    if (sent == SOCKET_ERROR) {
        const NetError error = from_wsa(NetOp::send);  // capture FIRST
        if (cancel_.cancel_requested() || error.native == WSAEINTR ||
            error.native == WSA_OPERATION_ABORTED) {
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
