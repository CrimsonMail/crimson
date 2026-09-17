// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef CRIMSON_PLATFORM_WINDOWS_NET_TCP_STREAM_H
#define CRIMSON_PLATFORM_WINDOWS_NET_TCP_STREAM_H

#include <chrono>
#include <cstddef>
#include <expected>

#include "core/net/byte_stream.h"
#include "core/net/endpoint.h"
#include "platform/windows/net/cancel.h"
#include "platform/windows/net/socket_handle.h"

namespace crimson::net::win {

// Connection policy.
//
// On socket options, Step 1's guidance is not to enable things merely because
// they exist, so each of these is justified rather than inherited:
//
//   no_delay (TCP_NODELAY) defaults ON. Mail protocols are request-response
//   with small commands, which is precisely the shape that Nagle's algorithm
//   and delayed ACK combine to punish: a small write waits for the previous
//   segment's acknowledgement while the peer delays that acknowledgement
//   waiting for more data. The result is up to ~200 ms of dead time per
//   command, and an IMAP session issues a great many commands.
//
//   read_timeout (SO_RCVTIMEO) defaults to 60 s, as a safety net rather than a
//   protocol deadline. It guarantees no thread blocks forever if a cancellation
//   is missed or a middlebox blackholes an idle connection. Expiry surfaces as
//   WSAETIMEDOUT, which classifies as retryable.
//
//   There is deliberately NO write timeout. SO_SNDTIMEO looks like the
//   symmetric counterpart and is not: when a blocking send times out, the
//   connection is left in a documented indeterminate state, with an unknown
//   number of bytes transferred. That is unrecoverable for write_all, which
//   must know where to resume, so the option is not offered at all.
//
//   keep_alive (SO_KEEPALIVE) defaults OFF. Nothing in Step 1 holds an idle
//   connection. IMAP IDLE will want it, along with the TCP_KEEP* intervals, and
//   can turn it on then.
struct ConnectOptions {
    // Delay before starting the NEXT candidate, without giving up on the ones
    // already in flight. This is RFC 8305's Connection Attempt Delay, and 250 ms
    // is its recommended default (it allows 100 ms to 2 s).
    //
    // This one value is what keeps a broken address family from costing whole
    // seconds. Measured on a host with a router-advertised IPv6 address but no
    // working IPv6 route — an entirely ordinary consumer Wi-Fi configuration —
    // strict sequential iteration over example.com's four addresses took
    // 10,318 ms, because each blackholed IPv6 candidate consumed its full
    // deadline before IPv4 was tried at all. Overlapping the attempts brings
    // the same connection in at roughly 280 ms.
    std::chrono::milliseconds attempt_delay{250};

    // Deadline for any single attempt. A blackholed SYN never fails on its own,
    // so without this an attempt would occupy a slot until the overall deadline.
    std::chrono::milliseconds candidate_timeout{5000};

    // Deadline for the whole operation, so a hostname with many addresses
    // cannot compound into minutes.
    std::chrono::milliseconds overall_timeout{20000};

    std::chrono::milliseconds read_timeout{60000};

    // Ceiling on simultaneously pending attempts, so a name with a long address
    // list cannot emit a burst of SYNs.
    std::size_t max_in_flight{6};

    bool no_delay = true;
    bool keep_alive = false;
};

// A connected TCP byte stream.
//
// Move-only: exactly one owner, which closes the socket. Shared ownership would
// make close ordering ambiguous, and for sockets that is a correctness problem
// rather than a matter of taste (see cancel.h).
//
// THREADING. One stream is owned and used by one thread at a time. Reads and
// writes are not internally synchronized and concurrent calls are not
// supported. The single exception is the CancelHandle, which is explicitly safe
// from any thread. Only the owning thread may destroy or close the stream.
class TcpStream final : public ByteStream {
public:
    // Resolves `endpoint` and connects, overlapping attempts across the
    // resolved addresses so a dead address family costs milliseconds rather
    // than seconds.
    //
    // The strategy is RFC 8305 ("Happy Eyeballs v2"), which is what browsers
    // and mature mail clients do:
    //
    //   1. Candidates are interleaved by address family, keeping the system's
    //      own preferred address first so a working IPv6 path is still
    //      preferred.
    //   2. The first attempt starts immediately. Each subsequent attempt starts
    //      one attempt_delay later WITHOUT abandoning those already running.
    //   3. All pending attempts are polled together. The first to complete
    //      cleanly wins and the rest are closed at once.
    //
    // Why not a plain blocking connect: an unreachable address takes about
    // 21 seconds to fail on Windows (SYN at 0s, 3s and 9s), and SO_SNDTIMEO
    // does not apply to connect, so there is no way to shorten it afterwards.
    // Why not sequential attempts with a deadline: that bounds each address but
    // still pays for every dead one in turn, which measured 10.3 s on an
    // IPv6-blackholed network.
    //
    // No threads and no IOCP are involved. The sockets are non-blocking and a
    // single WSAPoll covers all pending attempts; this function is synchronous
    // from the caller's point of view.
    //
    // Sockets from losing and failed attempts are always closed, so a hostname
    // with several dead addresses leaks nothing.
    //
    // Pass a handle from make_cancel_handle() to abandon a connect in progress
    // from another thread; cancellation is observed within roughly 200 ms. The
    // returned stream adopts that handle.
    [[nodiscard]] static std::expected<TcpStream, NetError> connect(
        const Endpoint& endpoint, const ConnectOptions& options = {},
        const CancelHandle& cancel = {});

    ~TcpStream() override;

    TcpStream(TcpStream&&) noexcept;
    TcpStream& operator=(TcpStream&&) noexcept;

    // ByteStream. See byte_stream.h for the read and write contracts.
    [[nodiscard]] ReadOutcome read(std::span<std::byte> dst) noexcept override;
    [[nodiscard]] WriteOutcome write_some(
        std::span<const std::byte> src) noexcept override;
    [[nodiscard]] VoidOutcome shutdown_send() noexcept override;
    void close() noexcept override;

    [[nodiscard]] bool is_open() const noexcept { return socket_.valid(); }

    // Non-sensitive connection diagnostics, safe to log. Answers the question
    // behind reports like "Gmail works on Wi-Fi but not on university
    // Ethernet": which address, which family, which port.
    [[nodiscard]] const PeerAddress& peer() const noexcept { return peer_; }
    [[nodiscard]] const PeerAddress& local() const noexcept { return local_; }

    // Safe to copy to another thread and cancel from there.
    [[nodiscard]] CancelHandle cancel_handle() const noexcept { return cancel_; }

private:
    TcpStream(SocketHandle socket, CancelHandle cancel, PeerAddress peer,
              PeerAddress local) noexcept;

    SocketHandle socket_;
    CancelHandle cancel_;
    PeerAddress peer_;
    PeerAddress local_;
};

}  // namespace crimson::net::win

#endif  // CRIMSON_PLATFORM_WINDOWS_NET_TCP_STREAM_H
