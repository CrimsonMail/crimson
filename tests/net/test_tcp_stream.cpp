// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#include <atomic>
#include <chrono>
#include <string>
#include <thread>
#include <vector>

#include "core/net/stream_helpers.h"
#include "harness.h"
#include "net/echo_server.h"
#include "platform/windows/net/cancel.h"
#include "platform/windows/net/tcp_stream.h"
#include "platform/windows/net/win_sockets.h"
#include "platform/windows/net/wsa_error.h"

using crimson::net::Endpoint;
using crimson::net::NetCat;
using crimson::net::NetOp;
using crimson::net::read_exactly;
using crimson::net::read_to_eof;
using crimson::net::Retry;
using crimson::net::write_all;
using crimson::net::win::ConnectOptions;
using crimson::net::win::make_cancel_handle;
using crimson::net::win::TcpStream;
using crimson::test::AbortNow;
using crimson::test::bytes;
using crimson::test::DrainToEof;
using crimson::test::HalfClose;
using crimson::test::Script;
using crimson::test::Send;
using crimson::test::SendFragmented;
using crimson::test::Idle;
using crimson::test::TestServer;

namespace {

[[nodiscard]] std::span<const std::byte> span_of(std::string_view text) noexcept {
    return std::span{reinterpret_cast<const std::byte*>(text.data()), text.size()};
}

[[nodiscard]] DWORD handle_count() {
    DWORD count = 0;
    if (::GetProcessHandleCount(::GetCurrentProcess(), &count) == 0) {
        return 0;
    }
    return count;
}

// Tests talk to the loopback server, so the generous production defaults would
// only slow failures down.
[[nodiscard]] ConnectOptions fast_options() {
    ConnectOptions options;
    options.candidate_timeout = std::chrono::milliseconds{2000};
    options.overall_timeout = std::chrono::milliseconds{4000};
    options.read_timeout = std::chrono::milliseconds{4000};
    return options;
}

}  // namespace

CRIMSON_TEST(tcp_stream, connects_to_loopback_and_reads_a_reply) {
    auto server = TestServer::start(AF_INET, Script{Send{bytes("* OK Crimson ready\r\n")},
                                                    HalfClose{}});
    CHECK_OK(server);

    auto stream = TcpStream::connect(Endpoint{server->host(), server->port()},
                                     fast_options());
    CHECK_OK(stream);
    CHECK(stream->is_open());
    CHECK_EQ(stream->peer().address, std::string{"127.0.0.1"});
    CHECK_EQ(stream->peer().port, server->port());
    CHECK_EQ(stream->peer().family, crimson::net::AddressFamily::ipv4);

    std::vector<std::byte> received;
    const auto result = read_to_eof(*stream, received, 4096);
    CHECK_OK(result);
    CHECK(result->eof);

    const std::string_view text{reinterpret_cast<const char*>(received.data()),
                                received.size()};
    CHECK_EQ(text, std::string_view{"* OK Crimson ready\r\n"});
}

CRIMSON_TEST(tcp_stream, reassembles_a_reply_delivered_one_byte_at_a_time) {
    // The lesson that matters most for the IMAP tokenizer later: TCP guarantees
    // ordered bytes and says nothing about how they are grouped. A client that
    // treats a read boundary as a message boundary works until it does not.
    auto server = TestServer::start(
        AF_INET, Script{SendFragmented{bytes("HELLO WORLD"), 1, std::chrono::milliseconds{1}},
                        HalfClose{}});
    CHECK_OK(server);

    auto stream = TcpStream::connect(Endpoint{server->host(), server->port()},
                                     fast_options());
    CHECK_OK(stream);

    std::vector<std::byte> buffer(11);
    CHECK_OK(read_exactly(*stream, buffer));

    const std::string_view text{reinterpret_cast<const char*>(buffer.data()),
                                buffer.size()};
    CHECK_EQ(text, std::string_view{"HELLO WORLD"});
}

CRIMSON_TEST(tcp_stream, writes_a_megabyte_across_many_partial_sends) {
    // One-directional on purpose. A bidirectional echo of this size deadlocks a
    // single-threaded blocking client: loopback send buffers are around 64 KB,
    // so both sides fill their buffers with neither reading. Draining one way
    // still exercises the partial-write loop and the FIN path.
    auto server = TestServer::start(AF_INET, Script{DrainToEof{}});
    CHECK_OK(server);

    auto stream = TcpStream::connect(Endpoint{server->host(), server->port()},
                                     fast_options());
    CHECK_OK(stream);

    const std::string payload(1024u * 1024u, 'M');
    CHECK_OK(write_all(*stream, span_of(payload)));
    CHECK_OK(stream->shutdown_send());

    // After half-closing, the server finishes draining and closes, so this
    // read reports end of stream and also serves as the synchronisation point.
    std::byte scratch[64] = {};
    const auto tail = stream->read(std::span{scratch});
    CHECK_OK(tail);
    CHECK(tail->eof);
    CHECK_EQ(tail->bytes, std::size_t{0});

    CHECK_EQ(server->bytes_drained(), payload.size());
}

CRIMSON_TEST(tcp_stream, reports_a_clean_end_of_stream_when_the_peer_half_closes) {
    auto server = TestServer::start(AF_INET, Script{HalfClose{}});
    CHECK_OK(server);

    auto stream = TcpStream::connect(Endpoint{server->host(), server->port()},
                                     fast_options());
    CHECK_OK(stream);

    std::byte scratch[64] = {};
    const auto result = stream->read(std::span{scratch});

    // A peer finishing is a successful read reporting EOF, not an error. The
    // sync engine has to be able to tell "mailbox closed normally" from
    // "connection broke", and this is where that distinction starts.
    CHECK_OK(result);
    CHECK(result->eof);
    CHECK_EQ(result->bytes, std::size_t{0});
}

CRIMSON_TEST(tcp_stream, surfaces_an_abortive_reset_as_an_error) {
    auto server = TestServer::start(AF_INET, Script{AbortNow{}});
    CHECK_OK(server);

    auto stream = TcpStream::connect(Endpoint{server->host(), server->port()},
                                     fast_options());
    CHECK_OK(stream);

    std::byte scratch[64] = {};
    const auto result = stream->read(std::span{scratch});

    CHECK_ERR(result);
    CHECK_EQ(result.error().cat, NetCat::wsa);
    CHECK_EQ(result.error().op, NetOp::recv);
    CHECK_MSG(result.error().native == WSAECONNRESET ||
                  result.error().native == WSAECONNABORTED,
              "expected a reset, got " +
                  crimson::net::win::symbolic_name(result.error().native));
    // A reset connection is worth reconnecting; it is not a permanent failure.
    CHECK_EQ(result.error().retry, Retry::new_connection);
}

CRIMSON_TEST(tcp_stream, reports_connection_refused_without_an_exception) {
    // Nothing listens on loopback port 1, and no other process can steal the
    // port out from under the test.
    //
    // A refusal is NOT instant, contrary to the obvious assumption. Measured on
    // Windows it takes about 2,030 ms, uniformly across ports (1, 9, 47821 and
    // 59999 all landed within 15 ms of each other), so the deadline has to sit
    // well above that. With a tighter one the attempt is retired as a timeout
    // before the refusal arrives, and the error says "timeout" instead of
    // "connection refused".
    ConnectOptions options = fast_options();
    options.candidate_timeout = std::chrono::milliseconds{4000};
    options.overall_timeout = std::chrono::milliseconds{6000};

    const auto stream = TcpStream::connect(Endpoint{"127.0.0.1", 1}, options);

    CHECK_ERR(stream);
    CHECK_EQ(stream.error().op, NetOp::connect);
    CHECK_EQ(stream.error().native, WSAECONNREFUSED);
    // Refused means this address answered and declined, so the right move is a
    // different address rather than hammering this one.
    CHECK_EQ(stream.error().retry, Retry::new_candidate);
}

CRIMSON_TEST(tcp_stream, reports_dns_failure_as_a_resolution_error) {
    // .invalid is reserved by RFC 2606 and must never resolve, so this cannot
    // be rescued by a provider's wildcard DNS.
    const auto stream =
        TcpStream::connect(Endpoint{"zq7x9k-crimson-test.invalid", 993}, fast_options());

    CHECK_ERR(stream);
    // The stage is the point: "DNS resolution failed for imap.example.com" is
    // actionable, "connect failed" is not.
    CHECK_EQ(stream.error().op, NetOp::resolve);
    CHECK_EQ(stream.error().cat, NetCat::gai);
    CHECK_MSG(stream.error().native == WSAHOST_NOT_FOUND ||
                  stream.error().native == WSANO_DATA,
              "expected a name-not-found code, got " +
                  crimson::net::win::symbolic_name(stream.error().native));
}

CRIMSON_TEST(tcp_stream, works_over_ipv6_loopback) {
    // Catches IPv4-only assumptions: anything that reached for sockaddr_in
    // directly, or assumed a 4-byte address, fails here.
    auto server = TestServer::start(AF_INET6, Script{Send{bytes("v6 ok")}, HalfClose{}});
    CHECK_OK(server);

    auto stream = TcpStream::connect(Endpoint{server->host(), server->port()},
                                     fast_options());
    CHECK_OK(stream);
    CHECK_EQ(stream->peer().family, crimson::net::AddressFamily::ipv6);
    CHECK_EQ(stream->peer().address, std::string{"::1"});

    std::vector<std::byte> buffer(5);
    CHECK_OK(read_exactly(*stream, buffer));
    const std::string_view text{reinterpret_cast<const char*>(buffer.data()),
                                buffer.size()};
    CHECK_EQ(text, std::string_view{"v6 ok"});
}

CRIMSON_TEST(tcp_stream, accepts_a_bracketed_ipv6_literal) {
    // Users and configuration files write "[::1]"; GetAddrInfoW rejects it.
    auto server = TestServer::start(AF_INET6, Script{Send{bytes("ok")}, HalfClose{}});
    CHECK_OK(server);

    auto stream = TcpStream::connect(Endpoint{"[::1]", server->port()}, fast_options());
    CHECK_OK(stream);
    CHECK_EQ(stream->peer().family, crimson::net::AddressFamily::ipv6);
}

CRIMSON_TEST(tcp_stream, cancel_from_another_thread_unblocks_a_blocked_read) {
    // Proves the escape hatch actually works. If shutdown-unblocks-recv ever
    // regresses, on a future Windows build or under a layered service provider,
    // this fails here rather than as a frozen interface in front of a user.
    auto server = TestServer::start(AF_INET, Script{Idle{std::chrono::seconds{5}}});
    CHECK_OK(server);

    const auto cancel = make_cancel_handle();
    auto stream = TcpStream::connect(Endpoint{server->host(), server->port()},
                                     fast_options(), cancel);
    CHECK_OK(stream);

    std::thread canceller{[cancel] {
        std::this_thread::sleep_for(std::chrono::milliseconds{100});
        cancel.cancel();
    }};

    const auto started = std::chrono::steady_clock::now();
    std::byte scratch[64] = {};
    const auto result = stream->read(std::span{scratch});
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - started);

    canceller.join();

    CHECK_ERR(result);
    CHECK_EQ(result.error().cat, NetCat::cancelled);
    CHECK_MSG(elapsed < std::chrono::milliseconds{1500},
              "read took " + std::to_string(elapsed.count()) +
                  " ms to unblock; cancellation is not working");
}

CRIMSON_TEST(tcp_stream, cancelling_before_connecting_abandons_the_attempt) {
    auto server = TestServer::start(AF_INET, Script{Idle{std::chrono::seconds{5}}});
    CHECK_OK(server);

    const auto cancel = make_cancel_handle();
    cancel.cancel();  // already requested before we start

    const auto stream = TcpStream::connect(Endpoint{server->host(), server->port()},
                                           fast_options(), cancel);
    CHECK_ERR(stream);
    CHECK_EQ(stream.error().cat, NetCat::cancelled);
    CHECK_EQ(stream.error().op, NetOp::connect);
}

CRIMSON_TEST(tcp_stream, moved_streams_transfer_the_connection) {
    auto server = TestServer::start(AF_INET, Script{Send{bytes("moved")}, HalfClose{}});
    CHECK_OK(server);

    auto stream = TcpStream::connect(Endpoint{server->host(), server->port()},
                                     fast_options());
    CHECK_OK(stream);

    TcpStream moved{std::move(*stream)};
    CHECK(moved.is_open());
    CHECK(!stream->is_open());  // the source must not still own the socket

    std::vector<std::byte> buffer(5);
    CHECK_OK(read_exactly(moved, buffer));
    const std::string_view text{reinterpret_cast<const char*>(buffer.data()),
                                buffer.size()};
    CHECK_EQ(text, std::string_view{"moved"});
}

CRIMSON_TEST(tcp_stream, repeated_connections_do_not_leak_handles) {
    auto server = TestServer::start(AF_INET, Script{HalfClose{}});
    CHECK_OK(server);

    const Endpoint endpoint{server->host(), server->port()};
    const ConnectOptions options = fast_options();

    // Warm up first, so one-off allocations do not count against the baseline.
    for (int index = 0; index < 5; ++index) {
        auto warm = TcpStream::connect(endpoint, options);
        CHECK_OK(warm);
    }

    const DWORD before = handle_count();
    constexpr int kIterations = 100;
    for (int index = 0; index < kIterations; ++index) {
        auto stream = TcpStream::connect(endpoint, options);
        CHECK_OK(stream);
        std::byte scratch[16] = {};
        (void)stream->read(std::span{scratch});
    }
    const DWORD after = handle_count();

    CHECK_MSG(after <= before + 15,
              "handle count grew by " + std::to_string(after - before) + " over " +
                  std::to_string(kIterations) +
                  " connections; sockets are leaking per connection");
}

CRIMSON_TEST(tcp_stream, failed_connections_do_not_leak_handles) {
    // Every failed attempt creates a socket that has to be closed before moving
    // to the next candidate. A leak here stays invisible until a user with a
    // flaky server exhausts the process.
    //
    // The deadline is deliberately short. Each attempt then creates a socket
    // and abandons it on timeout, which is exactly the path under test, without
    // paying the ~2 s a real refusal costs on Windows. That keeps the run well
    // inside the harness watchdog while still making a per-iteration leak
    // obvious against the margin.
    const Endpoint refused{"127.0.0.1", 1};
    ConnectOptions options = fast_options();
    options.candidate_timeout = std::chrono::milliseconds{300};
    options.overall_timeout = std::chrono::milliseconds{600};

    for (int index = 0; index < 3; ++index) {
        const auto warm = TcpStream::connect(refused, options);
        CHECK_ERR(warm);
    }

    const DWORD before = handle_count();
    constexpr int kIterations = 20;
    for (int index = 0; index < kIterations; ++index) {
        const auto stream = TcpStream::connect(refused, options);
        CHECK_ERR(stream);
    }
    const DWORD after = handle_count();

    CHECK_MSG(after <= before + 10,
              "handle count grew by " + std::to_string(after - before) + " over " +
                  std::to_string(kIterations) +
                  " failed connections; the candidate loop is leaking");
}
