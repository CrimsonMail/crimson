// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#include <chrono>
#include <expected>
#include <memory>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "core/net/stream_helpers.h"
#include "harness.h"
#include "net/fragmenting_stream.h"
#include "net/scripted_stream.h"
#include "platform/windows/net/sspi_error.h"
#include "platform/windows/net/tcp_stream.h"
#include "platform/windows/net/tls_stream.h"
#include "platform/windows/net/win_security.h"

// TLS tests.
//
// The offline ones drive TlsStream against scripted peers that cannot speak
// TLS, to prove failure is prompt and clean. The rest need the public internet:
// Crimson deliberately has no TLS server of its own (that would be a second
// handshake state machine), so handshakes are tested against real servers,
// and the record layer is stressed by putting a fragmenting stream underneath.
//
// Certificate and protocol failures use badssl.com, which exists precisely to
// serve broken TLS on purpose. The expected codes below were measured against
// it before these assertions were written.

using crimson::net::Endpoint;
using crimson::net::NetCat;
using crimson::net::NetError;
using crimson::net::NetOp;
using crimson::net::read_to_eof;
using crimson::net::Retry;
using crimson::net::write_all;
using crimson::net::win::ConnectOptions;
using crimson::net::win::error_name;
using crimson::net::win::is_certificate_error;
using crimson::net::win::TcpStream;
using crimson::net::win::TlsCredentials;
using crimson::net::win::TlsOptions;
using crimson::net::win::TlsStream;
using crimson::test::FragmentingStream;
using crimson::test::ScriptedStream;

namespace {

// Lends a stream the test owns to something that insists on ownership.
//
// TlsStream::wrap takes a unique_ptr and destroys the stream when a handshake
// fails. A test that then inspected its scripted peer through a raw pointer
// would be reading freed memory, so the peer lives on the test's stack and
// wrap gets this forwarding shell instead.
class BorrowedStream final : public crimson::net::ByteStream {
public:
    explicit BorrowedStream(crimson::net::ByteStream& target) : target_(target) {}
    crimson::net::ReadOutcome read(std::span<std::byte> dst) noexcept override { return target_.read(dst); }
    crimson::net::WriteOutcome write_some(std::span<const std::byte> src) noexcept override {
        return target_.write_some(src);
    }
    crimson::net::VoidOutcome shutdown_send() noexcept override { return target_.shutdown_send(); }
    void close() noexcept override { target_.close(); }

private:
    crimson::net::ByteStream& target_;
};

[[nodiscard]] std::wstring target(std::string_view host) {
    auto name = crimson::net::win::detail::tls_target_name(host);
    CHECK_OK(name);
    return *name;
}

[[nodiscard]] TlsCredentials credentials() {
    auto created = TlsCredentials::create();
    CHECK_OK(created);
    return *created;
}

[[nodiscard]] std::span<const std::byte> bytes_of(std::string_view text) noexcept {
    return std::span{reinterpret_cast<const std::byte*>(text.data()), text.size()};
}

[[nodiscard]] std::string_view text_of(const std::vector<std::byte>& data) noexcept {
    return std::string_view{reinterpret_cast<const char*>(data.data()), data.size()};
}

[[nodiscard]] std::string http_get(std::string_view host) {
    return "GET / HTTP/1.1\r\nHost: " + std::string{host} +
           "\r\nConnection: close\r\nUser-Agent: crimson-tests\r\n\r\n";
}

[[nodiscard]] DWORD handle_count() {
    DWORD count = 0;
    ::GetProcessHandleCount(::GetCurrentProcess(), &count);
    return count;
}

// Connects to one of badssl.com's deliberately broken servers.
//
// badssl.com is a public service with bad minutes: stretches where it resets
// or drops a large share of connections, for every client alike. A failure
// below the TLS layer means Schannel never saw the server's certificate or
// protocol choice, so a test about those has nothing to judge. Such failures
// are retried, and if they persist the test is skipped rather than failed —
// an outage there is not a regression here. Anything Schannel did decide is
// returned untouched, for the caller to assert on.
//
// Only badssl.com gets this. The example.com tests exercise Crimson's own
// record layer, where a dropped connection could be Crimson's fault.
[[nodiscard]] std::expected<TlsStream, NetError> connect_to_test_server(
    const char* host, std::uint16_t port, const TlsCredentials& creds) {
    constexpr int kAttempts = 4;
    NetError last{};
    for (int attempt = 1; attempt <= kAttempts; ++attempt) {
        auto stream = TlsStream::connect(Endpoint{host, port}, creds);
        if (stream || stream.error().cat == NetCat::sspi) {
            return stream;
        }
        last = stream.error();
        if (attempt < kAttempts) {
            std::this_thread::sleep_for(std::chrono::milliseconds{500 * attempt});
        }
    }
    throw crimson::test::SkipTest{std::string{host} + " gave no TLS verdict in " +
                                  std::to_string(kAttempts) + " attempts: " + error_name(last)};
}

// A handshake against `host:port` must fail at the handshake stage with
// exactly `expected`, as a permanent, reportable problem.
void expect_handshake_failure(const char* host, std::uint16_t port, long expected,
                              bool certificate_problem) {
    const TlsCredentials creds = credentials();
    const auto stream = connect_to_test_server(host, port, creds);
    CHECK_ERR(stream);
    const NetError& error = stream.error();
    CHECK_EQ(error.op, NetOp::tls_handshake);
    CHECK_EQ(error.cat, NetCat::sspi);
    CHECK_MSG(error.native == static_cast<int>(expected),
              std::string{"expected "} + crimson::net::win::sspi_symbolic_name(expected) +
                  ", got " + error_name(error));
    CHECK_EQ(error.retry, Retry::no);
    CHECK_EQ(is_certificate_error(error), certificate_problem);
}

// A server that speaks only a protocol below the floor must be refused during
// the handshake. Which code reports it depends on the client machine, not on
// Crimson: offered a CBC suite that TLS 1.0 can use, the server answers with a
// TLS 1.0 ServerHello and Schannel rejects the version (ALGORITHM_MISMATCH, as
// on Windows 11 25H2); offered none, the server sends a handshake_failure
// alert instead (ILLEGAL_MESSAGE, as on GitHub's Windows Server 2025 runner).
// Either way the connection never happens, which is the property under test.
void expect_protocol_refused(const char* host, std::uint16_t port) {
    const TlsCredentials creds = credentials();
    const auto stream = connect_to_test_server(host, port, creds);
    CHECK_ERR(stream);
    const NetError& error = stream.error();
    CHECK_EQ(error.op, NetOp::tls_handshake);
    CHECK_EQ(error.cat, NetCat::sspi);
    const bool version_rejected = error.native == static_cast<int>(SEC_E_ALGORITHM_MISMATCH);
    const bool server_aborted = error.native == static_cast<int>(SEC_E_ILLEGAL_MESSAGE);
    CHECK_MSG(version_rejected || server_aborted,
              "expected SEC_E_ALGORITHM_MISMATCH or SEC_E_ILLEGAL_MESSAGE, got " + error_name(error));
    CHECK(!is_certificate_error(error));
    if (version_rejected) {
        CHECK_EQ(error.retry, Retry::no);
    }
}

}  // namespace

// --- Offline ---------------------------------------------------------------

CRIMSON_TEST(tls, credentials_are_shared_by_copies) {
    const TlsCredentials first = credentials();
    const TlsCredentials copy = first;  // NOLINT: the copy is the point
    CHECK(first.valid());
    CHECK(copy.valid());
    // Copies share one handle, which is what lets Schannel resume sessions
    // across connections and what keeps a handle alive under every stream.
    CHECK(first.handle() == copy.handle());
}

CRIMSON_TEST(tls, wrap_refuses_an_empty_hostname) {
    ScriptedStream peer;
    const auto stream = TlsStream::wrap(std::make_unique<BorrowedStream>(peer), credentials(),
                                        TlsOptions{""});
    CHECK_ERR(stream);
    CHECK_EQ(stream.error().cat, NetCat::logic);
    // Refused before a ClientHello was ever sent.
    CHECK_EQ(peer.written().size(), std::size_t{0});
}

CRIMSON_TEST(tls, target_name_strips_brackets_and_converts_international_names) {
    CHECK(target("imap.example.com") == L"imap.example.com");
    CHECK(target("[::1]") == L"::1");
    // "müller.de" in UTF-8. Certificates list internationalised names in
    // their ASCII-compatible form, so that is what must be verified and sent.
    CHECK(target("m\xC3\xBCller.de") == L"xn--mller-kva.de");
    CHECK_ERR(crimson::net::win::detail::tls_target_name(""));
    CHECK_ERR(crimson::net::win::detail::tls_target_name("[]"));
}

CRIMSON_TEST(tls, a_peer_that_does_not_speak_tls_fails_the_handshake_promptly) {
    // A plaintext server answering a ClientHello with an HTTP error, as a
    // misconfigured port would. This must fail cleanly, not hang or crash.
    ScriptedStream peer;
    peer.give("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");

    const auto stream = TlsStream::wrap(std::make_unique<BorrowedStream>(peer), credentials(),
                                        TlsOptions{"mail.example.com"});
    CHECK_ERR(stream);
    CHECK_EQ(stream.error().op, NetOp::tls_handshake);
    CHECK(stream.error().cat == NetCat::sspi || stream.error().cat == NetCat::truncated);
    // A ClientHello did go out first: a TLS handshake record, content type 22.
    CHECK(peer.written().size() > 0);
    CHECK(static_cast<unsigned char>(peer.written()[0]) == 0x16);
}

CRIMSON_TEST(tls, a_peer_that_closes_immediately_is_a_truncated_handshake) {
    ScriptedStream peer;  // nothing to give: end of stream at once
    const auto stream = TlsStream::wrap(std::make_unique<BorrowedStream>(peer), credentials(),
                                        TlsOptions{"mail.example.com"});
    CHECK_ERR(stream);
    CHECK_EQ(stream.error().cat, NetCat::truncated);
    CHECK_EQ(stream.error().op, NetOp::tls_handshake);
}

// --- Real servers ------------------------------------------------------------

CRIMSON_TEST(tls, handshake_with_a_real_server) {
    CRIMSON_REQUIRE_NETWORK();
    auto stream = TlsStream::connect(Endpoint{"example.com", 443}, credentials());
    CHECK_OK(stream);

    const auto& info = stream->info();
    CHECK_MSG(info.protocol == "TLS 1.3" || info.protocol == "TLS 1.2",
              "negotiated " + info.protocol);
    CHECK(!info.cipher_suite.empty());
    CHECK(!info.certificate_subject.empty());
    CHECK(!info.certificate_issuer.empty());
    CHECK(!stream->peer().address.empty());
}

CRIMSON_TEST(tls, https_round_trip_reads_to_the_end) {
    CRIMSON_REQUIRE_NETWORK();
    auto stream = TlsStream::connect(Endpoint{"example.com", 443}, credentials());
    CHECK_OK(stream);

    CHECK_OK(write_all(*stream, bytes_of(http_get("example.com"))));
    std::vector<std::byte> response;
    const auto result = read_to_eof(*stream, response, 1u << 20);
    CHECK_OK(result);
    CHECK(result->eof);
    CHECK(text_of(response).starts_with("HTTP/1.1 200"));
}

CRIMSON_TEST(tls, handshake_and_response_survive_one_byte_fragmentation) {
    CRIMSON_REQUIRE_NETWORK();
    // One byte per read AND per write. Every TLS record, handshake messages
    // included, is split across hundreds of reads, driving the incomplete-
    // message and extra-bytes handling through its full length against a
    // genuine handshake.
    auto tcp = TcpStream::connect(Endpoint{"example.com", 443});
    CHECK_OK(tcp);
    auto fragmenting = std::make_unique<FragmentingStream>(
        std::make_unique<TcpStream>(std::move(*tcp)), 1, 1);
    FragmentingStream* wire = fragmenting.get();

    auto stream = TlsStream::wrap(std::move(fragmenting), credentials(), TlsOptions{"example.com"});
    CHECK_OK(stream);

    CHECK_OK(write_all(*stream, bytes_of(http_get("example.com"))));
    std::vector<std::byte> response;
    const auto result = read_to_eof(*stream, response, 1u << 20);
    CHECK_OK(result);
    CHECK(result->eof);
    CHECK(text_of(response).starts_with("HTTP/1.1 200"));

    // Proof the fragmentation actually happened, rather than the test passing
    // because the interposer was bypassed.
    CHECK_MSG(wire->reads() > 1000, "only " + std::to_string(wire->reads()) + " reads");
    CHECK(wire->reads() >= wire->bytes_read());
}

CRIMSON_TEST(tls, a_large_write_is_split_into_bounded_records) {
    CRIMSON_REQUIRE_NETWORK();
    auto tcp = TcpStream::connect(Endpoint{"example.com", 443});
    CHECK_OK(tcp);
    auto capturing = std::make_unique<FragmentingStream>(
        std::make_unique<TcpStream>(std::move(*tcp)), 0, 0);
    FragmentingStream* wire = capturing.get();

    auto stream = TlsStream::wrap(std::move(capturing), credentials(), TlsOptions{"example.com"});
    CHECK_OK(stream);

    // 48 KB fits in the socket's send buffer, so write_all completes locally
    // whatever the server makes of the request.
    constexpr std::size_t kBody = 48 * 1024;
    std::string request = "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: " +
                          std::to_string(kBody) + "\r\nConnection: close\r\n\r\n";
    request.append(kBody, 'x');

    wire->start_capture();
    CHECK_OK(write_all(*stream, bytes_of(request)));
    CHECK(!wire->capture_failed());

    // Walk what actually went on the wire: a sequence of TLS records.
    const auto& raw = wire->captured();
    std::size_t offset = 0;
    std::size_t records = 0;
    while (offset + 5 <= raw.size()) {
        const auto type = static_cast<unsigned char>(raw[offset]);
        const std::size_t length = (static_cast<std::size_t>(static_cast<unsigned char>(raw[offset + 3])) << 8) |
                                   static_cast<unsigned char>(raw[offset + 4]);
        CHECK_MSG(type == 0x17, "record " + std::to_string(records) + " has type " + std::to_string(type));
        // RFC 8446 5.2: ciphertext never exceeds 2^14 + 256 bytes.
        CHECK_MSG(length <= 16384 + 256, "record of " + std::to_string(length) + " bytes");
        offset += 5 + length;
        ++records;
    }
    CHECK_EQ(offset, raw.size());  // whole records only — never a torn one
    CHECK_MSG(records >= 3, std::to_string(records) + " records for " +
                                std::to_string(request.size()) + " bytes");
}

CRIMSON_TEST(tls, the_tls_1_2_path_works_too) {
    CRIMSON_REQUIRE_NETWORK();
    // Most servers negotiate 1.3. This one only offers 1.2, which exercises the
    // older record format and a handshake without TLS 1.3's post-handshake
    // session ticket.
    const TlsCredentials creds = credentials();
    auto stream = connect_to_test_server("tls-v1-2.badssl.com", 1012, creds);
    CHECK_OK(stream);
    CHECK_EQ(stream->info().protocol, std::string{"TLS 1.2"});
}

CRIMSON_TEST(tls, rejects_an_expired_certificate) {
    CRIMSON_REQUIRE_NETWORK();
    expect_handshake_failure("expired.badssl.com", 443, SEC_E_CERT_EXPIRED, true);
}

CRIMSON_TEST(tls, rejects_a_certificate_for_another_host) {
    CRIMSON_REQUIRE_NETWORK();
    expect_handshake_failure("wrong.host.badssl.com", 443, SEC_E_WRONG_PRINCIPAL, true);
}

CRIMSON_TEST(tls, rejects_a_self_signed_certificate) {
    CRIMSON_REQUIRE_NETWORK();
    expect_handshake_failure("self-signed.badssl.com", 443, SEC_E_UNTRUSTED_ROOT, true);
}

CRIMSON_TEST(tls, rejects_an_untrusted_root) {
    CRIMSON_REQUIRE_NETWORK();
    expect_handshake_failure("untrusted-root.badssl.com", 443, SEC_E_UNTRUSTED_ROOT, true);
}

CRIMSON_TEST(tls, rejects_a_revoked_certificate) {
    CRIMSON_REQUIRE_NETWORK();
    // Revocation is soft-fail when revocation data is unreachable. This proves
    // that tolerance does not also hide a certificate that IS revoked.
    expect_handshake_failure("revoked.badssl.com", 443, CRYPT_E_REVOKED, true);
}

CRIMSON_TEST(tls, refuses_tls_1_0) {
    CRIMSON_REQUIRE_NETWORK();
    expect_protocol_refused("tls-v1-0.badssl.com", 1010);
}

CRIMSON_TEST(tls, refuses_tls_1_1) {
    CRIMSON_REQUIRE_NETWORK();
    expect_protocol_refused("tls-v1-1.badssl.com", 1011);
}

CRIMSON_TEST(tls, connecting_by_address_does_not_verify) {
    CRIMSON_REQUIRE_NETWORK();
    // SNI cannot carry an address and certificates rarely list one, so this
    // must fail. Measured against a CDN it fails before any certificate is
    // sent — the server has no name to choose one by — so only the stage is
    // asserted, not which of the possible codes appears.
    auto tcp = TcpStream::connect(Endpoint{"example.com", 443});
    CHECK_OK(tcp);
    const std::string address = tcp->peer().address;
    tcp->close();

    const auto stream = TlsStream::connect(Endpoint{address, 443}, credentials());
    CHECK_ERR(stream);
    CHECK_EQ(stream.error().op, NetOp::tls_handshake);
}

CRIMSON_TEST(tls, repeated_handshakes_do_not_leak_handles) {
    CRIMSON_REQUIRE_NETWORK();
    const TlsCredentials shared = credentials();
    const Endpoint endpoint{"example.com", 443};

    for (int warm = 0; warm < 3; ++warm) {
        auto stream = TlsStream::connect(endpoint, shared);
        CHECK_OK(stream);
    }

    const DWORD before = handle_count();
    constexpr int kIterations = 20;
    for (int index = 0; index < kIterations; ++index) {
        auto stream = TlsStream::connect(endpoint, shared);
        CHECK_OK(stream);
    }
    const DWORD after = handle_count();

    CHECK_MSG(after <= before + 15,
              "handle count grew by " + std::to_string(after - before) + " over " +
                  std::to_string(kIterations) + " TLS connections");
}
