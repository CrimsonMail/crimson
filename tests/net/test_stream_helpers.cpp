// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "core/net/stream_helpers.h"
#include "harness.h"
#include "net/scripted_stream.h"
// For the WSA_* constants used to build representative errors. The helpers
// themselves are SDK-free; only these test fixtures name concrete codes.
#include "platform/windows/net/win_sockets.h"

// These run against the in-memory fake rather than a socket, because that is
// the only way to make partial writes and short reads happen on demand. Over
// loopback the kernel would deliver a small buffer whole almost every time, and
// the loops under test would never execute more than one iteration.

using crimson::net::NetCat;
using crimson::net::NetError;
using crimson::net::NetOp;
using crimson::net::read_exactly;
using crimson::net::read_to_eof;
using crimson::net::write_all;
using crimson::test::ScriptedStream;

namespace {

[[nodiscard]] std::span<const std::byte> bytes_of(std::string_view text) noexcept {
    return std::span{reinterpret_cast<const std::byte*>(text.data()), text.size()};
}

}  // namespace

CRIMSON_TEST(stream_helpers, write_all_loops_over_one_byte_writes) {
    ScriptedStream stream;
    stream.write_chunk(1);

    const std::string payload = "A001 CAPABILITY\r\n";
    CHECK_OK(write_all(stream, bytes_of(payload)));

    CHECK_EQ(stream.written_text(), std::string_view{payload});
    // One call per byte proves the loop actually ran rather than the whole
    // buffer going out in a single write.
    CHECK_EQ(stream.write_calls(), payload.size());
}

CRIMSON_TEST(stream_helpers, write_all_handles_uneven_chunks) {
    ScriptedStream stream;
    stream.write_chunk(7);

    const std::string payload(1000, 'x');
    CHECK_OK(write_all(stream, bytes_of(payload)));

    CHECK_EQ(stream.written().size(), payload.size());
    CHECK_EQ(stream.write_calls(), (payload.size() + 6) / 7);
}

CRIMSON_TEST(stream_helpers, write_all_stops_at_the_first_error) {
    ScriptedStream stream;
    stream.write_chunk(4).fail_write_at(
        3, NetError{WSAECONNRESET, NetOp::send, NetCat::wsa,
                    crimson::net::Retry::new_connection});

    const std::string payload(100, 'y');
    const auto result = write_all(stream, bytes_of(payload));

    CHECK_ERR(result);
    CHECK_EQ(result.error().native, WSAECONNRESET);
    CHECK_EQ(result.error().op, NetOp::send);
    // Two successful writes of four bytes landed before the failure.
    CHECK_EQ(stream.written().size(), std::size_t{8});
}

CRIMSON_TEST(stream_helpers, write_all_accepts_an_empty_buffer) {
    ScriptedStream stream;
    CHECK_OK(write_all(stream, std::span<const std::byte>{}));
    CHECK_EQ(stream.write_calls(), std::size_t{0});
}

CRIMSON_TEST(stream_helpers, read_exactly_fills_across_short_reads) {
    ScriptedStream stream;
    stream.give("HELLO WORLD").read_chunk(1);

    std::vector<std::byte> buffer(11);
    CHECK_OK(read_exactly(stream, buffer));

    const std::string_view got{reinterpret_cast<const char*>(buffer.data()),
                               buffer.size()};
    CHECK_EQ(got, std::string_view{"HELLO WORLD"});
    CHECK_EQ(stream.read_calls(), std::size_t{11});
}

CRIMSON_TEST(stream_helpers, read_exactly_reports_truncation_not_eof) {
    ScriptedStream stream;
    stream.give("short").read_chunk(2);

    // Ask for more than the stream will ever produce. An IMAP literal that
    // announces {4281} and then closes early is a protocol failure, not a
    // normal end of stream, so this must not look like success.
    std::vector<std::byte> buffer(64);
    const auto result = read_exactly(stream, buffer);

    CHECK_ERR(result);
    CHECK_EQ(result.error().cat, NetCat::truncated);
    CHECK_EQ(result.error().op, NetOp::recv);
}

CRIMSON_TEST(stream_helpers, read_exactly_refuses_to_spin_on_a_stalled_stream) {
    ScriptedStream stream;
    // A stream that reports no bytes, no EOF and no error violates the
    // ByteStream contract. The helper must fail rather than loop forever; if
    // this regresses the watchdog fires instead of the assertion.
    stream.give("abcdef").read_chunk(1).stall_at(3);

    std::vector<std::byte> buffer(6);
    const auto result = read_exactly(stream, buffer);

    CHECK_ERR(result);
    CHECK_EQ(result.error().cat, NetCat::logic);
}

CRIMSON_TEST(stream_helpers, read_exactly_accepts_an_empty_buffer) {
    ScriptedStream stream;
    CHECK_OK(read_exactly(stream, std::span<std::byte>{}));
    CHECK_EQ(stream.read_calls(), std::size_t{0});
}

CRIMSON_TEST(stream_helpers, read_to_eof_collects_everything) {
    ScriptedStream stream;
    const std::string payload(5000, 'z');
    stream.give(payload).read_chunk(64);

    std::vector<std::byte> out;
    const auto result = read_to_eof(stream, out, 1u << 20);

    CHECK_OK(result);
    CHECK(result->eof);
    CHECK_EQ(result->bytes, payload.size());
    CHECK_EQ(out.size(), payload.size());
}

CRIMSON_TEST(stream_helpers, read_to_eof_distinguishes_the_cap_from_end_of_stream) {
    ScriptedStream stream;
    stream.give(std::string(5000, 'q')).read_chunk(128);

    std::vector<std::byte> out;
    const auto result = read_to_eof(stream, out, 1000);

    CHECK_OK(result);
    // Stopping at the limit is not the same as the peer finishing, and a caller
    // must be able to tell the difference without guessing.
    CHECK(!result->eof);
    CHECK_EQ(result->bytes, std::size_t{1000});
    CHECK_EQ(out.size(), std::size_t{1000});
}

CRIMSON_TEST(stream_helpers, read_handles_bytes_and_eof_arriving_together) {
    // The case Step 2 depends on: Schannel can return application data and
    // close_notify from one input buffer, so {bytes, eof} must be expressible.
    ScriptedStream stream;
    stream.give("final").read_chunk(0).eof_with_final_bytes(true);

    std::vector<std::byte> buffer(5);
    const auto result = stream.read(buffer);

    CHECK_OK(result);
    CHECK_EQ(result->bytes, std::size_t{5});
    CHECK(result->eof);
    // One call delivered both, rather than needing a second round trip.
    CHECK_EQ(stream.read_calls(), std::size_t{1});
}

CRIMSON_TEST(stream_helpers, read_to_eof_reports_the_underlying_error) {
    ScriptedStream stream;
    stream.give("partial data here")
        .read_chunk(4)
        .fail_read_at(2, NetError{WSAECONNRESET, NetOp::recv, NetCat::wsa,
                                  crimson::net::Retry::new_connection});

    std::vector<std::byte> out;
    const auto result = read_to_eof(stream, out, 1u << 20);

    CHECK_ERR(result);
    CHECK_EQ(result.error().native, WSAECONNRESET);
    // Bytes that arrived before the failure are still in the buffer, and the
    // buffer is not left sized for a read that never completed.
    CHECK_EQ(out.size(), std::size_t{4});
}
