// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// crimson-net-smoke — exercises the networking layer against a real server.
//
//     crimson-net-smoke [host] [port]
//
// Resolves a host, connects, sends a fixed HTTP request, reads to end of
// stream, and reports what happened. Defaults to example.com:80.
//
// This is a diagnostic tool, not a test and not an HTTP client. It writes a
// fixed request and prints bytes; it does not parse the response. HTTP is used
// only because it is a plaintext TCP protocol whose behaviour is easy to eyeball
// while proving DNS, connection, partial-safe writing, reading and end-of-stream
// detection all work together.
//
// The thing worth watching in the output is the elapsed time when a candidate
// fails. On a host with IPv6 configured but no working IPv6 route, failover to
// the IPv4 candidate should take milliseconds. A plain blocking connect would
// take about 21 seconds, which is the reason connect uses an explicit deadline.

#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#include "core/net/stream_helpers.h"
#include "core/version.h"
#include "platform/windows/net/net_log.h"
#include "platform/windows/net/tcp_stream.h"
#include "platform/windows/net/winsock_runtime.h"
#include "platform/windows/net/wsa_error.h"

namespace {

using namespace crimson::net;
using namespace crimson::net::win;

constexpr std::size_t kMaxResponseBytes = 1u << 20;  // 1 MiB is plenty to look at
constexpr std::size_t kPreviewBytes = 512;

// Calm, plain wording, with the machine detail in its own section rather than
// in the user's face. See the Crimson naming guide on error tone.
void report_failure(const char* summary, const NetError& error) {
    std::printf("\n%s\n\nTechnical details:\n  stage: %s\n  category: %s\n"
                "  code: %s\n  detail: %s\n  retry: %s\n",
                summary, std::string{to_string(error.op)}.c_str(),
                std::string{to_string(error.cat)}.c_str(),
                symbolic_name(error.native).c_str(), describe(error).c_str(),
                std::string{to_string(error.retry)}.c_str());
}

void print_preview(const std::vector<std::byte>& data) {
    const std::size_t shown = data.size() < kPreviewBytes ? data.size() : kPreviewBytes;
    std::printf("\nFirst %zu bytes:\n", shown);
    std::printf("----------------------------------------\n");
    for (std::size_t index = 0; index < shown; ++index) {
        const auto value = static_cast<unsigned char>(data[index]);
        if (value == '\n' || value == '\t' || (value >= 0x20 && value < 0x7f)) {
            std::fputc(static_cast<int>(value), stdout);
        } else if (value == '\r') {
            // Skip, so CRLF line endings do not double-space the preview.
        } else {
            std::fputc('.', stdout);
        }
    }
    std::printf("\n----------------------------------------\n");
}

}  // namespace

int main(int argc, char** argv) {
    std::string host = "example.com";
    std::uint16_t port = 80;

    if (argc > 1) {
        host = argv[1];
    }
    if (argc > 2) {
        const long parsed = std::strtol(argv[2], nullptr, 10);
        if (parsed <= 0 || parsed > 65535) {
            std::printf("Port must be between 1 and 65535.\n");
            return 2;
        }
        port = static_cast<std::uint16_t>(parsed);
    }

    std::printf("Crimson %s - network smoke test\n\n",
                std::string{crimson::version_string}.c_str());

    // Structured diagnostics from the networking layer go to stderr, so they
    // interleave with this report without corrupting it if stdout is piped.
    set_log_level(LogLevel::debug);

    const auto winsock = WinsockScope::create();
    if (!winsock) {
        report_failure("Couldn't start Windows networking.", winsock.error());
        return 1;
    }

    std::printf("Connecting to %s:%u...\n", host.c_str(), static_cast<unsigned>(port));

    const Endpoint endpoint{host, port};
    auto stream = TcpStream::connect(endpoint);
    if (!stream) {
        report_failure("Couldn't connect to the server.", stream.error());
        return 1;
    }

    std::printf("\nConnected.\n  address: %s\n  family:  %s\n  port:    %u\n"
                "  local:   %s\n",
                stream->peer().address.c_str(),
                std::string{to_string(stream->peer().family)}.c_str(),
                static_cast<unsigned>(stream->peer().port),
                stream->local().address.c_str());

    // CRLF on the wire, and Connection: close is load-bearing. HTTP/1.1
    // defaults to keep-alive, so without it "read to end of stream" would wait
    // out the server's idle timeout instead of finishing.
    const std::string request = "GET / HTTP/1.1\r\nHost: " + host +
                                "\r\nConnection: close\r\nUser-Agent: crimson-net-smoke/" +
                                std::string{crimson::version_string} + "\r\n\r\n";

    std::printf("\nSending %zu bytes...\n", request.size());
    const auto written = write_all(
        *stream, std::span{reinterpret_cast<const std::byte*>(request.data()),
                           request.size()});
    if (!written) {
        report_failure("Couldn't send the request.", written.error());
        return 1;
    }
    std::printf("Sent %zu bytes.\n", request.size());

    std::printf("\nReading response...\n");
    std::vector<std::byte> response;
    const auto result = read_to_eof(*stream, response, kMaxResponseBytes);

    if (!result) {
        const NetError error = result.error();
        // Real servers frequently abort rather than close cleanly once they
        // have finished responding. Treat a reset as a degraded end of stream
        // if usable bytes already arrived, rather than discarding them.
        if (error.native == WSAECONNRESET && !response.empty()) {
            std::printf("Received %zu bytes, then the peer reset the connection.\n",
                        response.size());
            print_preview(response);
            std::printf("\nPartial success: data arrived, but the close was not"
                        " orderly.\n");
            return 0;
        }
        report_failure("Couldn't read the response.", error);
        return 1;
    }

    if (result->eof) {
        std::printf("Received %zu bytes. Peer closed the connection cleanly.\n",
                    response.size());
    } else {
        std::printf("Received %zu bytes, stopping at the %zu byte limit.\n",
                    response.size(), kMaxResponseBytes);
    }

    print_preview(response);

    // Orderly close: stop sending, then let the stream's destructor release the
    // socket. The response has already been drained to end of stream, which is
    // what keeps closesocket from emitting an RST.
    if (const auto finished = stream->shutdown_send(); !finished) {
        report_failure("Couldn't shut the connection down cleanly.", finished.error());
        return 1;
    }

    std::printf("\nSummary\n  host:           %s\n  address:        %s\n"
                "  family:         %s\n  bytes sent:     %zu\n"
                "  bytes received: %zu\n  clean close:    %s\n",
                host.c_str(), stream->peer().address.c_str(),
                std::string{to_string(stream->peer().family)}.c_str(), request.size(),
                response.size(), result->eof ? "yes" : "no (hit byte limit)");

    return 0;
}
