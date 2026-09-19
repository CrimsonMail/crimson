// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// crimson-imap-probe — puts a real IMAP server's responses through Crimson's
// tokenizer.
//
//     crimson-imap-probe [--record <file>] [host] [port]
//
// Connects with TLS (imap.gmail.com on 993 unless told otherwise), reads the
// greeting, sends "a1 CAPABILITY" and then "a2 LOGOUT", and prints every token
// of every response.
//
// It never sends credentials. Everything it exercises happens before login,
// which is still where the hardest tokenizing lives: status responses whose
// free text may contain brackets, quotes or a "{5}" that must not be taken for
// a literal, and response codes with arguments of every shape.
//
// --record writes the bytes the server sent to <file>, byte for byte, for use
// as a test fixture in tests/imap/fixtures. IP addresses are replaced with
// documentation addresses first (192.0.2.x, 2001:db8::x), because some
// greetings name the address the connection came from — which would publish
// the recording machine's public IP in the repository.

#include <cstdio>
#include <cstdlib>
#include <expected>
#include <map>
#include <span>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

#include "core/net/stream_helpers.h"
#include "core/version.h"
#include "platform/windows/net/sspi_error.h"
#include "platform/windows/net/tls_stream.h"
#include "platform/windows/net/win_sockets.h"
#include "platform/windows/net/winsock_runtime.h"
#include "platform/windows/net/wsa_error.h"
#include "protocols/imap/response_reader.h"

namespace {

using namespace crimson::net;
using namespace crimson::net::win;
using crimson::imap::ReadError;
using crimson::imap::ReadStatus;
using crimson::imap::ResponseKind;
using crimson::imap::ResponseReader;
using crimson::imap::SyntaxError;
using crimson::imap::Token;
using crimson::imap::TokenKind;

// Keeps a copy of everything read through it.
class RecordingStream final : public ByteStream {
public:
    explicit RecordingStream(ByteStream& inner) : inner_(inner) {}

    ReadOutcome read(std::span<std::byte> dst) noexcept override {
        auto result = inner_.read(dst);
        if (result && result->bytes > 0) {
            try {
                recorded_.insert(recorded_.end(), dst.begin(), dst.begin() + static_cast<std::ptrdiff_t>(result->bytes));
            } catch (...) {
                overflowed_ = true;
            }
        }
        return result;
    }
    WriteOutcome write_some(std::span<const std::byte> src) noexcept override {
        return inner_.write_some(src);
    }
    VoidOutcome shutdown_send() noexcept override { return inner_.shutdown_send(); }
    void close() noexcept override { inner_.close(); }

    [[nodiscard]] const std::vector<std::byte>& recorded() const noexcept { return recorded_; }
    [[nodiscard]] bool overflowed() const noexcept { return overflowed_; }

private:
    ByteStream& inner_;
    std::vector<std::byte> recorded_;
    bool overflowed_ = false;
};

void report_network_failure(const char* summary, const NetError& error) {
    std::printf("\n%s\n", summary);
    if (is_certificate_error(error)) {
        std::printf("The server's certificate could not be verified, so the connection was not\n"
                    "trusted. Crimson does not connect to servers it cannot verify.\n");
    }
    std::printf("\nTechnical details:\n  stage: %s\n  category: %s\n  code: %s\n  detail: %s\n",
                std::string{to_string(error.op)}.c_str(), std::string{to_string(error.cat)}.c_str(),
                error_name(error).c_str(), describe(error).c_str());
}

void report_syntax_failure(const SyntaxError& error, const std::vector<std::byte>& received) {
    std::printf("\nThe server sent something Crimson could not read: %s.\n",
                std::string{crimson::imap::describe(error.kind)}.c_str());
    std::printf("\nTechnical details:\n  error: %s\n  offset: %llu of %zu bytes received\n",
                std::string{crimson::imap::to_string(error.kind)}.c_str(),
                static_cast<unsigned long long>(error.offset), received.size());
}

void report_read_failure(const char* summary, const ReadError& error,
                         const std::vector<std::byte>& received) {
    if (const auto* net = std::get_if<NetError>(&error)) {
        report_network_failure(summary, *net);
    } else {
        report_syntax_failure(std::get<SyntaxError>(error), received);
    }
}

// Printable form of raw bytes: CR and LF are shown, not acted on.
std::string printable(std::string_view raw) {
    std::string shown;
    for (const char character : raw) {
        const auto value = static_cast<unsigned char>(character);
        if (value >= 0x20 && value < 0x7F) {
            shown.push_back(character);
        } else if (value == '\r') {
            shown += "\\r";
        } else if (value == '\n') {
            shown += "\\n";
        } else {
            char escape[8];
            std::snprintf(escape, sizeof escape, "\\x%02X", value);
            shown += escape;
        }
    }
    return shown;
}

struct ResponseSummary {
    ResponseKind kind = ResponseKind::none;
    std::string tag;
    bool bye = false;
    bool saw_literal = false;
};

// Reads one whole response, printing it as the server sent it and then as
// tokens. Returns ReadStatus::end if the server closed between responses.
std::expected<ReadStatus, ReadError> read_response(ResponseReader& reader, ResponseSummary& summary,
                                                   std::size_t& token_count) {
    summary = {};
    std::string line;
    std::string tokens;
    Token token;
    std::size_t index = 0;
    for (;;) {
        const auto got = reader.next(token);
        if (!got) {
            return std::unexpected(got.error());
        }
        if (*got == ReadStatus::end) {
            return ReadStatus::end;
        }
        ++token_count;
        line.append(token.spaces_before, ' ');
        if (token.is(TokenKind::literal_data)) {
            line += "<" + std::to_string(token.data.size()) + " literal bytes>";
        } else if (!token.is(TokenKind::eol)) {
            line += token.raw;
        }

        if (index == 0) {
            summary.tag = token.raw;
            summary.kind = reader.kind();
        } else if (index == 1) {
            summary.bye = token.is_atom("BYE");
        }
        if (token.is(TokenKind::literal_begin)) {
            summary.saw_literal = true;
        }
        ++index;

        tokens += "  ";
        tokens += std::string{crimson::imap::to_string(token.kind)};
        switch (token.kind) {
            case TokenKind::lparen:
            case TokenKind::rparen:
            case TokenKind::lbracket:
            case TokenKind::rbracket:
            case TokenKind::eol:
            case TokenKind::literal_end:
                break;
            case TokenKind::literal_data:
                tokens += "(" + std::to_string(token.data.size()) + " bytes)";
                break;
            case TokenKind::literal_begin:
                tokens += "(" + std::to_string(token.number) + (token.binary ? ", binary)" : ")");
                break;
            default:
                tokens += "(" + printable(token.value()) + ")";
                break;
        }

        if (token.is(TokenKind::eol) && reader.at_response_start()) {
            std::printf("S: %s\n  %s\n", printable(line).c_str(), tokens.c_str());
            return ReadStatus::token;
        }
    }
}

// Writes the whole command, CRLF included. The commands are fixed strings:
// the probe has no command layer and wants none.
[[nodiscard]] VoidOutcome send_command(ByteStream& stream, std::string_view command) {
    std::printf("C: %s\n", std::string{command.substr(0, command.size() - 2)}.c_str());
    return write_all(stream, std::span{reinterpret_cast<const std::byte*>(command.data()), command.size()});
}

// Replaces every IPv4 and IPv6 address in `text` with a documentation address.
// Candidates are maximal runs of address characters, each confirmed by the
// system's own parser, so "12:34:56" or "IMAP4rev1" are left alone. A dotted
// version number that happens to be a valid IPv4 address is replaced too;
// that costs a little fidelity and never leaks an address.
std::string redact_addresses(std::string_view text, std::size_t& replaced) {
    const auto is_address_char = [](char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') || c == ':' ||
               c == '.';
    };
    std::map<std::string, std::string> substitutes;
    std::string result;
    std::size_t index = 0;
    while (index < text.size()) {
        if (!is_address_char(text[index])) {
            result.push_back(text[index++]);
            continue;
        }
        std::size_t end = index;
        while (end < text.size() && is_address_char(text[end])) {
            ++end;
        }
        // A sentence can end right after an address: "from 203.0.113.9."
        std::size_t trimmed = end;
        while (trimmed > index && (text[trimmed - 1] == '.' || text[trimmed - 1] == ':')) {
            --trimmed;
        }
        const std::string candidate{text.substr(index, trimmed - index)};
        IN_ADDR v4{};
        IN6_ADDR v6{};
        std::string substitute;
        if (!candidate.empty() && ::InetPtonA(AF_INET, candidate.c_str(), &v4) == 1) {
            auto [entry, inserted] = substitutes.try_emplace(candidate);
            if (inserted) {
                entry->second = "192.0.2." + std::to_string(substitutes.size());
            }
            substitute = entry->second;
        } else if (!candidate.empty() && candidate.find(':') != std::string::npos &&
                   ::InetPtonA(AF_INET6, candidate.c_str(), &v6) == 1) {
            auto [entry, inserted] = substitutes.try_emplace(candidate);
            if (inserted) {
                entry->second = "2001:db8::" + std::to_string(substitutes.size());
            }
            substitute = entry->second;
        }
        if (substitute.empty()) {
            result.append(text.substr(index, end - index));
        } else {
            ++replaced;
            result += substitute;
            result.append(text.substr(trimmed, end - trimmed));
        }
        index = end;
    }
    return result;
}

bool write_recording(const char* path, const std::vector<std::byte>& received) {
    std::size_t replaced = 0;
    const std::string redacted = redact_addresses(
        std::string_view{reinterpret_cast<const char*>(received.data()), received.size()}, replaced);

    std::FILE* file = nullptr;
    if (fopen_s(&file, path, "wb") != 0 || file == nullptr) {
        std::printf("\nCouldn't open %s for writing.\n", path);
        return false;
    }
    const bool written = std::fwrite(redacted.data(), 1, redacted.size(), file) == redacted.size();
    const bool closed = std::fclose(file) == 0;
    if (!written || !closed) {
        std::printf("\nCouldn't write %s.\n", path);
        return false;
    }
    std::printf("\nRecorded %zu bytes to %s (%zu address%s redacted).\n", redacted.size(), path, replaced,
                replaced == 1 ? "" : "es");
    return true;
}

}  // namespace

int main(int argc, char** argv) {
    const char* record_path = nullptr;
    std::vector<std::string> positional;
    for (int index = 1; index < argc; ++index) {
        const std::string_view argument = argv[index];
        if (argument == "--record" && index + 1 < argc) {
            record_path = argv[++index];
        } else if (argument == "--record") {
            std::printf("--record needs a file name.\n");
            return 2;
        } else {
            positional.emplace_back(argument);
        }
    }

    const std::string host = !positional.empty() ? positional[0] : "imap.gmail.com";
    std::uint16_t port = 993;
    if (positional.size() > 1) {
        const long parsed = std::strtol(positional[1].c_str(), nullptr, 10);
        if (parsed <= 0 || parsed > 65535) {
            std::printf("Port must be between 1 and 65535.\n");
            return 2;
        }
        port = static_cast<std::uint16_t>(parsed);
    }

    std::printf("Crimson %s - IMAP probe\n\n", std::string{crimson::version_string}.c_str());

    const auto winsock = WinsockScope::create();
    if (!winsock) {
        report_network_failure("Couldn't start Windows networking.", winsock.error());
        return 1;
    }
    const auto credentials = TlsCredentials::create();
    if (!credentials) {
        report_network_failure("Couldn't set up secure connections.", credentials.error());
        return 1;
    }

    std::printf("Connecting to %s:%u...\n", host.c_str(), static_cast<unsigned>(port));
    auto tls = TlsStream::connect(Endpoint{host, port}, *credentials);
    if (!tls) {
        report_network_failure("Couldn't establish a secure connection to the server.", tls.error());
        return 1;
    }
    std::printf("Connected securely (%s, %s).\n\n", tls->info().protocol.c_str(),
                tls->info().cipher_suite.c_str());

    RecordingStream stream{*tls};
    ResponseReader reader{stream};
    ResponseSummary summary;
    std::size_t tokens = 0;
    std::size_t responses = 0;
    bool saw_literal = false;

    // Greeting.
    auto got = read_response(reader, summary, tokens);
    if (!got || *got == ReadStatus::end) {
        if (!got) {
            report_read_failure("Couldn't read the server's greeting.", got.error(), stream.recorded());
        } else {
            std::printf("\nThe server closed the connection without a greeting.\n");
        }
        return 1;
    }
    ++responses;
    if (summary.bye) {
        std::printf("\nThe server refused the connection in its greeting.\n");
        return 1;
    }

    // One command, then log out. Each is complete when its tagged response
    // arrives; everything untagged before it is printed on the way.
    for (const std::string_view command : {std::string_view{"a1 CAPABILITY\r\n"},
                                           std::string_view{"a2 LOGOUT\r\n"}}) {
        const std::string tag{command.substr(0, 2)};
        if (const auto sent = send_command(stream, command); !sent) {
            report_network_failure("Couldn't send a command.", sent.error());
            return 1;
        }
        for (;;) {
            got = read_response(reader, summary, tokens);
            if (!got) {
                report_read_failure("Couldn't read the server's response.", got.error(), stream.recorded());
                return 1;
            }
            if (*got == ReadStatus::end) {
                break;  // a server may close straight after its BYE
            }
            ++responses;
            saw_literal = saw_literal || summary.saw_literal;
            if (summary.kind == ResponseKind::tagged && summary.tag == tag) {
                break;
            }
        }
        if (*got == ReadStatus::end) {
            break;
        }
    }

    (void)stream.shutdown_send();

    std::printf("\nSummary\n  host:       %s\n  responses:  %zu\n  tokens:     %zu\n  bytes:      %zu\n",
                host.c_str(), responses, tokens, stream.recorded().size());

    if (record_path != nullptr) {
        if (stream.overflowed()) {
            std::printf("\nNot recording: the copy of the traffic is incomplete.\n");
            return 1;
        }
        if (saw_literal) {
            // Redaction changes lengths, which would break a literal's {n}.
            std::printf("\nNot recording: the traffic contains a literal, and redacting addresses\n"
                        "could change its length.\n");
            return 1;
        }
        if (!write_recording(record_path, stream.recorded())) {
            return 1;
        }
    }
    return 0;
}
