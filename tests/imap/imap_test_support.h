// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef CRIMSON_TESTS_IMAP_IMAP_TEST_SUPPORT_H
#define CRIMSON_TESTS_IMAP_IMAP_TEST_SUPPORT_H

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <optional>
#include <source_location>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

#include "core/net/byte_stream.h"
#include "protocols/imap/lexer.h"
#include "protocols/imap/parser.h"
#include "protocols/imap/response.h"
#include "protocols/imap/response_reader.h"

namespace crimson::test::imap {

using crimson::imap::LexerLimits;
using crimson::imap::LexMode;
using crimson::imap::ReadStatus;
using crimson::imap::SyntaxError;
using crimson::imap::Token;
using crimson::imap::TokenKind;

// A ByteStream that hands out `input` in exactly the pieces listed in
// `chunks`, then reports end of stream. Where ScriptedStream uses one chunk
// size throughout, this places every boundary where a test wants it — which is
// how the tests put a split at every single byte position of a transcript.
class ChunkedSource final : public crimson::net::ByteStream {
public:
    ChunkedSource(std::string_view input, std::vector<std::size_t> chunks)
        : input_(input), chunks_(std::move(chunks)) {}

    crimson::net::ReadOutcome read(std::span<std::byte> dst) noexcept override {
        if (position_ >= input_.size()) {
            return crimson::net::ReadResult{0, true};
        }
        std::size_t want = input_.size() - position_;
        if (next_chunk_ < chunks_.size()) {
            want = std::min(want, std::max<std::size_t>(chunks_[next_chunk_++], 1));
        }
        const std::size_t count = std::min(want, dst.size());
        std::copy_n(reinterpret_cast<const std::byte*>(input_.data()) + position_, count, dst.begin());
        position_ += count;
        return crimson::net::ReadResult{count, false};
    }
    crimson::net::WriteOutcome write_some(std::span<const std::byte> src) noexcept override {
        return src.size();
    }
    crimson::net::VoidOutcome shutdown_send() noexcept override { return {}; }
    void close() noexcept override {}

private:
    std::string_view input_;
    std::vector<std::size_t> chunks_;
    std::size_t next_chunk_ = 0;
    std::size_t position_ = 0;
};

// A token reduced to what the server actually said. Consecutive literal_data
// tokens are merged, because how literal content is divided depends on how
// the network divided it, and nothing else about the token stream may.
struct Lexed {
    TokenKind kind = TokenKind::eol;
    std::uint32_t spaces = 0;
    std::uint64_t offset = 0;
    std::string bytes;  // raw, or the literal content
    std::string unescaped;
    std::uint64_t number = 0;
    bool binary = false;

    bool operator==(const Lexed&) const = default;
};

struct Tokenized {
    std::vector<Lexed> tokens;
    std::optional<crimson::imap::ReadError> error;
    bool ended_cleanly = false;

    [[nodiscard]] std::optional<SyntaxError> syntax_error() const {
        if (error && std::holds_alternative<SyntaxError>(*error)) {
            return std::get<SyntaxError>(*error);
        }
        return std::nullopt;
    }
};

inline void append(Tokenized& result, const Token& token) {
    if (token.is(TokenKind::literal_data) && !result.tokens.empty() &&
        result.tokens.back().kind == TokenKind::literal_data) {
        result.tokens.back().bytes.append(reinterpret_cast<const char*>(token.data.data()),
                                          token.data.size());
        return;
    }
    Lexed lexed;
    lexed.kind = token.kind;
    lexed.spaces = token.spaces_before;
    lexed.offset = token.offset;
    lexed.bytes = token.is(TokenKind::literal_data)
                      ? std::string{reinterpret_cast<const char*>(token.data.data()), token.data.size()}
                      : token.raw;
    lexed.unescaped = token.unescaped;
    lexed.number = token.number;
    lexed.binary = token.binary;
    result.tokens.push_back(std::move(lexed));
}

// Reads `input` through ResponseReader::next, delivered in `chunks`.
inline Tokenized read_framed(std::string_view input, std::vector<std::size_t> chunks,
                             LexerLimits limits = {}) {
    ChunkedSource source{input, std::move(chunks)};
    crimson::imap::ResponseReader reader{source, limits};
    Tokenized result;
    Token token;
    for (;;) {
        const auto got = reader.next(token);
        if (!got) {
            result.error = got.error();
            return result;
        }
        if (*got == ReadStatus::end) {
            result.ended_cleanly = true;
            return result;
        }
        append(result, token);
    }
}

inline Tokenized read_framed(std::string_view input, LexerLimits limits = {}) {
    return read_framed(input, std::vector<std::size_t>{input.size()}, limits);
}

// Runs the bare Lexer over `input` in a single mode, all input at once.
inline Tokenized lex(std::string_view input, LexMode mode = LexMode::normal, LexerLimits limits = {}) {
    crimson::imap::Lexer lexer{limits};
    lexer.feed(std::span{reinterpret_cast<const std::byte*>(input.data()), input.size()});
    lexer.finish();
    Tokenized result;
    Token token;
    for (;;) {
        const auto got = lexer.next(mode, token);
        if (!got) {
            result.error = crimson::imap::ReadError{got.error()};
            return result;
        }
        if (*got == crimson::imap::LexStatus::end_of_input) {
            result.ended_cleanly = true;
            return result;
        }
        append(result, token);
    }
}

// For assertion messages.
inline std::string error_text(const Tokenized& result) {
    if (!result.error) {
        return "no error";
    }
    if (const auto* syntax = std::get_if<SyntaxError>(&*result.error)) {
        return std::string{to_string(syntax->kind)} + " at offset " + std::to_string(syntax->offset);
    }
    return "network error";
}

// The lossless property: spaces and raw bytes, in order, are the input.
inline std::string reassemble(const Tokenized& result) {
    std::string bytes;
    for (const Lexed& token : result.tokens) {
        bytes.append(token.spaces, ' ');
        bytes += token.bytes;
    }
    return bytes;
}

// --- Parsing -----------------------------------------------------------------

// The result of parsing a whole transcript: the responses, how it ended, and
// a comparable summary so the same input divided differently can be checked
// for having produced the same meaning.
struct Parsed {
    std::vector<crimson::imap::Response> responses;
    std::optional<crimson::imap::ReadError> error;
    bool ended_cleanly = false;

    [[nodiscard]] std::optional<SyntaxError> syntax_error() const {
        if (error && std::holds_alternative<SyntaxError>(*error)) {
            return std::get<SyntaxError>(*error);
        }
        return std::nullopt;
    }

    [[nodiscard]] std::string error_text() const {
        if (!error) {
            return "no error";
        }
        if (const auto syntax = syntax_error()) {
            return std::string{to_string(syntax->kind)} + " at offset " + std::to_string(syntax->offset);
        }
        return "network error";
    }

    [[nodiscard]] std::string summary() const;
};

inline std::string describe(const crimson::imap::StatusResponse& status) {
    std::string text = std::string{to_string(status.kind)};
    if (status.code.kind != crimson::imap::ResponseCodeKind::none) {
        text += " [" + status.code.name;
        if (status.code.number) {
            text += " " + std::to_string(*status.code.number);
        }
        if (status.code.capabilities) {
            text += " x" + std::to_string(status.code.capabilities->names.size());
        }
        if (status.code.flags) {
            text += " flags:" + std::to_string(status.code.flags->keywords.size()) +
                    (status.code.flags->seen ? "+seen" : "");
        }
        for (const std::string& argument : status.code.arguments) {
            text += " " + argument;
        }
        text += "]";
    }
    return text + " '" + status.text + "'";
}

inline std::string describe(const crimson::imap::UntaggedBody& body) {
    return std::visit(
        [](const auto& value) -> std::string {
            using Kind = std::decay_t<decltype(value)>;
            if constexpr (std::is_same_v<Kind, crimson::imap::StatusResponse>) {
                return "status " + describe(value);
            } else if constexpr (std::is_same_v<Kind, crimson::imap::UnknownResponse>) {
                return "unknown " + value.name + " '" + value.text + "'";
            } else if constexpr (std::is_same_v<Kind, crimson::imap::Capabilities>) {
                std::string text = "capabilities";
                for (const std::string& name : value.names) {
                    text += " " + name;
                }
                return text;
            } else if constexpr (std::is_same_v<Kind, crimson::imap::MailboxListing>) {
                std::string text = "list '" + value.name + "' delimiter=";
                text += value.delimiter ? std::string{*value.delimiter} : std::string{"NIL"};
                for (const std::string& attribute : value.attributes) {
                    text += " " + attribute;
                }
                return text;
            } else if constexpr (std::is_same_v<Kind, crimson::imap::MailboxStatus>) {
                const auto number = [](const auto& optional) {
                    return optional ? std::to_string(*optional) : std::string{"-"};
                };
                return "status-of '" + value.mailbox + "' messages=" + number(value.messages) +
                       " uidnext=" + number(value.uid_next) + " uidvalidity=" + number(value.uid_validity) +
                       " unseen=" + number(value.unseen) + " modseq=" + number(value.highest_mod_sequence);
            } else if constexpr (std::is_same_v<Kind, crimson::imap::SearchResults>) {
                std::string text = "search";
                for (const std::uint32_t number : value.numbers) {
                    text += " " + std::to_string(number);
                }
                if (value.mod_sequence) {
                    text += " modseq=" + std::to_string(*value.mod_sequence);
                }
                return text;
            } else if constexpr (std::is_same_v<Kind, crimson::imap::MailboxFlags>) {
                std::string text = "flags";
                text += value.flags.seen ? " seen" : "";
                text += value.flags.answered ? " answered" : "";
                text += value.flags.accepts_new_keywords ? " *" : "";
                for (const std::string& keyword : value.flags.keywords) {
                    text += " " + keyword;
                }
                return text;
            } else if constexpr (std::is_same_v<Kind, crimson::imap::MailboxCount>) {
                return std::string{to_string(value.kind)} + " " + std::to_string(value.number);
            } else {
                return "other";
            }
        },
        body);
}

inline std::string Parsed::summary() const {
    std::string text;
    for (const crimson::imap::Response& response : responses) {
        text += std::visit(
            [](const auto& value) -> std::string {
                using Kind = std::decay_t<decltype(value)>;
                if constexpr (std::is_same_v<Kind, crimson::imap::TaggedResponse>) {
                    return "tagged " + value.tag + " " + describe(value.status);
                } else if constexpr (std::is_same_v<Kind, crimson::imap::UntaggedResponse>) {
                    return "untagged " + describe(value.body);
                } else {
                    return "continuation '" + value.text + "'";
                }
            },
            response);
        text += "\n";
    }
    text += ended_cleanly ? "end\n" : (error ? error_text() + "\n" : "stopped\n");
    return text;
}

// Parses `input`, delivered in `chunks` (the whole thing at once by default).
inline Parsed parse_all(std::string_view input, std::vector<std::size_t> chunks = {},
                        crimson::imap::Parser::Limits limits = {}) {
    if (chunks.empty()) {
        chunks.push_back(input.size());
    }
    ChunkedSource source{input, std::move(chunks)};
    crimson::imap::ResponseReader reader{source};
    crimson::imap::Parser parser{reader, limits};
    Parsed parsed;
    for (;;) {
        crimson::imap::Response response;
        const auto got = parser.next(response);
        if (!got) {
            parsed.error = got.error();
            return parsed;
        }
        if (*got == crimson::imap::ParseStatus::end) {
            parsed.ended_cleanly = true;
            return parsed;
        }
        parsed.responses.push_back(std::move(response));
    }
}

// Test transcripts live beside this header, in fixtures/. Located from this
// file's own path so the suite finds them whatever the working directory.
inline std::filesystem::path fixture_directory() {
    return std::filesystem::path{std::source_location::current().file_name()}.parent_path() / "fixtures";
}

inline std::string read_file(const std::filesystem::path& path) {
    std::ifstream file{path, std::ios::binary};
    return std::string{std::istreambuf_iterator<char>{file}, std::istreambuf_iterator<char>{}};
}

}  // namespace crimson::test::imap

#endif  // CRIMSON_TESTS_IMAP_IMAP_TEST_SUPPORT_H
