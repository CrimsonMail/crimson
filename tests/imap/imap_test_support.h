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
#include <utility>
#include <variant>
#include <vector>

#include "core/net/byte_stream.h"
#include "protocols/imap/lexer.h"
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
