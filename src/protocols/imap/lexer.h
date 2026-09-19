// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef CRIMSON_PROTOCOLS_IMAP_LEXER_H
#define CRIMSON_PROTOCOLS_IMAP_LEXER_H

#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <string_view>
#include <vector>

#include "protocols/imap/syntax_error.h"
#include "protocols/imap/token.h"

namespace crimson::imap {

// How the next token is to be read. The caller chooses, because IMAP cannot be
// tokenized without context: after OK, NO, BAD, PREAUTH, BYE or +, the rest of
// the line is free text, and that text can contain an unbalanced quote or a
// "{5}". Read in normal mode, that "{5}" would be taken as a literal
// announcement and the next five bytes of the following response swallowed —
// the stream would be silently out of step from then on. See ADR 0012.
enum class LexMode : std::uint8_t {
    normal,     // atoms, numbers, NIL, quoted strings, literals, ( ) [ ]
    astring,    // as normal, except [ and ] belong to atoms, so an unquoted
                // [Gmail]/Drafts is one token (RFC 9051 ASTRING-CHAR)
    text,       // the rest of the line as one text token, whatever it holds
    resp_text,  // as text, except that a leading [ opens a response code
    code_name,  // just after [: the code's name, as an atom
    code_text,  // a response code's arguments as text, up to ] or the line end
};

// Upper bounds on what a server can make the lexer hold. A server is untrusted
// input like any other, and a parser without limits can be made to allocate
// until the process dies.
struct LexerLimits {
    // One atom, number, quoted string or text token, or one run of spaces.
    // Literals are exempt: they are streamed, never held whole.
    std::size_t max_token_bytes = 64 * 1024;

    // The largest literal announced by {n} that is accepted at all. Providers
    // cap messages well below this; a larger announcement is either an attack
    // or a server fault.
    std::uint64_t max_literal_bytes = std::uint64_t{2} << 30;  // 2 GiB

    // Nested ( and [. Real BODYSTRUCTUREs stay in single digits; thousands of
    // opening parentheses are an attack on whatever recursive parser follows.
    std::uint32_t max_depth = 128;
};

enum class LexStatus : std::uint8_t {
    token,         // `out` holds the next token
    need_more,     // feed() more input, then call next() again with the same mode
    end_of_input,  // finish() was called and the input ended cleanly between lines
};

using LexOutcome = std::expected<LexStatus, SyntaxError>;

[[nodiscard]] constexpr std::string_view to_string(LexMode mode) noexcept {
    switch (mode) {
        case LexMode::normal:    return "normal";
        case LexMode::astring:   return "astring";
        case LexMode::text:      return "text";
        case LexMode::resp_text: return "resp_text";
        case LexMode::code_name: return "code_name";
        case LexMode::code_text: return "code_text";
    }
    return "unknown";
}

[[nodiscard]] constexpr std::string_view to_string(LexStatus status) noexcept {
    switch (status) {
        case LexStatus::token:        return "token";
        case LexStatus::need_more:    return "need_more";
        case LexStatus::end_of_input: return "end_of_input";
    }
    return "unknown";
}

// A streaming IMAP tokenizer.
//
// It performs no I/O. Bytes go in through feed(), in pieces of any size, and
// tokens come out of next(). It can stop at any byte and resume there, and
// every decision depends only on bytes it has already examined — so the tokens
// are identical however the input was split, which is the property that TCP's
// arbitrary read boundaries demand. The tests replay real server traffic split
// at every possible position to hold it to that.
//
// Literals are streamed rather than buffered: literal_begin announces the
// size, literal_data tokens carry the content in whatever pieces are
// available, and literal_end closes it. A 50 MB message body therefore never
// has to fit in memory, which is what streaming bodies to disk will need.
//
// After a SyntaxError the lexer stays failed and returns the same error from
// every call. The stream is out of step; the connection has to go.
//
// Exceptions: feed() and next() can throw std::bad_alloc, and nothing else
// (ADR 0006).
class Lexer {
public:
    explicit Lexer(LexerLimits limits = {}) noexcept : limits_(limits) {}

    // Appends input. Invalidates any literal_data view returned earlier.
    void feed(std::span<const std::byte> bytes);

    // Declares that no more input will arrive. A token that was waiting for its
    // terminator is then complete, and input that stops part-way through a
    // line becomes an unexpected_end error.
    void finish() noexcept { finished_ = true; }

    // Produces the next token, read according to `mode`. While a literal is
    // being delivered the mode is irrelevant: literal content is opaque.
    [[nodiscard]] LexOutcome next(LexMode mode, Token& out);

    // Stream offset of the next byte not yet consumed.
    [[nodiscard]] std::uint64_t offset() const noexcept { return base_offset_ + pos_; }

    [[nodiscard]] bool in_literal() const noexcept { return literal_active_; }

    // True between lines: nothing of a new line has been consumed yet.
    [[nodiscard]] bool at_line_start() const noexcept {
        return line_start_ && pending_spaces_ == 0 && !literal_active_;
    }

    // Bytes received but not yet consumed.
    [[nodiscard]] std::size_t buffered() const noexcept { return buffer_.size() - pos_; }

    [[nodiscard]] const LexerLimits& limits() const noexcept { return limits_; }

private:
    [[nodiscard]] LexOutcome lex_general(LexMode mode, Token& out);
    [[nodiscard]] LexOutcome lex_eol(Token& out);
    [[nodiscard]] LexOutcome lex_open(TokenKind kind, Token& out);
    [[nodiscard]] LexOutcome lex_close(TokenKind kind, Token& out);
    [[nodiscard]] LexOutcome lex_atom(LexMode chars, bool classify, Token& out);
    [[nodiscard]] LexOutcome lex_quoted(Token& out);
    [[nodiscard]] LexOutcome lex_literal_header(Token& out);
    [[nodiscard]] LexOutcome lex_text(bool stop_at_bracket, Token& out);
    [[nodiscard]] LexOutcome next_literal(Token& out);

    // Nothing more to examine: wait for input, or report how the input ended.
    [[nodiscard]] LexOutcome starved();
    [[nodiscard]] LexOutcome fail(SyntaxErrorKind kind, std::uint64_t at) noexcept;

    // Resets `out` to a new token of `kind` starting at the current position.
    void begin(Token& out, TokenKind kind);
    void consume(std::size_t count) noexcept;
    void suspend(std::size_t examined) noexcept;
    void complete() noexcept;

    [[nodiscard]] unsigned char at(std::size_t index) const noexcept {
        return static_cast<unsigned char>(buffer_[index]);
    }
    [[nodiscard]] std::uint64_t offset_of(std::size_t index) const noexcept {
        return base_offset_ + index;
    }

    LexerLimits limits_;

    std::vector<std::byte> buffer_;
    std::size_t pos_ = 0;             // first unconsumed byte in buffer_
    std::uint64_t base_offset_ = 0;   // stream offset of buffer_[0]
    bool finished_ = false;

    bool line_start_ = true;
    std::uint32_t pending_spaces_ = 0;
    std::uint32_t depth_ = 0;

    // A token that is still arriving: how far into it has been examined, and
    // for which mode. Resuming from here is what keeps one-byte reads linear
    // rather than rescanning the whole token on every byte.
    bool scanning_ = false;
    LexMode scan_mode_ = LexMode::normal;
    std::size_t scan_ = 0;
    bool quoted_escape_ = false;

    bool literal_active_ = false;
    std::uint64_t literal_remaining_ = 0;

    bool failed_ = false;
    SyntaxError error_{};
};

}  // namespace crimson::imap

#endif  // CRIMSON_PROTOCOLS_IMAP_LEXER_H
