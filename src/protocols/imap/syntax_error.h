// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef CRIMSON_PROTOCOLS_IMAP_SYNTAX_ERROR_H
#define CRIMSON_PROTOCOLS_IMAP_SYNTAX_ERROR_H

#include <cstdint>
#include <string_view>
#include <type_traits>

namespace crimson::imap {

// What was wrong with the bytes a server sent.
//
// Every one of these means the same thing to the caller: the connection's
// framing can no longer be trusted, because the next byte might be the middle
// of a literal, a quoted string or a line that was misread. The only safe
// response is to drop the connection. There is deliberately no Retry
// classification here — reconnecting is always the answer, and whether to try
// again at all is the sync engine's decision, not the tokenizer's.
enum class SyntaxErrorKind : std::uint8_t {
    invalid_character,    // a control character or NUL where the grammar allows none
    bad_line_ending,      // CR without LF, or LF without CR
    unterminated_quoted,  // a line ended inside a quoted string
    bad_escape,           // a backslash in a quoted string before something other than " or backslash
    bad_literal,          // a malformed {n} literal header
    literal_too_large,    // a literal beyond LexerLimits::max_literal_bytes
    number_too_large,     // digits beyond what 63 bits hold (RFC 9051 number64)
    token_too_long,       // a token, or run of spaces, beyond LexerLimits::max_token_bytes
    nesting_too_deep,     // ( or [ nested beyond LexerLimits::max_depth
    unexpected_end,       // the input ended inside a token, a literal or a line
    unexpected_token,     // a response that does not begin with a tag, * or +
};

struct SyntaxError {
    SyntaxErrorKind kind = SyntaxErrorKind::invalid_character;
    std::uint64_t offset = 0;  // stream offset of the offending byte
};

static_assert(std::is_trivially_copyable_v<SyntaxError>);

[[nodiscard]] constexpr std::string_view to_string(SyntaxErrorKind kind) noexcept {
    switch (kind) {
        case SyntaxErrorKind::invalid_character:   return "invalid_character";
        case SyntaxErrorKind::bad_line_ending:     return "bad_line_ending";
        case SyntaxErrorKind::unterminated_quoted: return "unterminated_quoted";
        case SyntaxErrorKind::bad_escape:          return "bad_escape";
        case SyntaxErrorKind::bad_literal:         return "bad_literal";
        case SyntaxErrorKind::literal_too_large:   return "literal_too_large";
        case SyntaxErrorKind::number_too_large:    return "number_too_large";
        case SyntaxErrorKind::token_too_long:      return "token_too_long";
        case SyntaxErrorKind::nesting_too_deep:    return "nesting_too_deep";
        case SyntaxErrorKind::unexpected_end:      return "unexpected_end";
        case SyntaxErrorKind::unexpected_token:    return "unexpected_token";
    }
    return "unknown";
}

// A sentence for diagnostics. Plain wording: this can end up in a log a user
// attaches to a bug report.
[[nodiscard]] constexpr std::string_view describe(SyntaxErrorKind kind) noexcept {
    switch (kind) {
        case SyntaxErrorKind::invalid_character:
            return "the server sent a control character where none is allowed";
        case SyntaxErrorKind::bad_line_ending:
            return "the server ended a line without CRLF";
        case SyntaxErrorKind::unterminated_quoted:
            return "a quoted string was not closed before the end of the line";
        case SyntaxErrorKind::bad_escape:
            return "a quoted string contained an invalid backslash escape";
        case SyntaxErrorKind::bad_literal:
            return "a literal's {size} header was malformed";
        case SyntaxErrorKind::literal_too_large:
            return "the server announced a literal larger than Crimson accepts";
        case SyntaxErrorKind::number_too_large:
            return "a number was too large to represent";
        case SyntaxErrorKind::token_too_long:
            return "a single item in the response exceeded the size limit";
        case SyntaxErrorKind::nesting_too_deep:
            return "parentheses or brackets were nested too deeply";
        case SyntaxErrorKind::unexpected_end:
            return "the connection ended part-way through a response";
        case SyntaxErrorKind::unexpected_token:
            return "a response did not start with a tag, * or +";
    }
    return "unknown syntax error";
}

}  // namespace crimson::imap

#endif  // CRIMSON_PROTOCOLS_IMAP_SYNTAX_ERROR_H
