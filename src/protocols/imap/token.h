// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef CRIMSON_PROTOCOLS_IMAP_TOKEN_H
#define CRIMSON_PROTOCOLS_IMAP_TOKEN_H

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

namespace crimson::imap {

enum class TokenKind : std::uint8_t {
    atom,           // CAPABILITY, \Seen, $Forwarded, a tag, * or +
    number,         // digits only, within 63 bits
    quoted,         // "..." — value() is the unescaped content
    nil,            // NIL, in any case
    literal_begin,  // {n} or ~{n} and its CRLF; number is n, binary marks ~{n}
    literal_data,   // part of a literal's content, in data
    literal_end,    // the literal is complete; the line continues after it
    lparen,         // (
    rparen,         // )
    lbracket,       // [
    rbracket,       // ]
    text,           // human-readable text, in the text modes only
    eol,            // CRLF
};

// One token.
//
// Tokenizing is lossless. For every token, spaces_before spaces followed by
// raw — or data, for literal_data — reproduce exactly the bytes the server
// sent. That is a test invariant, a fuzzing invariant, and the reason a
// message's original bytes can always be recovered.
//
// A Token is meant to be reused: the lexer overwrites it in place, so its
// strings keep their capacity and a long session does not allocate per token.
struct Token {
    TokenKind kind = TokenKind::eol;

    // Spaces between the previous token and this one. IMAP's grammar is
    // space-sensitive in places — BODY[TEXT] is not BODY [TEXT] — so the
    // parser needs adjacency, not just order.
    std::uint32_t spaces_before = 0;

    // Stream offset of the token's first byte, after the spaces.
    std::uint64_t offset = 0;

    // The exact bytes. Empty for literal_data (see data) and literal_end.
    std::string raw;

    // Quoted strings only: the content with quotes and escapes removed.
    std::string unescaped;

    // number: its value. literal_begin: the literal's size in bytes.
    std::uint64_t number = 0;

    // literal_begin only: true for a literal8, ~{n}, whose content may hold
    // any byte including NUL (RFC 3516).
    bool binary = false;

    // literal_data only: a view into the lexer's buffer, valid until the next
    // call to Lexer::feed or Lexer::next. Copy it or write it out before then.
    std::span<const std::byte> data;

    // The token's meaning as text: the unescaped content of a quoted string,
    // the raw bytes of anything else.
    [[nodiscard]] std::string_view value() const noexcept {
        return kind == TokenKind::quoted ? std::string_view{unescaped} : std::string_view{raw};
    }

    [[nodiscard]] bool is(TokenKind wanted) const noexcept { return kind == wanted; }

    // True for an atom equal to `name`, ignoring ASCII case. IMAP keywords
    // are case-insensitive: "ok", "OK" and "Ok" are the same response.
    [[nodiscard]] bool is_atom(std::string_view name) const noexcept {
        if (kind != TokenKind::atom || raw.size() != name.size()) {
            return false;
        }
        for (std::size_t index = 0; index < name.size(); ++index) {
            char a = raw[index];
            char b = name[index];
            if (a >= 'a' && a <= 'z') {
                a = static_cast<char>(a - 'a' + 'A');
            }
            if (b >= 'a' && b <= 'z') {
                b = static_cast<char>(b - 'a' + 'A');
            }
            if (a != b) {
                return false;
            }
        }
        return true;
    }
};

[[nodiscard]] constexpr std::string_view to_string(TokenKind kind) noexcept {
    switch (kind) {
        case TokenKind::atom:          return "atom";
        case TokenKind::number:        return "number";
        case TokenKind::quoted:        return "quoted";
        case TokenKind::nil:           return "nil";
        case TokenKind::literal_begin: return "literal_begin";
        case TokenKind::literal_data:  return "literal_data";
        case TokenKind::literal_end:   return "literal_end";
        case TokenKind::lparen:        return "lparen";
        case TokenKind::rparen:        return "rparen";
        case TokenKind::lbracket:      return "lbracket";
        case TokenKind::rbracket:      return "rbracket";
        case TokenKind::text:          return "text";
        case TokenKind::eol:           return "eol";
    }
    return "unknown";
}

}  // namespace crimson::imap

#endif  // CRIMSON_PROTOCOLS_IMAP_TOKEN_H
