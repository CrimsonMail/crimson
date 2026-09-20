// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#include "protocols/imap/lexer.h"

#include <algorithm>

namespace crimson::imap {

namespace {

// RFC 9051 number64: 63 bits, so a value always fits in a signed 64-bit
// integer on the way to the database.
constexpr std::uint64_t kMaxNumber = (std::uint64_t{1} << 63) - 1;

// Buffered bytes already consumed are reclaimed once they pass this size, or
// half the buffer, whichever comes first.
constexpr std::size_t kCompactThreshold = 64 * 1024;

// Atom characters. Deliberately more permissive than RFC 9051 ATOM-CHAR:
// list-wildcards (* %) and backslash are included so that flags such as \Seen
// and \*, the untagged marker * and the continuation marker + all arrive as
// atoms, and bytes above 0x7F are included because servers send UTF-8 in
// atoms whatever the grammar says. The exclusions are the ones that matter for
// framing: space, controls, parentheses, the literal opener and the quote.
[[nodiscard]] constexpr bool is_atom_char(unsigned char c, LexMode mode) noexcept {
    if (c <= 0x20 || c == 0x7F) {
        return false;
    }
    switch (c) {
        case '(':
        case ')':
        case '{':
        case '"':
            return false;
        case '[':
        case ']':
            return mode == LexMode::astring;
        default:
            return true;
    }
}

[[nodiscard]] constexpr bool is_control(unsigned char c) noexcept {
    return c < 0x20 || c == 0x7F;
}

[[nodiscard]] bool equals_nil(std::string_view raw) noexcept {
    return raw.size() == 3 && (raw[0] == 'N' || raw[0] == 'n') &&
           (raw[1] == 'I' || raw[1] == 'i') && (raw[2] == 'L' || raw[2] == 'l');
}

}  // namespace

void Lexer::feed(std::span<const std::byte> bytes) {
    if (bytes.empty()) {
        return;
    }
    // Reclaim consumed bytes. Literal views handed out earlier point into this
    // buffer, which is why feed() is documented to invalidate them.
    if (pos_ > 0 && (pos_ >= kCompactThreshold || pos_ * 2 >= buffer_.size())) {
        buffer_.erase(buffer_.begin(), buffer_.begin() + static_cast<std::ptrdiff_t>(pos_));
        base_offset_ += pos_;
        pos_ = 0;
    }
    buffer_.insert(buffer_.end(), bytes.begin(), bytes.end());
}

LexOutcome Lexer::next(LexMode mode, Token& out) {
    if (failed_) {
        return std::unexpected(error_);
    }
    if (literal_active_) {
        return next_literal(out);
    }

    // A token part-way through arriving was being read for a particular mode.
    // If the caller has changed its mind, examine it afresh.
    if (scanning_ && mode != scan_mode_) {
        complete();
    }

    if (!scanning_) {
        // Separating spaces are consumed as they arrive and only counted, so a
        // long run of them costs no buffer space. They are still bounded: a
        // run longer than a token is not a separator, it is an attack.
        while (pos_ < buffer_.size() && at(pos_) == ' ') {
            if (pending_spaces_ >= limits_.max_token_bytes) {
                return fail(SyntaxErrorKind::token_too_long, offset());
            }
            ++pending_spaces_;
            ++pos_;
            line_start_ = false;
        }
        if (pos_ == buffer_.size()) {
            return starved();
        }
        scan_mode_ = mode;
    }

    const unsigned char c = at(pos_);
    if (c == '\r' || c == '\n') {
        return lex_eol(out);
    }

    switch (mode) {
        case LexMode::normal:
        case LexMode::astring:
            return lex_general(mode, out);

        case LexMode::text:
            return lex_text(false, out);

        case LexMode::resp_text:
            if (c == '[') {
                return lex_open(TokenKind::lbracket, out);
            }
            return lex_text(false, out);

        case LexMode::code_name:
            if (c == ']') {
                return lex_close(TokenKind::rbracket, out);
            }
            if (is_atom_char(c, LexMode::normal)) {
                return lex_atom(LexMode::normal, false, out);
            }
            return lex_text(true, out);

        case LexMode::code_text:
            if (c == ']') {
                return lex_close(TokenKind::rbracket, out);
            }
            return lex_text(true, out);
    }
    return fail(SyntaxErrorKind::invalid_character, offset());
}

LexOutcome Lexer::lex_general(LexMode mode, Token& out) {
    const unsigned char c = at(pos_);
    switch (c) {
        case '(':
            return lex_open(TokenKind::lparen, out);
        case ')':
            return lex_close(TokenKind::rparen, out);
        case '[':
            if (mode == LexMode::normal) {
                return lex_open(TokenKind::lbracket, out);
            }
            break;
        case ']':
            if (mode == LexMode::normal) {
                return lex_close(TokenKind::rbracket, out);
            }
            break;
        case '"':
            return lex_quoted(out);
        case '{':
            return lex_literal_header(out);
        case '~':
            // ~{n} is a literal8; a ~ followed by anything else is an ordinary
            // atom character. Which one needs the next byte.
            if (pos_ + 1 >= buffer_.size() && !finished_) {
                return LexStatus::need_more;
            }
            if (pos_ + 1 < buffer_.size() && at(pos_ + 1) == '{') {
                return lex_literal_header(out);
            }
            break;
        default:
            break;
    }
    if (is_control(c)) {
        return fail(SyntaxErrorKind::invalid_character, offset());
    }
    // Where the grammar expects an astring, NIL and 2024 are strings: a
    // mailbox may be called either. Only normal mode gives them meaning.
    return lex_atom(mode, mode == LexMode::normal, out);
}

LexOutcome Lexer::lex_eol(Token& out) {
    if (at(pos_) == '\n') {
        return fail(SyntaxErrorKind::bad_line_ending, offset());
    }
    if (pos_ + 1 >= buffer_.size()) {
        if (!finished_) {
            return LexStatus::need_more;
        }
        return fail(SyntaxErrorKind::unexpected_end, offset_of(pos_ + 1));
    }
    if (at(pos_ + 1) != '\n') {
        return fail(SyntaxErrorKind::bad_line_ending, offset());
    }
    begin(out, TokenKind::eol);
    out.raw = "\r\n";
    consume(2);
    line_start_ = true;
    // Brackets left open at the end of a line belong to a malformed response;
    // they must not make every following line look deeper than it is.
    depth_ = 0;
    return LexStatus::token;
}

LexOutcome Lexer::lex_open(TokenKind kind, Token& out) {
    if (depth_ >= limits_.max_depth) {
        return fail(SyntaxErrorKind::nesting_too_deep, offset());
    }
    ++depth_;
    begin(out, kind);
    out.raw.assign(1, static_cast<char>(at(pos_)));
    consume(1);
    return LexStatus::token;
}

LexOutcome Lexer::lex_close(TokenKind kind, Token& out) {
    // A stray closer is left for the parser to judge. Refusing it here would
    // reject valid input the parser reads differently — ] is legal inside an
    // unquoted mailbox name — so the depth simply never goes negative.
    if (depth_ > 0) {
        --depth_;
    }
    begin(out, kind);
    out.raw.assign(1, static_cast<char>(at(pos_)));
    consume(1);
    return LexStatus::token;
}

LexOutcome Lexer::lex_atom(LexMode chars, bool classify, Token& out) {
    std::size_t end = pos_ + scan_;
    while (end < buffer_.size() && is_atom_char(at(end), chars)) {
        // Checked before each byte is accepted, so the decision is reached at
        // the same byte however the input was split.
        if (end - pos_ >= limits_.max_token_bytes) {
            return fail(SyntaxErrorKind::token_too_long, offset());
        }
        ++end;
    }
    if (end == buffer_.size() && !finished_) {
        suspend(end - pos_);
        return LexStatus::need_more;
    }

    const std::size_t length = end - pos_;
    begin(out, TokenKind::atom);
    out.raw.assign(reinterpret_cast<const char*>(buffer_.data() + pos_), length);

    if (classify) {
        if (equals_nil(out.raw)) {
            out.kind = TokenKind::nil;
        } else if (std::all_of(out.raw.begin(), out.raw.end(),
                               [](char digit) { return digit >= '0' && digit <= '9'; })) {
            std::uint64_t value = 0;
            for (std::size_t index = 0; index < length; ++index) {
                const auto digit = static_cast<std::uint64_t>(out.raw[index] - '0');
                if (value > (kMaxNumber - digit) / 10) {
                    return fail(SyntaxErrorKind::number_too_large, offset_of(pos_ + index));
                }
                value = value * 10 + digit;
            }
            out.kind = TokenKind::number;
            out.number = value;
        }
    }

    consume(length);
    complete();
    return LexStatus::token;
}

LexOutcome Lexer::lex_quoted(Token& out) {
    // pos_ is at the opening quote.
    std::size_t index = pos_ + (scan_ == 0 ? 1 : scan_);
    if (scan_ == 0) {
        quoted_escape_ = false;
    }

    while (index < buffer_.size()) {
        if (index - pos_ >= limits_.max_token_bytes) {
            return fail(SyntaxErrorKind::token_too_long, offset());
        }
        const unsigned char c = at(index);
        if (quoted_escape_) {
            // RFC 9051 allows only \" and \\. Anything else is not a looser
            // server, it is a different string than the one intended.
            if (c != '"' && c != '\\') {
                return fail(SyntaxErrorKind::bad_escape, offset_of(index));
            }
            quoted_escape_ = false;
        } else if (c == '\\') {
            quoted_escape_ = true;
        } else if (c == '"') {
            ++index;
            const std::size_t length = index - pos_;
            begin(out, TokenKind::quoted);
            out.raw.assign(reinterpret_cast<const char*>(buffer_.data() + pos_), length);
            out.unescaped.reserve(length - 2);
            // Skips the opening and closing quotes, and turns each backslash
            // escape into the character it protects.
            std::size_t at_raw = 1;
            while (at_raw + 1 < length) {
                if (out.raw[at_raw] == '\\') {
                    ++at_raw;  // the escaped character, always " or backslash
                }
                out.unescaped.push_back(out.raw[at_raw]);
                ++at_raw;
            }
            consume(length);
            complete();
            return LexStatus::token;
        } else if (c == '\r' || c == '\n') {
            return fail(SyntaxErrorKind::unterminated_quoted, offset_of(index));
        } else if (c == 0) {
            return fail(SyntaxErrorKind::invalid_character, offset_of(index));
        }
        ++index;
    }

    if (finished_) {
        return fail(SyntaxErrorKind::unexpected_end, offset_of(index));
    }
    suspend(index - pos_);
    return LexStatus::need_more;
}

LexOutcome Lexer::lex_literal_header(Token& out) {
    // A header is a tilde for a literal8, then a brace, the size in digits, an
    // optional plus, a closing brace and CRLF. That is a couple of dozen bytes
    // at most, so it is simply re-examined from the start as input arrives,
    // rather than carrying resume state like the longer tokens do.
    std::size_t index = pos_;
    const bool binary = at(index) == '~';
    if (binary) {
        ++index;
    }
    ++index;  // the {

    // Input ran out part-way through the header.
    const auto wait_at = [this](std::size_t position) -> LexOutcome {
        if (finished_) {
            return fail(SyntaxErrorKind::unexpected_end, offset_of(position));
        }
        suspend(1);
        return LexStatus::need_more;
    };

    std::uint64_t size = 0;
    std::size_t digits = 0;
    while (index < buffer_.size() && at(index) >= '0' && at(index) <= '9') {
        const auto digit = static_cast<std::uint64_t>(at(index) - '0');
        if (size > (kMaxNumber - digit) / 10) {
            return fail(SyntaxErrorKind::number_too_large, offset_of(index));
        }
        size = size * 10 + digit;
        ++digits;
        ++index;
    }
    if (index >= buffer_.size()) {
        return wait_at(index);
    }
    if (digits == 0) {
        return fail(SyntaxErrorKind::bad_literal, offset_of(index));
    }
    // RFC 9051 allows {n+} (a non-synchronizing literal) in its grammar; only
    // clients send it, but accepting it costs nothing and loses nothing.
    if (at(index) == '+') {
        ++index;
    }
    for (const char expected : {'}', '\r', '\n'}) {
        if (index >= buffer_.size()) {
            return wait_at(index);
        }
        if (at(index) != static_cast<unsigned char>(expected)) {
            return fail(SyntaxErrorKind::bad_literal, offset_of(index));
        }
        ++index;
    }

    if (size > limits_.max_literal_bytes) {
        return fail(SyntaxErrorKind::literal_too_large, offset());
    }

    begin(out, TokenKind::literal_begin);
    out.raw.assign(reinterpret_cast<const char*>(buffer_.data() + pos_), index - pos_);
    out.number = size;
    out.binary = binary;
    consume(index - pos_);
    complete();
    literal_active_ = true;
    literal_remaining_ = size;
    return LexStatus::token;
}

LexOutcome Lexer::lex_text(bool stop_at_bracket, Token& out) {
    std::size_t end = pos_ + scan_;
    while (end < buffer_.size()) {
        const unsigned char c = at(end);
        if (c == '\r' || c == '\n' || (stop_at_bracket && c == ']')) {
            break;
        }
        if (end - pos_ >= limits_.max_token_bytes) {
            return fail(SyntaxErrorKind::token_too_long, offset());
        }
        if (c == 0) {
            return fail(SyntaxErrorKind::invalid_character, offset_of(end));
        }
        ++end;
    }
    if (end == buffer_.size() && !finished_) {
        suspend(end - pos_);
        return LexStatus::need_more;
    }

    begin(out, TokenKind::text);
    out.raw.assign(reinterpret_cast<const char*>(buffer_.data() + pos_), end - pos_);
    consume(end - pos_);
    complete();
    return LexStatus::token;
}

LexOutcome Lexer::next_literal(Token& out) {
    if (literal_remaining_ == 0) {
        begin(out, TokenKind::literal_end);
        literal_active_ = false;
        return LexStatus::token;
    }
    if (pos_ == buffer_.size()) {
        if (!finished_) {
            return LexStatus::need_more;
        }
        return fail(SyntaxErrorKind::unexpected_end, offset());
    }
    const std::size_t available = buffer_.size() - pos_;
    const std::size_t chunk = literal_remaining_ < available
                                  ? static_cast<std::size_t>(literal_remaining_)
                                  : available;
    begin(out, TokenKind::literal_data);
    out.data = std::span<const std::byte>{buffer_.data() + pos_, chunk};
    consume(chunk);
    literal_remaining_ -= chunk;
    return LexStatus::token;
}

LexOutcome Lexer::starved() {
    if (!finished_) {
        return LexStatus::need_more;
    }
    if (line_start_ && pending_spaces_ == 0) {
        return LexStatus::end_of_input;
    }
    return fail(SyntaxErrorKind::unexpected_end, offset());
}

LexOutcome Lexer::fail(SyntaxErrorKind kind, std::uint64_t at_offset) noexcept {
    failed_ = true;
    error_ = SyntaxError{kind, at_offset};
    return std::unexpected(error_);
}

void Lexer::begin(Token& out, TokenKind kind) {
    out.kind = kind;
    out.spaces_before = pending_spaces_;
    pending_spaces_ = 0;
    out.offset = offset();
    out.raw.clear();
    out.unescaped.clear();
    out.number = 0;
    out.binary = false;
    out.data = {};
}

void Lexer::consume(std::size_t count) noexcept {
    pos_ += count;
    if (count > 0) {
        line_start_ = false;
    }
}

void Lexer::suspend(std::size_t examined) noexcept {
    scanning_ = true;
    scan_ = examined;
}

void Lexer::complete() noexcept {
    scanning_ = false;
    scan_ = 0;
    quoted_escape_ = false;
}

}  // namespace crimson::imap
