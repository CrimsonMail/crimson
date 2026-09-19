// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#include "protocols/imap/response_reader.h"

#include <array>
#include <string_view>

namespace crimson::imap {

namespace {

// Large enough that a busy FETCH is a handful of reads, small enough to be one
// TLS record's worth of plaintext.
constexpr std::size_t kReadChunk = 16 * 1024;

[[nodiscard]] bool is_status(const Token& token) noexcept {
    return token.is_atom("OK") || token.is_atom("NO") || token.is_atom("BAD") ||
           token.is_atom("PREAUTH") || token.is_atom("BYE");
}

// Response codes whose arguments have grammar: flags, capabilities, numbers,
// UID sets, charsets. Every other code's arguments are read as text, because
// RFC 9051 lets an unknown code carry any text up to the closing bracket —
// quotes and braces included.
[[nodiscard]] bool is_structured_code(const Token& name) noexcept {
    constexpr std::array<std::string_view, 10> kCodes{
        "CAPABILITY", "PERMANENTFLAGS", "BADCHARSET", "UIDVALIDITY", "UIDNEXT",
        "UNSEEN",     "HIGHESTMODSEQ",  "APPENDUID",  "COPYUID",     "MODIFIED",
    };
    for (const std::string_view code : kCodes) {
        if (name.is_atom(code)) {
            return true;
        }
    }
    return false;
}

}  // namespace

ResponseReader::ResponseReader(net::ByteStream& stream, LexerLimits limits)
    : stream_(stream), lexer_(limits), chunk_(kReadChunk) {}

TokenOutcome ResponseReader::read(LexMode mode, Token& out) {
    for (;;) {
        const LexOutcome lexed = lexer_.next(mode, out);
        if (!lexed) {
            return std::unexpected(ReadError{lexed.error()});
        }
        if (*lexed == LexStatus::token) {
            return ReadStatus::token;
        }
        if (*lexed == LexStatus::end_of_input) {
            return ReadStatus::end;
        }

        const net::ReadOutcome received = stream_.read(chunk_);
        if (!received) {
            return std::unexpected(ReadError{received.error()});
        }
        if (received->bytes == 0 && !received->eof) {
            // ByteStream forbids this; looping on it would spin forever.
            return std::unexpected(ReadError{net::NetError::logic(net::NetOp::recv)});
        }
        lexer_.feed(std::span{chunk_.data(), received->bytes});
        if (received->eof) {
            lexer_.finish();
        }
    }
}

TokenOutcome ResponseReader::next(Token& out) {
    const TokenOutcome got = read(mode_for(state_), out);
    if (!got || *got == ReadStatus::end) {
        return got;
    }
    return advance(out);
}

LexMode ResponseReader::mode_for(State state) noexcept {
    switch (state) {
        case State::resp_text:  return LexMode::resp_text;
        case State::code_name:  return LexMode::code_name;
        case State::code_text:  return LexMode::code_text;
        case State::code_close: return LexMode::code_text;
        case State::text_rest:  return LexMode::text;
        case State::start:
        case State::second:
        case State::code_args:
        case State::data:
            return LexMode::normal;
    }
    return LexMode::normal;
}

TokenOutcome ResponseReader::advance(const Token& token) {
    // Literal content is opaque and changes nothing about where the response
    // is: the line simply continues after literal_end.
    if (token.is(TokenKind::literal_begin) || token.is(TokenKind::literal_data) ||
        token.is(TokenKind::literal_end)) {
        if (state_ == State::start) {
            // A response cannot begin with a literal: there is no tag.
            return std::unexpected(
                ReadError{SyntaxError{SyntaxErrorKind::unexpected_token, token.offset}});
        }
        return ReadStatus::token;
    }

    if (token.is(TokenKind::eol)) {
        if (state_ == State::start) {
            // An empty line where a response should begin.
            return std::unexpected(
                ReadError{SyntaxError{SyntaxErrorKind::unexpected_token, token.offset}});
        }
        state_ = State::start;
        return ReadStatus::token;
    }

    switch (state_) {
        case State::start:
            if (token.is_atom("*")) {
                kind_ = ResponseKind::untagged;
                state_ = State::second;
            } else if (token.is_atom("+")) {
                kind_ = ResponseKind::continuation;
                state_ = State::text_rest;
            } else if (token.is(TokenKind::atom) || token.is(TokenKind::number)) {
                kind_ = ResponseKind::tagged;
                state_ = State::second;
            } else {
                return std::unexpected(
                    ReadError{SyntaxError{SyntaxErrorKind::unexpected_token, token.offset}});
            }
            break;

        case State::second:
            state_ = is_status(token) ? State::resp_text : State::data;
            break;

        case State::resp_text:
            state_ = token.is(TokenKind::lbracket) ? State::code_name : State::text_rest;
            break;

        case State::code_name:
            if (token.is(TokenKind::rbracket)) {
                state_ = State::text_rest;
            } else if (token.is(TokenKind::atom) && is_structured_code(token)) {
                state_ = State::code_args;
                code_depth_ = 1;
            } else if (token.is(TokenKind::atom)) {
                state_ = State::code_text;
            } else {
                state_ = State::code_close;
            }
            break;

        case State::code_args:
            if (token.is(TokenKind::lbracket)) {
                ++code_depth_;
            } else if (token.is(TokenKind::rbracket) && --code_depth_ == 0) {
                state_ = State::text_rest;
            }
            break;

        case State::code_text:
        case State::code_close:
            state_ = token.is(TokenKind::rbracket) ? State::text_rest : State::code_close;
            break;

        case State::text_rest:
        case State::data:
            break;
    }
    return ReadStatus::token;
}

}  // namespace crimson::imap
