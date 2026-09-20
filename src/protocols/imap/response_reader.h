// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef CRIMSON_PROTOCOLS_IMAP_RESPONSE_READER_H
#define CRIMSON_PROTOCOLS_IMAP_RESPONSE_READER_H

#include <cstddef>
#include <cstdint>
#include <expected>
#include <string_view>
#include <variant>
#include <vector>

#include "core/net/byte_stream.h"
#include "core/net/net_error.h"
#include "protocols/imap/lexer.h"
#include "protocols/imap/syntax_error.h"
#include "protocols/imap/token.h"

namespace crimson::imap {

enum class ResponseKind : std::uint8_t {
    none,          // before the first response
    tagged,        // a1 OK ...    the end of a command
    untagged,      // * ...        data, or a status the server volunteers
    continuation,  // + ...        the server is ready for more of a command
};

enum class ReadStatus : std::uint8_t {
    token,  // `out` holds the next token
    end,    // the server closed the connection cleanly, between responses
};

// Either the transport failed, or the server sent something malformed. The
// two are kept apart because they are diagnosed differently — a reset is the
// network, a bad literal is the server — even though both end the connection.
using ReadError = std::variant<net::NetError, SyntaxError>;

using TokenOutcome = std::expected<ReadStatus, ReadError>;

[[nodiscard]] constexpr std::string_view to_string(ResponseKind kind) noexcept {
    switch (kind) {
        case ResponseKind::none:         return "none";
        case ResponseKind::tagged:       return "tagged";
        case ResponseKind::untagged:     return "untagged";
        case ResponseKind::continuation: return "continuation";
    }
    return "unknown";
}

[[nodiscard]] constexpr std::string_view to_string(ReadStatus status) noexcept {
    switch (status) {
        case ReadStatus::token: return "token";
        case ReadStatus::end:   return "end";
    }
    return "unknown";
}

// Tokens from an IMAP server, read from any ByteStream.
//
// Two levels:
//
//   read(mode, out)  one token in a mode the caller chooses. This is what the
//                    Step 4 parser will use: it knows the grammar, so it knows
//                    where an astring or free text is expected.
//
//   next(out)        one token with the mode chosen from the response's own
//                    shape. It knows exactly as much IMAP as correct
//                    tokenizing requires — a tag, * or + first, and free text
//                    after a status keyword or + — and nothing about what any
//                    response means.
//
// Because it holds a ByteStream&, the same code reads from TcpStream,
// TlsStream, or a scripted or fragmenting test stream.
//
// THREADING. As the stream it reads: one owning thread.
class ResponseReader {
public:
    explicit ResponseReader(net::ByteStream& stream, LexerLimits limits = {});

    [[nodiscard]] TokenOutcome read(LexMode mode, Token& out);
    [[nodiscard]] TokenOutcome next(Token& out);

    // The kind of the response next() is reading, or last finished.
    [[nodiscard]] ResponseKind kind() const noexcept { return kind_; }

    // True when the previous token from next() ended a response.
    [[nodiscard]] bool at_response_start() const noexcept { return state_ == State::start; }

    // Stream offset of the next byte not yet tokenized.
    [[nodiscard]] std::uint64_t offset() const noexcept { return lexer_.offset(); }

private:
    enum class State : std::uint8_t {
        start,       // expecting a tag, * or +
        second,      // after the tag or *: a status keyword, a number, or a data keyword
        resp_text,   // after a status keyword: an optional [code], then text
        code_name,   // after [
        code_args,   // a structured code's arguments, read in normal mode
        code_text,   // any other code's arguments, read as text
        code_close,  // after a code's text: its ]
        text_rest,   // the rest of the line is text
        data,        // a data response: normal mode to the end of the line
    };

    [[nodiscard]] static LexMode mode_for(State state) noexcept;
    [[nodiscard]] TokenOutcome advance(const Token& token);

    net::ByteStream& stream_;
    Lexer lexer_;
    std::vector<std::byte> chunk_;

    State state_ = State::start;
    ResponseKind kind_ = ResponseKind::none;
    std::uint32_t code_depth_ = 0;
};

[[nodiscard]] inline bool is_net_error(const ReadError& error) noexcept {
    return std::holds_alternative<net::NetError>(error);
}

}  // namespace crimson::imap

#endif  // CRIMSON_PROTOCOLS_IMAP_RESPONSE_READER_H
