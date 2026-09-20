// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef CRIMSON_PROTOCOLS_IMAP_PARSER_H
#define CRIMSON_PROTOCOLS_IMAP_PARSER_H

#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "protocols/imap/lexer.h"
#include "protocols/imap/response.h"
#include "protocols/imap/response_reader.h"
#include "protocols/imap/token.h"

namespace crimson::imap {

enum class ParseStatus : std::uint8_t {
    response,  // `out` holds the next response
    end,       // the server closed the connection between responses
};

[[nodiscard]] constexpr std::string_view to_string(ParseStatus status) noexcept {
    switch (status) {
        case ParseStatus::response: return "response";
        case ParseStatus::end:      return "end";
    }
    return "unknown";
}

// Turns tokens into typed responses.
//
// The parser drives the lexer's modes from the grammar, which is what they
// exist for (ADR 0012): a mailbox name is read as an astring, so an unquoted
// [Gmail]/Drafts stays one token, while the rest of a response is read as
// ordinary grammar. It therefore calls ResponseReader::read(mode, token)
// rather than ResponseReader::next(), whose mode guesses are only for
// tokenizing without a parser.
//
// It is deliberately forgiving about what it does not know. An unrecognised
// response, response code or FETCH item is kept as text rather than refused,
// because every server sends extensions and one of them must not end a
// session. It is unforgiving about structure: a malformed response is a
// SyntaxError, and the connection has to go.
class Parser {
public:
    struct Limits {
        // A literal larger than this is streamed to the sink instead of being
        // collected in memory. A 50 MB message body must never have to fit.
        std::size_t max_inline_literal = std::size_t{1} << 20;  // 1 MiB

        // Items in one list: search results, flags, addresses. A server that
        // sends more than this is not one Crimson can work with anyway.
        //
        // Counted in grammar items only. The pieces a literal arrives in are
        // never counted, because how many there are is decided by the network
        // rather than by the server, and a limit that depends on that accepts
        // a response read whole and refuses the same one read a byte at a
        // time. The fuzzer found that twice.
        std::size_t max_items = 100'000;
    };

    // Receives literal content too large to keep. Called with successive
    // chunks; `last` marks the final one. Chunks are only valid for the
    // duration of the call.
    using LiteralSink =
        std::function<void(std::string_view specifier, std::span<const std::byte> chunk, bool last)>;

    explicit Parser(ResponseReader& reader, Limits limits = {});

    // Where large literals go. Without a sink they are dropped, with only
    // their size recorded, which is what a caller that asked for metadata
    // wants.
    void stream_large_literals(LiteralSink sink);

    // Reads one whole response, up to and including its CRLF.
    [[nodiscard]] std::expected<ParseStatus, ReadError> next(Response& out);

private:
    // Reading. Each returns the error unchanged, so a transport failure stays
    // a NetError all the way up.
    [[nodiscard]] std::expected<ReadStatus, ReadError> read(LexMode mode);
    [[nodiscard]] std::expected<void, ReadError> expect(TokenKind kind);
    [[nodiscard]] std::expected<void, ReadError> expect_end_of_line();

    // Grammar pieces.
    [[nodiscard]] std::expected<std::string, ReadError> read_astring();
    [[nodiscard]] std::expected<std::optional<std::string>, ReadError> read_nstring();
    [[nodiscard]] std::expected<std::uint64_t, ReadError> read_number();
    [[nodiscard]] std::expected<Flags, ReadError> read_flag_list();

    // Responses.
    [[nodiscard]] std::expected<void, ReadError> parse_tagged(std::string tag, Response& out);
    [[nodiscard]] std::expected<void, ReadError> parse_untagged(Response& out);
    [[nodiscard]] std::expected<void, ReadError> parse_numbered(std::uint32_t number, Response& out);
    [[nodiscard]] std::expected<void, ReadError> parse_named(Response& out);
    [[nodiscard]] std::expected<StatusResponse, ReadError> parse_status(StatusKind kind);
    [[nodiscard]] std::expected<Capabilities, ReadError> parse_capabilities();
    [[nodiscard]] std::expected<MailboxListing, ReadError> parse_mailbox_listing();
    [[nodiscard]] std::expected<MailboxStatus, ReadError> parse_mailbox_status();
    [[nodiscard]] std::expected<SearchResults, ReadError> parse_search_results();
    [[nodiscard]] std::expected<FetchResponse, ReadError> parse_fetch(std::uint32_t sequence);
    [[nodiscard]] std::expected<Envelope, ReadError> parse_envelope();
    [[nodiscard]] std::expected<std::vector<Address>, ReadError> parse_address_list();
    [[nodiscard]] std::expected<void, ReadError> parse_body_section(FetchResponse& fetch,
                                                                    bool binary);

    // Reads and discards one value of any shape: an atom, a parenthesised
    // list, or a literal. An item Crimson does not know still has to be
    // consumed, or the rest of the response is misread.
    [[nodiscard]] std::expected<void, ReadError> skip_value();
    // `line_ended` comes back true when a malformed code ran to the end of
    // the line, so the caller knows there is no text left to read.
    [[nodiscard]] std::expected<ResponseCode, ReadError> parse_response_code(bool& line_ended);
    [[nodiscard]] std::expected<void, ReadError> recover_code(ResponseCode& code, bool& line_ended);
    [[nodiscard]] std::expected<UnknownResponse, ReadError> parse_unknown(std::string name);

    [[nodiscard]] ReadError malformed() const;

    // Counts the token just read against max_items, except for literal
    // content, which the network divides as it pleases. True means the limit
    // is exceeded.
    [[nodiscard]] bool over_item_limit(std::size_t& count) const noexcept;

    ResponseReader& reader_;
    Limits limits_;
    LiteralSink sink_;
    Token token_;
};

}  // namespace crimson::imap

#endif  // CRIMSON_PROTOCOLS_IMAP_PARSER_H
