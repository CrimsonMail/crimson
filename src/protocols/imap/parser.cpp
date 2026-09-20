// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#include "protocols/imap/parser.h"

#include <array>
#include <utility>

namespace crimson::imap {

namespace {

// Status keywords, in the order of StatusKind.
constexpr std::array<std::string_view, 5> kStatusKeywords{"OK", "NO", "BAD", "PREAUTH", "BYE"};

[[nodiscard]] std::optional<StatusKind> status_keyword(const Token& token) noexcept {
    for (std::size_t index = 0; index < kStatusKeywords.size(); ++index) {
        if (token.is_atom(kStatusKeywords[index])) {
            return static_cast<StatusKind>(index);
        }
    }
    return std::nullopt;
}

// Response codes with no arguments at all.
[[nodiscard]] std::optional<ResponseCodeKind> bare_code(const Token& name) noexcept {
    if (name.is_atom("ALERT")) {
        return ResponseCodeKind::alert;
    }
    if (name.is_atom("PARSE")) {
        return ResponseCodeKind::parse;
    }
    if (name.is_atom("READ-ONLY")) {
        return ResponseCodeKind::read_only;
    }
    if (name.is_atom("READ-WRITE")) {
        return ResponseCodeKind::read_write;
    }
    if (name.is_atom("TRYCREATE")) {
        return ResponseCodeKind::try_create;
    }
    if (name.is_atom("CLOSED")) {
        return ResponseCodeKind::closed;
    }
    if (name.is_atom("NOMODSEQ")) {
        return ResponseCodeKind::no_mod_sequence;
    }
    return std::nullopt;
}

// Response codes whose single argument is a number.
[[nodiscard]] std::optional<ResponseCodeKind> numeric_code(const Token& name) noexcept {
    if (name.is_atom("UIDNEXT")) {
        return ResponseCodeKind::uid_next;
    }
    if (name.is_atom("UIDVALIDITY")) {
        return ResponseCodeKind::uid_validity;
    }
    if (name.is_atom("UNSEEN")) {
        return ResponseCodeKind::unseen;
    }
    if (name.is_atom("HIGHESTMODSEQ")) {
        return ResponseCodeKind::highest_mod_sequence;
    }
    return std::nullopt;
}

void add_flag(Flags& flags, std::string_view name) {
    if (equals_ignore_case(name, "\\Seen")) {
        flags.seen = true;
    } else if (equals_ignore_case(name, "\\Answered")) {
        flags.answered = true;
    } else if (equals_ignore_case(name, "\\Flagged")) {
        flags.flagged = true;
    } else if (equals_ignore_case(name, "\\Deleted")) {
        flags.deleted = true;
    } else if (equals_ignore_case(name, "\\Draft")) {
        flags.draft = true;
    } else if (equals_ignore_case(name, "\\Recent")) {
        flags.recent = true;
    } else if (name == "\\*") {
        flags.accepts_new_keywords = true;
    } else {
        flags.keywords.emplace_back(name);
    }
}

}  // namespace

Parser::Parser(ResponseReader& reader, Limits limits) : reader_(reader), limits_(limits) {}

void Parser::stream_large_literals(LiteralSink sink) { sink_ = std::move(sink); }

ReadError Parser::malformed() const {
    return ReadError{SyntaxError{SyntaxErrorKind::unexpected_token, token_.offset}};
}

std::expected<ReadStatus, ReadError> Parser::read(LexMode mode) { return reader_.read(mode, token_); }

std::expected<void, ReadError> Parser::expect(TokenKind kind) {
    const auto got = read(LexMode::normal);
    if (!got) {
        return std::unexpected(got.error());
    }
    if (*got == ReadStatus::end || !token_.is(kind)) {
        return std::unexpected(malformed());
    }
    return {};
}

std::expected<void, ReadError> Parser::expect_end_of_line() { return expect(TokenKind::eol); }

std::expected<std::uint64_t, ReadError> Parser::read_number() {
    if (auto got = expect(TokenKind::number); !got) {
        return std::unexpected(got.error());
    }
    return token_.number;
}

std::expected<std::string, ReadError> Parser::read_astring() {
    const auto got = read(LexMode::astring);
    if (!got) {
        return std::unexpected(got.error());
    }
    if (*got == ReadStatus::end) {
        return std::unexpected(malformed());
    }
    if (token_.is(TokenKind::atom) || token_.is(TokenKind::quoted)) {
        return std::string{token_.value()};
    }
    if (!token_.is(TokenKind::literal_begin)) {
        return std::unexpected(malformed());
    }

    // A literal where a name belongs. Mailbox names are short; a server
    // announcing megabytes here is not one to keep talking to.
    if (token_.number > limits_.max_inline_literal) {
        return std::unexpected(malformed());
    }
    std::string value;
    value.reserve(static_cast<std::size_t>(token_.number));
    for (;;) {
        const auto piece = read(LexMode::normal);
        if (!piece) {
            return std::unexpected(piece.error());
        }
        if (*piece == ReadStatus::end) {
            return std::unexpected(malformed());
        }
        if (token_.is(TokenKind::literal_end)) {
            return value;
        }
        if (!token_.is(TokenKind::literal_data)) {
            return std::unexpected(malformed());
        }
        value.append(reinterpret_cast<const char*>(token_.data.data()), token_.data.size());
    }
}

std::expected<std::optional<std::string>, ReadError> Parser::read_nstring() {
    // NIL is only NIL unquoted. A mailbox really called "NIL" arrives quoted,
    // and then it is a string like any other.
    const auto got = read(LexMode::astring);
    if (!got) {
        return std::unexpected(got.error());
    }
    if (*got == ReadStatus::end) {
        return std::unexpected(malformed());
    }
    if (token_.is(TokenKind::atom) && equals_ignore_case(token_.raw, "NIL")) {
        return std::optional<std::string>{};
    }
    if (token_.is(TokenKind::atom) || token_.is(TokenKind::quoted)) {
        return std::optional<std::string>{std::string{token_.value()}};
    }
    if (!token_.is(TokenKind::literal_begin)) {
        return std::unexpected(malformed());
    }
    if (token_.number > limits_.max_inline_literal) {
        return std::unexpected(malformed());
    }
    std::string value;
    value.reserve(static_cast<std::size_t>(token_.number));
    for (;;) {
        const auto piece = read(LexMode::normal);
        if (!piece) {
            return std::unexpected(piece.error());
        }
        if (*piece == ReadStatus::end) {
            return std::unexpected(malformed());
        }
        if (token_.is(TokenKind::literal_end)) {
            return std::optional<std::string>{std::move(value)};
        }
        if (!token_.is(TokenKind::literal_data)) {
            return std::unexpected(malformed());
        }
        value.append(reinterpret_cast<const char*>(token_.data.data()), token_.data.size());
    }
}

std::expected<Flags, ReadError> Parser::read_flag_list() {
    if (auto open = expect(TokenKind::lparen); !open) {
        return std::unexpected(open.error());
    }
    Flags flags;
    for (std::size_t count = 0;; ++count) {
        if (count > limits_.max_items) {
            return std::unexpected(malformed());
        }
        const auto got = read(LexMode::normal);
        if (!got) {
            return std::unexpected(got.error());
        }
        if (*got == ReadStatus::end) {
            return std::unexpected(malformed());
        }
        if (token_.is(TokenKind::rparen)) {
            return flags;
        }
        if (!token_.is(TokenKind::atom)) {
            return std::unexpected(malformed());
        }
        add_flag(flags, token_.raw);
    }
}

std::expected<ParseStatus, ReadError> Parser::next(Response& out) {
    const auto got = read(LexMode::normal);
    if (!got) {
        return std::unexpected(got.error());
    }
    if (*got == ReadStatus::end) {
        return ParseStatus::end;
    }

    if (token_.is_atom("*")) {
        if (auto parsed = parse_untagged(out); !parsed) {
            return std::unexpected(parsed.error());
        }
        return ParseStatus::response;
    }

    if (token_.is_atom("+")) {
        // The rest of the line is whatever the server wants to say, including
        // base64 for a SASL challenge. Read as text, never as grammar.
        ContinuationRequest continuation;
        const auto text = read(LexMode::text);
        if (!text) {
            return std::unexpected(text.error());
        }
        if (*text == ReadStatus::end) {
            return std::unexpected(malformed());
        }
        if (token_.is(TokenKind::text)) {
            continuation.text = token_.raw;
            if (auto end = expect_end_of_line(); !end) {
                return std::unexpected(end.error());
            }
        } else if (!token_.is(TokenKind::eol)) {
            return std::unexpected(malformed());
        }
        out = std::move(continuation);
        return ParseStatus::response;
    }

    if (!token_.is(TokenKind::atom) && !token_.is(TokenKind::number)) {
        return std::unexpected(malformed());
    }
    std::string tag = token_.raw;
    if (auto parsed = parse_tagged(std::move(tag), out); !parsed) {
        return std::unexpected(parsed.error());
    }
    return ParseStatus::response;
}

std::expected<void, ReadError> Parser::parse_tagged(std::string tag, Response& out) {
    const auto got = read(LexMode::normal);
    if (!got) {
        return std::unexpected(got.error());
    }
    if (*got == ReadStatus::end) {
        return std::unexpected(malformed());
    }
    const std::optional<StatusKind> kind = status_keyword(token_);
    if (!kind) {
        return std::unexpected(malformed());
    }
    auto status = parse_status(*kind);
    if (!status) {
        return std::unexpected(status.error());
    }
    out = TaggedResponse{std::move(tag), std::move(*status)};
    return {};
}

std::expected<void, ReadError> Parser::parse_untagged(Response& out) {
    const auto got = read(LexMode::normal);
    if (!got) {
        return std::unexpected(got.error());
    }
    if (*got == ReadStatus::end) {
        return std::unexpected(malformed());
    }

    if (token_.is(TokenKind::number)) {
        const auto number = static_cast<std::uint32_t>(token_.number);
        const auto name = read(LexMode::normal);
        if (!name) {
            return std::unexpected(name.error());
        }
        if (*name == ReadStatus::end || !token_.is(TokenKind::atom)) {
            return std::unexpected(malformed());
        }
        if (token_.is_atom("EXISTS") || token_.is_atom("RECENT") || token_.is_atom("EXPUNGE")) {
            MailboxCount count;
            count.number = number;
            count.kind = token_.is_atom("EXISTS")   ? MailboxCount::Kind::exists
                         : token_.is_atom("RECENT") ? MailboxCount::Kind::recent
                                                    : MailboxCount::Kind::expunge;
            if (auto end = expect_end_of_line(); !end) {
                return std::unexpected(end.error());
            }
            out = UntaggedResponse{count};
            return {};
        }
        auto unknown = parse_unknown(std::to_string(number) + " " + token_.raw);
        if (!unknown) {
            return std::unexpected(unknown.error());
        }
        out = UntaggedResponse{std::move(*unknown)};
        return {};
    }

    if (!token_.is(TokenKind::atom)) {
        return std::unexpected(malformed());
    }

    if (const std::optional<StatusKind> kind = status_keyword(token_)) {
        auto status = parse_status(*kind);
        if (!status) {
            return std::unexpected(status.error());
        }
        out = UntaggedResponse{std::move(*status)};
        return {};
    }

    if (token_.is_atom("CAPABILITY")) {
        auto capabilities = parse_capabilities();
        if (!capabilities) {
            return std::unexpected(capabilities.error());
        }
        out = UntaggedResponse{std::move(*capabilities)};
        return {};
    }

    // LSUB has LIST's shape, and so does Gmail's older XLIST.
    if (token_.is_atom("LIST") || token_.is_atom("LSUB") || token_.is_atom("XLIST")) {
        auto listing = parse_mailbox_listing();
        if (!listing) {
            return std::unexpected(listing.error());
        }
        out = UntaggedResponse{std::move(*listing)};
        return {};
    }

    if (token_.is_atom("STATUS")) {
        auto status = parse_mailbox_status();
        if (!status) {
            return std::unexpected(status.error());
        }
        out = UntaggedResponse{std::move(*status)};
        return {};
    }

    if (token_.is_atom("SEARCH")) {
        auto results = parse_search_results();
        if (!results) {
            return std::unexpected(results.error());
        }
        out = UntaggedResponse{std::move(*results)};
        return {};
    }

    if (token_.is_atom("FLAGS")) {
        auto flags = read_flag_list();
        if (!flags) {
            return std::unexpected(flags.error());
        }
        if (auto end = expect_end_of_line(); !end) {
            return std::unexpected(end.error());
        }
        out = UntaggedResponse{MailboxFlags{std::move(*flags)}};
        return {};
    }

    auto unknown = parse_unknown(token_.raw);
    if (!unknown) {
        return std::unexpected(unknown.error());
    }
    out = UntaggedResponse{std::move(*unknown)};
    return {};
}

std::expected<StatusResponse, ReadError> Parser::parse_status(StatusKind kind) {
    StatusResponse status;
    status.kind = kind;

    // resp_text mode: a leading [ opens a response code, and anything else is
    // free text. This is the mode that stops a "{5}" in a server's message
    // from being read as a literal.
    const auto got = read(LexMode::resp_text);
    if (!got) {
        return std::unexpected(got.error());
    }
    if (*got == ReadStatus::end) {
        return std::unexpected(malformed());
    }

    if (token_.is(TokenKind::eol)) {
        // iCloud and Fastmail both send a bare "* BYE". RFC 9051 requires
        // text; they do not send it, and refusing the line would be worse.
        return status;
    }

    if (token_.is(TokenKind::lbracket)) {
        auto code = parse_response_code();
        if (!code) {
            return std::unexpected(code.error());
        }
        status.code = std::move(*code);

        const auto text = read(LexMode::text);
        if (!text) {
            return std::unexpected(text.error());
        }
        if (*text == ReadStatus::end) {
            return std::unexpected(malformed());
        }
        if (token_.is(TokenKind::eol)) {
            return status;
        }
        if (!token_.is(TokenKind::text)) {
            return std::unexpected(malformed());
        }
        status.text = token_.raw;
        if (auto end = expect_end_of_line(); !end) {
            return std::unexpected(end.error());
        }
        return status;
    }

    if (!token_.is(TokenKind::text)) {
        return std::unexpected(malformed());
    }
    status.text = token_.raw;
    if (auto end = expect_end_of_line(); !end) {
        return std::unexpected(end.error());
    }
    return status;
}

std::expected<ResponseCode, ReadError> Parser::parse_response_code() {
    ResponseCode code;

    // code_name mode: the name as an atom if it looks like one, and text
    // otherwise, so a malformed code cannot be read as grammar.
    const auto got = read(LexMode::code_name);
    if (!got) {
        return std::unexpected(got.error());
    }
    if (*got == ReadStatus::end) {
        return std::unexpected(malformed());
    }
    if (token_.is(TokenKind::rbracket)) {
        return code;  // "[]", which no server should send and none is refused for
    }
    if (!token_.is(TokenKind::atom)) {
        // Not even a name: keep the lot as text.
        code.kind = ResponseCodeKind::other;
        for (std::size_t count = 0;; ++count) {
            if (count > limits_.max_items) {
                return std::unexpected(malformed());
            }
            if (token_.is(TokenKind::rbracket)) {
                return code;
            }
            if (token_.is(TokenKind::text)) {
                code.arguments.emplace_back(token_.raw);
            }
            const auto more = read(LexMode::code_text);
            if (!more) {
                return std::unexpected(more.error());
            }
            if (*more == ReadStatus::end || token_.is(TokenKind::eol)) {
                return std::unexpected(malformed());
            }
        }
    }

    code.name = token_.raw;

    if (const std::optional<ResponseCodeKind> bare = bare_code(token_)) {
        code.kind = *bare;
        if (auto close = expect(TokenKind::rbracket); !close) {
            return std::unexpected(close.error());
        }
        return code;
    }

    if (const std::optional<ResponseCodeKind> numeric = numeric_code(token_)) {
        code.kind = *numeric;
        auto number = read_number();
        if (!number) {
            return std::unexpected(number.error());
        }
        code.number = *number;
        if (auto close = expect(TokenKind::rbracket); !close) {
            return std::unexpected(close.error());
        }
        return code;
    }

    if (token_.is_atom("CAPABILITY")) {
        code.kind = ResponseCodeKind::capability;
        Capabilities capabilities;
        for (std::size_t count = 0;; ++count) {
            if (count > limits_.max_items) {
                return std::unexpected(malformed());
            }
            const auto item = read(LexMode::normal);
            if (!item) {
                return std::unexpected(item.error());
            }
            if (*item == ReadStatus::end) {
                return std::unexpected(malformed());
            }
            if (token_.is(TokenKind::rbracket)) {
                code.capabilities = std::move(capabilities);
                return code;
            }
            if (!token_.is(TokenKind::atom)) {
                return std::unexpected(malformed());
            }
            capabilities.names.emplace_back(token_.raw);
        }
    }

    if (token_.is_atom("PERMANENTFLAGS")) {
        code.kind = ResponseCodeKind::permanent_flags;
        auto flags = read_flag_list();
        if (!flags) {
            return std::unexpected(flags.error());
        }
        code.flags = std::move(*flags);
        if (auto close = expect(TokenKind::rbracket); !close) {
            return std::unexpected(close.error());
        }
        return code;
    }

    // Codes whose arguments have a grammar: charsets, UID sets, sequence
    // sets. Everything else is an extension, and RFC 9051 lets an unknown
    // code carry any text at all up to its closing bracket — quotes and
    // braces included. Reading that as grammar is how a tokenizer walks into
    // a "{5}" and loses the stream.
    const bool structured = token_.is_atom("BADCHARSET") || token_.is_atom("APPENDUID") ||
                            token_.is_atom("COPYUID") || token_.is_atom("MODIFIED");
    code.kind = token_.is_atom("BADCHARSET")  ? ResponseCodeKind::badcharset
                : token_.is_atom("APPENDUID") ? ResponseCodeKind::append_uid
                : token_.is_atom("COPYUID")   ? ResponseCodeKind::copy_uid
                                              : ResponseCodeKind::other;

    if (!structured) {
        for (std::size_t count = 0;; ++count) {
            if (count > limits_.max_items) {
                return std::unexpected(malformed());
            }
            const auto item = read(LexMode::code_text);
            if (!item) {
                return std::unexpected(item.error());
            }
            if (*item == ReadStatus::end || token_.is(TokenKind::eol)) {
                return std::unexpected(malformed());
            }
            if (token_.is(TokenKind::rbracket)) {
                return code;
            }
            if (token_.is(TokenKind::text)) {
                code.arguments.emplace_back(token_.raw);
            }
        }
    }

    for (std::size_t count = 0;; ++count) {
        if (count > limits_.max_items) {
            return std::unexpected(malformed());
        }
        const auto item = read(LexMode::normal);
        if (!item) {
            return std::unexpected(item.error());
        }
        if (*item == ReadStatus::end) {
            return std::unexpected(malformed());
        }
        if (token_.is(TokenKind::rbracket)) {
            return code;
        }
        if (token_.is(TokenKind::eol)) {
            return std::unexpected(malformed());
        }
        if (token_.is(TokenKind::atom) || token_.is(TokenKind::number) ||
            token_.is(TokenKind::quoted) || token_.is(TokenKind::nil)) {
            code.arguments.emplace_back(token_.value());
        }
    }
}

std::expected<Capabilities, ReadError> Parser::parse_capabilities() {
    Capabilities capabilities;
    for (std::size_t count = 0;; ++count) {
        if (count > limits_.max_items) {
            return std::unexpected(malformed());
        }
        const auto got = read(LexMode::normal);
        if (!got) {
            return std::unexpected(got.error());
        }
        if (*got == ReadStatus::end) {
            return std::unexpected(malformed());
        }
        if (token_.is(TokenKind::eol)) {
            return capabilities;
        }
        if (!token_.is(TokenKind::atom)) {
            return std::unexpected(malformed());
        }
        capabilities.names.emplace_back(token_.raw);
    }
}

std::expected<MailboxListing, ReadError> Parser::parse_mailbox_listing() {
    MailboxListing listing;

    if (auto open = expect(TokenKind::lparen); !open) {
        return std::unexpected(open.error());
    }
    for (std::size_t count = 0;; ++count) {
        if (count > limits_.max_items) {
            return std::unexpected(malformed());
        }
        const auto attribute = read(LexMode::normal);
        if (!attribute) {
            return std::unexpected(attribute.error());
        }
        if (*attribute == ReadStatus::end) {
            return std::unexpected(malformed());
        }
        if (token_.is(TokenKind::rparen)) {
            break;
        }
        if (!token_.is(TokenKind::atom)) {
            return std::unexpected(malformed());
        }
        listing.attributes.emplace_back(token_.raw);
    }

    // The hierarchy delimiter: one character, or NIL for a flat namespace.
    const auto delimiter = read(LexMode::normal);
    if (!delimiter) {
        return std::unexpected(delimiter.error());
    }
    if (*delimiter == ReadStatus::end) {
        return std::unexpected(malformed());
    }
    if (token_.is(TokenKind::quoted)) {
        const std::string_view value = token_.value();
        if (value.size() != 1) {
            return std::unexpected(malformed());
        }
        listing.delimiter = value.front();
    } else if (!token_.is(TokenKind::nil)) {
        return std::unexpected(malformed());
    }

    // The name is an astring: Gmail's "[Gmail]/All Mail" arrives quoted, but
    // the grammar allows it unquoted, and then the brackets belong to it.
    auto name = read_astring();
    if (!name) {
        return std::unexpected(name.error());
    }
    listing.name = std::move(*name);

    if (auto end = expect_end_of_line(); !end) {
        return std::unexpected(end.error());
    }
    return listing;
}

std::expected<MailboxStatus, ReadError> Parser::parse_mailbox_status() {
    MailboxStatus status;
    auto name = read_astring();
    if (!name) {
        return std::unexpected(name.error());
    }
    status.mailbox = std::move(*name);

    if (auto open = expect(TokenKind::lparen); !open) {
        return std::unexpected(open.error());
    }
    for (std::size_t count = 0;; ++count) {
        if (count > limits_.max_items) {
            return std::unexpected(malformed());
        }
        const auto item = read(LexMode::normal);
        if (!item) {
            return std::unexpected(item.error());
        }
        if (*item == ReadStatus::end) {
            return std::unexpected(malformed());
        }
        if (token_.is(TokenKind::rparen)) {
            break;
        }
        if (!token_.is(TokenKind::atom)) {
            return std::unexpected(malformed());
        }
        const Token name_token = token_;
        auto value = read_number();
        if (!value) {
            return std::unexpected(value.error());
        }
        const auto small = static_cast<std::uint32_t>(*value);
        if (name_token.is_atom("MESSAGES")) {
            status.messages = small;
        } else if (name_token.is_atom("RECENT")) {
            status.recent = small;
        } else if (name_token.is_atom("UIDNEXT")) {
            status.uid_next = small;
        } else if (name_token.is_atom("UIDVALIDITY")) {
            status.uid_validity = small;
        } else if (name_token.is_atom("UNSEEN")) {
            status.unseen = small;
        } else if (name_token.is_atom("HIGHESTMODSEQ")) {
            status.highest_mod_sequence = *value;
        } else if (name_token.is_atom("SIZE")) {
            status.size = *value;
        }
        // An item Crimson does not know is read and dropped: its value still
        // has to be consumed, or the rest of the line is misread.
    }

    if (auto end = expect_end_of_line(); !end) {
        return std::unexpected(end.error());
    }
    return status;
}

std::expected<SearchResults, ReadError> Parser::parse_search_results() {
    SearchResults results;
    for (std::size_t count = 0;; ++count) {
        if (count > limits_.max_items) {
            return std::unexpected(malformed());
        }
        const auto item = read(LexMode::normal);
        if (!item) {
            return std::unexpected(item.error());
        }
        if (*item == ReadStatus::end) {
            return std::unexpected(malformed());
        }
        if (token_.is(TokenKind::eol)) {
            return results;
        }
        if (token_.is(TokenKind::number)) {
            results.numbers.push_back(static_cast<std::uint32_t>(token_.number));
            continue;
        }
        // CONDSTORE ends the list with (MODSEQ 917162500).
        if (token_.is(TokenKind::lparen)) {
            if (auto name = expect(TokenKind::atom); !name) {
                return std::unexpected(name.error());
            }
            if (!token_.is_atom("MODSEQ")) {
                return std::unexpected(malformed());
            }
            auto value = read_number();
            if (!value) {
                return std::unexpected(value.error());
            }
            results.mod_sequence = *value;
            if (auto close = expect(TokenKind::rparen); !close) {
                return std::unexpected(close.error());
            }
            if (auto end = expect_end_of_line(); !end) {
                return std::unexpected(end.error());
            }
            return results;
        }
        return std::unexpected(malformed());
    }
}

std::expected<UnknownResponse, ReadError> Parser::parse_unknown(std::string name) {
    UnknownResponse unknown;
    unknown.name = std::move(name);

    // Read to the end of the line as grammar, not as text. An unknown
    // response may still contain a literal, and a literal's content has to be
    // consumed as content — otherwise its bytes would be read as the next
    // response and every response after it would be wrong.
    for (std::size_t count = 0;; ++count) {
        if (count > limits_.max_items) {
            return std::unexpected(malformed());
        }
        const auto got = read(LexMode::normal);
        if (!got) {
            return std::unexpected(got.error());
        }
        if (*got == ReadStatus::end) {
            return std::unexpected(malformed());
        }
        if (token_.is(TokenKind::eol)) {
            return unknown;
        }
        if (token_.is(TokenKind::literal_data)) {
            unknown.text.append(token_.data.size(), '.');  // content, not shown
            continue;
        }
        if (token_.is(TokenKind::literal_end)) {
            continue;
        }
        if (!unknown.text.empty()) {
            unknown.text += ' ';
        }
        unknown.text += token_.raw;
    }
}

}  // namespace crimson::imap
