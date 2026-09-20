// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#include <cstddef>
#include <string>
#include <vector>

#include "harness.h"
#include "imap/imap_test_support.h"
#include "net/scripted_stream.h"
#include "protocols/imap/response_reader.h"

// ResponseReader::next chooses the lexer's mode from each response's shape.
// These tests are about that choice: free text after a status keyword must
// never be tokenized as grammar, and everything else must be.

using crimson::imap::ReadStatus;
using crimson::imap::ResponseKind;
using crimson::imap::ResponseReader;
using crimson::imap::SyntaxErrorKind;
using crimson::imap::Token;
using crimson::imap::TokenKind;
using crimson::net::NetCat;
using crimson::net::NetError;
using crimson::net::NetOp;
using crimson::net::Retry;
using crimson::test::ScriptedStream;
using crimson::test::imap::error_text;
using crimson::test::imap::Lexed;
using crimson::test::imap::read_framed;
using crimson::test::imap::reassemble;
using crimson::test::imap::Tokenized;

namespace {

struct Expected {
    TokenKind kind;
    std::string bytes;
};

void expect_syntax_error(const Tokenized& result, SyntaxErrorKind kind) {
    const auto error = result.syntax_error();
    CHECK_MSG(error.has_value(), "expected " + std::string{to_string(kind)} + ", got " + error_text(result));
    CHECK_EQ(error->kind, kind);
}

void expect_tokens(const Tokenized& result, const std::vector<Expected>& expected) {
    CHECK_MSG(!result.error, error_text(result));
    CHECK_EQ(result.tokens.size(), expected.size());
    for (std::size_t index = 0; index < expected.size(); ++index) {
        CHECK_EQ(result.tokens[index].kind, expected[index].kind);
        if (!expected[index].bytes.empty()) {
            CHECK_EQ(result.tokens[index].bytes, expected[index].bytes);
        }
    }
}

}  // namespace

CRIMSON_TEST(imap_reader, a_greeting_with_a_capability_code) {
    const std::string input = "* OK [CAPABILITY IMAP4rev1 LITERAL+ AUTH=PLAIN] Server ready {5}\r\n";
    const Tokenized result = read_framed(input);
    expect_tokens(result, {{TokenKind::atom, "*"},
                           {TokenKind::atom, "OK"},
                           {TokenKind::lbracket, "["},
                           {TokenKind::atom, "CAPABILITY"},
                           {TokenKind::atom, "IMAP4rev1"},
                           {TokenKind::atom, "LITERAL+"},
                           {TokenKind::atom, "AUTH=PLAIN"},
                           {TokenKind::rbracket, "]"},
                           {TokenKind::text, "Server ready {5}"},
                           {TokenKind::eol, ""}});
    CHECK(result.ended_cleanly);
    CHECK_EQ(reassemble(result), input);
}

CRIMSON_TEST(imap_reader, a_brace_in_status_text_is_not_a_literal) {
    // The desynchronisation this whole design exists to prevent. Read as
    // grammar, "{5}" would announce a literal and swallow the start of the
    // next response; the next response would then be misread from its sixth
    // byte on.
    const std::string input = "a1 NO Quota {5}\r\n* 3 EXISTS\r\n";
    const Tokenized result = read_framed(input);
    expect_tokens(result, {{TokenKind::atom, "a1"},
                           {TokenKind::atom, "NO"},
                           {TokenKind::text, "Quota {5}"},
                           {TokenKind::eol, ""},
                           {TokenKind::atom, "*"},
                           {TokenKind::number, "3"},
                           {TokenKind::atom, "EXISTS"},
                           {TokenKind::eol, ""}});
}

CRIMSON_TEST(imap_reader, unbalanced_quotes_and_brackets_in_text_are_harmless) {
    const std::string input = "* BAD Parse error at \"( near ] [\r\n* BYE\r\n";
    const Tokenized result = read_framed(input);
    expect_tokens(result, {{TokenKind::atom, "*"},
                           {TokenKind::atom, "BAD"},
                           {TokenKind::text, "Parse error at \"( near ] ["},
                           {TokenKind::eol, ""},
                           {TokenKind::atom, "*"},
                           {TokenKind::atom, "BYE"},
                           {TokenKind::eol, ""}});
}

CRIMSON_TEST(imap_reader, structured_codes_are_tokenized) {
    const std::string input = "* OK [PERMANENTFLAGS (\\Deleted \\Seen \\*)] Limited\r\n";
    const Tokenized result = read_framed(input);
    expect_tokens(result, {{TokenKind::atom, "*"},
                           {TokenKind::atom, "OK"},
                           {TokenKind::lbracket, ""},
                           {TokenKind::atom, "PERMANENTFLAGS"},
                           {TokenKind::lparen, ""},
                           {TokenKind::atom, "\\Deleted"},
                           {TokenKind::atom, "\\Seen"},
                           {TokenKind::atom, "\\*"},
                           {TokenKind::rparen, ""},
                           {TokenKind::rbracket, ""},
                           {TokenKind::text, "Limited"},
                           {TokenKind::eol, ""}});
}

CRIMSON_TEST(imap_reader, unknown_codes_keep_their_arguments_as_text) {
    // RFC 9051 lets an unknown code carry any text up to the closing bracket.
    const std::string input = "* NO [XWEIRD some \"text {5}] Carry on\r\n";
    const Tokenized result = read_framed(input);
    expect_tokens(result, {{TokenKind::atom, "*"},
                           {TokenKind::atom, "NO"},
                           {TokenKind::lbracket, ""},
                           {TokenKind::atom, "XWEIRD"},
                           {TokenKind::text, "some \"text {5}"},
                           {TokenKind::rbracket, ""},
                           {TokenKind::text, "Carry on"},
                           {TokenKind::eol, ""}});
}

CRIMSON_TEST(imap_reader, codes_without_arguments_or_without_a_close) {
    expect_tokens(read_framed("a2 OK [READ-WRITE] SELECT completed\r\n"),
                  {{TokenKind::atom, "a2"},
                   {TokenKind::atom, "OK"},
                   {TokenKind::lbracket, ""},
                   {TokenKind::atom, "READ-WRITE"},
                   {TokenKind::rbracket, ""},
                   {TokenKind::text, "SELECT completed"},
                   {TokenKind::eol, ""}});

    // A server that never closes the bracket: the line still ends cleanly.
    expect_tokens(read_framed("* OK [ALERT Disk nearly full\r\n"),
                  {{TokenKind::atom, "*"},
                   {TokenKind::atom, "OK"},
                   {TokenKind::lbracket, ""},
                   {TokenKind::atom, "ALERT"},
                   {TokenKind::text, "Disk nearly full"},
                   {TokenKind::eol, ""}});
}

CRIMSON_TEST(imap_reader, status_without_text) {
    expect_tokens(read_framed("* BYE\r\na1 OK\r\n"),
                  {{TokenKind::atom, "*"},
                   {TokenKind::atom, "BYE"},
                   {TokenKind::eol, ""},
                   {TokenKind::atom, "a1"},
                   {TokenKind::atom, "OK"},
                   {TokenKind::eol, ""}});
}

CRIMSON_TEST(imap_reader, continuation_requests) {
    expect_tokens(read_framed("+ Ready for literal data\r\n+\r\n+ YGgGCSqGSIb3EgECAgIBAAD/////6jcyG4GJ7Q==\r\n"),
                  {{TokenKind::atom, "+"},
                   {TokenKind::text, "Ready for literal data"},
                   {TokenKind::eol, ""},
                   {TokenKind::atom, "+"},
                   {TokenKind::eol, ""},
                   {TokenKind::atom, "+"},
                   {TokenKind::text, "YGgGCSqGSIb3EgECAgIBAAD/////6jcyG4GJ7Q=="},
                   {TokenKind::eol, ""}});
}

CRIMSON_TEST(imap_reader, data_responses_carry_literals_across_lines) {
    const std::string header = "Subject: hi\r\n\r\n";
    const std::string input = "* 12 FETCH (UID 7 BODY[HEADER] {" + std::to_string(header.size()) + "}\r\n" +
                              header + " FLAGS (\\Seen))\r\na1 OK FETCH done\r\n";
    const Tokenized result = read_framed(input);
    CHECK_MSG(!result.error, error_text(result));
    CHECK_EQ(reassemble(result), input);

    std::size_t literal = 0;
    while (literal < result.tokens.size() && result.tokens[literal].kind != TokenKind::literal_data) {
        ++literal;
    }
    CHECK(literal < result.tokens.size());
    CHECK_EQ(result.tokens[literal].bytes, header);
    // After the literal the line continues with the rest of the FETCH, and
    // only then does the tagged response start.
    CHECK_EQ(result.tokens[literal + 2].bytes, std::string{"FLAGS"});
    CHECK_EQ(result.tokens[result.tokens.size() - 2].bytes, std::string{"FETCH done"});
}

CRIMSON_TEST(imap_reader, the_kind_of_each_response_is_known) {
    ScriptedStream stream;
    stream.give("* OK hi\r\n+ go\r\na1 OK done\r\n");
    ResponseReader reader{stream};
    Token token;
    std::vector<ResponseKind> kinds;
    for (;;) {
        const auto got = reader.next(token);
        CHECK(got.has_value());
        if (*got == ReadStatus::end) {
            break;
        }
        if (token.is(TokenKind::eol)) {
            CHECK(reader.at_response_start());
            kinds.push_back(reader.kind());
        }
    }
    CHECK_EQ(kinds.size(), std::size_t{3});
    CHECK_EQ(kinds[0], ResponseKind::untagged);
    CHECK_EQ(kinds[1], ResponseKind::continuation);
    CHECK_EQ(kinds[2], ResponseKind::tagged);
}

CRIMSON_TEST(imap_reader, a_response_must_start_with_a_tag) {
    expect_syntax_error(read_framed("(oops)\r\n"), SyntaxErrorKind::unexpected_token);
    expect_syntax_error(read_framed("\r\n"), SyntaxErrorKind::unexpected_token);
    expect_syntax_error(read_framed("{3}\r\nabc OK\r\n"), SyntaxErrorKind::unexpected_token);
}

CRIMSON_TEST(imap_reader, the_connection_ending_mid_response_is_truncation) {
    const Tokenized result = read_framed("* OK [CAPABILITY IMAP4rev1");
    expect_syntax_error(result, SyntaxErrorKind::unexpected_end);
    CHECK(!result.ended_cleanly);
}

CRIMSON_TEST(imap_reader, network_errors_are_passed_through_as_they_are) {
    ScriptedStream stream;
    stream.give("* OK hi\r\n").fail_read_at(2, NetError{10054, NetOp::recv, NetCat::wsa, Retry::new_connection});
    ResponseReader reader{stream};
    Token token;
    for (int index = 0; index < 4; ++index) {
        CHECK(reader.next(token).has_value());
    }
    const auto failed = reader.next(token);
    CHECK(!failed.has_value());
    CHECK(crimson::imap::is_net_error(failed.error()));
    CHECK_EQ(std::get<NetError>(failed.error()).native, 10054);
}

CRIMSON_TEST(imap_reader, one_byte_reads_change_nothing) {
    const std::string input =
        "* OK [CAPABILITY IMAP4rev1] ready\r\n* 1 FETCH (BODY[] {5}\r\nhello)\r\na1 NO {3} not a literal\r\n";
    const Tokenized whole = read_framed(input);
    CHECK_MSG(!whole.error, error_text(whole));

    ScriptedStream stream;
    stream.give(input).read_chunk(1);
    ResponseReader reader{stream};
    Tokenized trickled;
    Token token;
    for (;;) {
        const auto got = reader.next(token);
        CHECK(got.has_value());
        if (*got == ReadStatus::end) {
            break;
        }
        crimson::test::imap::append(trickled, token);
    }
    CHECK(trickled.tokens == whole.tokens);
    CHECK(stream.read_calls() >= input.size());
}
