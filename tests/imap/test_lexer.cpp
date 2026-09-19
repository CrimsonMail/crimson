// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#include <cstddef>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "harness.h"
#include "imap/imap_test_support.h"
#include "protocols/imap/lexer.h"

// The bare lexer, one mode at a time. What each mode does with hostile input
// is tested here; how the modes are chosen for real responses is in
// test_response_reader.cpp, and chunking is in test_fixtures.cpp.

using crimson::imap::Lexer;
using crimson::imap::LexerLimits;
using crimson::imap::LexMode;
using crimson::imap::LexStatus;
using crimson::imap::SyntaxErrorKind;
using crimson::imap::Token;
using crimson::imap::TokenKind;
using crimson::test::imap::error_text;
using crimson::test::imap::lex;
using crimson::test::imap::reassemble;
using crimson::test::imap::Tokenized;

namespace {

[[nodiscard]] std::span<const std::byte> bytes_of(std::string_view text) noexcept {
    return std::span{reinterpret_cast<const std::byte*>(text.data()), text.size()};
}

void expect_kinds(const Tokenized& result, const std::vector<TokenKind>& kinds) {
    CHECK_MSG(!result.error, error_text(result));
    CHECK_EQ(result.tokens.size(), kinds.size());
    for (std::size_t index = 0; index < kinds.size(); ++index) {
        CHECK_EQ(result.tokens[index].kind, kinds[index]);
    }
}

void expect_error(const Tokenized& result, SyntaxErrorKind kind, std::uint64_t offset) {
    const auto error = result.syntax_error();
    CHECK_MSG(error.has_value(), "expected " + std::string{to_string(kind)} + ", got " + error_text(result));
    CHECK_EQ(error->kind, kind);
    CHECK_EQ(error->offset, offset);
}

}  // namespace

// --- Atoms, numbers and NIL --------------------------------------------------

CRIMSON_TEST(imap_lexer, reads_atoms_numbers_and_nil) {
    const std::string input = "* 12 FETCH NIL nil Nil \\Seen $Forwarded \\* +\r\n";
    const Tokenized result = lex(input);
    expect_kinds(result, {TokenKind::atom, TokenKind::number, TokenKind::atom, TokenKind::nil,
                          TokenKind::nil, TokenKind::nil, TokenKind::atom, TokenKind::atom,
                          TokenKind::atom, TokenKind::atom, TokenKind::eol});
    CHECK_EQ(result.tokens[1].number, std::uint64_t{12});
    CHECK_EQ(result.tokens[4].bytes, std::string{"nil"});  // raw keeps the server's spelling
    CHECK_EQ(result.tokens[6].bytes, std::string{"\\Seen"});
    CHECK_EQ(result.tokens[8].bytes, std::string{"\\*"});
    CHECK_EQ(result.tokens[2].spaces, std::uint32_t{1});
    CHECK_EQ(reassemble(result), input);
}

CRIMSON_TEST(imap_lexer, numbers_use_all_63_bits_and_no_more) {
    const Tokenized fits = lex("9223372036854775807 007\r\n");
    expect_kinds(fits, {TokenKind::number, TokenKind::number, TokenKind::eol});
    CHECK_EQ(fits.tokens[0].number, std::uint64_t{9223372036854775807ull});
    CHECK_EQ(fits.tokens[1].number, std::uint64_t{7});
    CHECK_EQ(fits.tokens[1].bytes, std::string{"007"});

    // One more than 2^63 - 1. The offset names the digit that overflowed.
    expect_error(lex("9223372036854775808\r\n"), SyntaxErrorKind::number_too_large, 18);
}

CRIMSON_TEST(imap_lexer, digits_mixed_with_letters_are_an_atom) {
    const Tokenized result = lex("1:3,5 12abc\r\n");
    expect_kinds(result, {TokenKind::atom, TokenKind::atom, TokenKind::eol});
}

CRIMSON_TEST(imap_lexer, control_characters_are_refused_in_atoms) {
    expect_error(lex("abc\x01" "def\r\n"), SyntaxErrorKind::invalid_character, 3);
    expect_error(lex("abc\tdef\r\n"), SyntaxErrorKind::invalid_character, 3);
}

// --- Quoted strings ------------------------------------------------------------

CRIMSON_TEST(imap_lexer, quoted_strings_are_unescaped) {
    const std::string input = R"("a \"b\" \\ c" "" "caf)" "\xC3\xA9" "\"\r\n";
    const Tokenized result = lex(input);
    expect_kinds(result, {TokenKind::quoted, TokenKind::quoted, TokenKind::quoted, TokenKind::eol});
    CHECK_EQ(result.tokens[0].unescaped, std::string{R"(a "b" \ c)"});
    CHECK_EQ(result.tokens[1].unescaped, std::string{});
    CHECK_EQ(result.tokens[2].unescaped, std::string{"caf\xC3\xA9"});  // UTF-8, as IMAP4rev2 allows
    CHECK_EQ(reassemble(result), input);
}

CRIMSON_TEST(imap_lexer, quoted_strings_accept_only_two_escapes) {
    expect_error(lex(R"("a\x")" "\r\n"), SyntaxErrorKind::bad_escape, 3);
}

CRIMSON_TEST(imap_lexer, a_line_cannot_end_inside_a_quoted_string) {
    expect_error(lex("\"unterminated\r\nnext\r\n"), SyntaxErrorKind::unterminated_quoted, 13);
}

CRIMSON_TEST(imap_lexer, quoted_strings_refuse_nul) {
    expect_error(lex(std::string{"\"a\0b\"\r\n", 7}), SyntaxErrorKind::invalid_character, 2);
}

// --- Literals ------------------------------------------------------------------

CRIMSON_TEST(imap_lexer, literal_content_is_opaque) {
    // Everything a literal contains is data: CRLF, a quote, even something that
    // looks like another literal. Only the announced length decides.
    const std::string content = "line one\r\n\"{3}\r\nabc";
    const std::string input = "(BODY[] {" + std::to_string(content.size()) + "}\r\n" + content + ")\r\n";
    const Tokenized result = lex(input);
    expect_kinds(result, {TokenKind::lparen, TokenKind::atom, TokenKind::lbracket, TokenKind::rbracket,
                          TokenKind::literal_begin, TokenKind::literal_data, TokenKind::literal_end,
                          TokenKind::rparen, TokenKind::eol});
    CHECK_EQ(result.tokens[4].number, std::uint64_t{content.size()});
    CHECK_EQ(result.tokens[5].bytes, content);
    CHECK_EQ(reassemble(result), input);
}

CRIMSON_TEST(imap_lexer, literal8_carries_any_byte) {
    const std::string content{"\0\x01\r\n\xFF", 5};
    const std::string input = "~{5}\r\n" + content + "\r\n";
    const Tokenized result = lex(input);
    expect_kinds(result, {TokenKind::literal_begin, TokenKind::literal_data, TokenKind::literal_end,
                          TokenKind::eol});
    CHECK(result.tokens[0].binary);
    CHECK_EQ(result.tokens[1].bytes, content);
}

CRIMSON_TEST(imap_lexer, a_tilde_without_a_brace_is_an_atom) {
    const Tokenized result = lex("~user ~\r\n");
    expect_kinds(result, {TokenKind::atom, TokenKind::atom, TokenKind::eol});
    CHECK_EQ(result.tokens[0].bytes, std::string{"~user"});
}

CRIMSON_TEST(imap_lexer, empty_and_non_synchronizing_literals) {
    const Tokenized result = lex("{0}\r\n {3+}\r\nabc\r\n");
    expect_kinds(result, {TokenKind::literal_begin, TokenKind::literal_end, TokenKind::literal_begin,
                          TokenKind::literal_data, TokenKind::literal_end, TokenKind::eol});
    CHECK_EQ(result.tokens[0].number, std::uint64_t{0});
    CHECK_EQ(result.tokens[3].bytes, std::string{"abc"});
}

CRIMSON_TEST(imap_lexer, malformed_literal_headers_are_refused) {
    expect_error(lex("{}\r\n"), SyntaxErrorKind::bad_literal, 1);
    expect_error(lex("{12a}\r\n"), SyntaxErrorKind::bad_literal, 3);
    expect_error(lex("{3}x"), SyntaxErrorKind::bad_literal, 3);
    expect_error(lex("{3}\rx"), SyntaxErrorKind::bad_literal, 4);
    expect_error(lex("{99999999999999999999}\r\n"), SyntaxErrorKind::number_too_large, 19);
}

CRIMSON_TEST(imap_lexer, literals_beyond_the_limit_are_refused_before_any_content) {
    LexerLimits limits;
    limits.max_literal_bytes = 1024;
    expect_error(lex("{1025}\r\n", LexMode::normal, limits), SyntaxErrorKind::literal_too_large, 0);
    const Tokenized fits = lex("{1024}\r\n" + std::string(1024, 'x') + "\r\n", LexMode::normal, limits);
    CHECK_MSG(!fits.error, error_text(fits));
}

CRIMSON_TEST(imap_lexer, input_ending_inside_a_literal_is_truncation) {
    expect_error(lex("{10}\r\nabc"), SyntaxErrorKind::unexpected_end, 9);
}

// --- Line endings ----------------------------------------------------------------

CRIMSON_TEST(imap_lexer, lines_end_with_crlf_and_nothing_else) {
    expect_error(lex("OK\n"), SyntaxErrorKind::bad_line_ending, 2);
    expect_error(lex("OK\rX"), SyntaxErrorKind::bad_line_ending, 2);
    expect_error(lex("OK\n", LexMode::text), SyntaxErrorKind::bad_line_ending, 2);
}

CRIMSON_TEST(imap_lexer, trailing_spaces_before_crlf_are_kept) {
    const std::string input = "OK   \r\n";
    const Tokenized result = lex(input);
    expect_kinds(result, {TokenKind::atom, TokenKind::eol});
    CHECK_EQ(result.tokens[1].spaces, std::uint32_t{3});
    CHECK_EQ(reassemble(result), input);
}

CRIMSON_TEST(imap_lexer, how_the_input_ends_is_reported) {
    CHECK(lex("OK\r\n").ended_cleanly);
    CHECK(lex("").ended_cleanly);

    // A token still waiting for its terminator is complete once the input
    // ends, and then the missing CRLF is the error.
    const Tokenized unterminated = lex("OK");
    CHECK_EQ(unterminated.tokens.size(), std::size_t{1});
    expect_error(unterminated, SyntaxErrorKind::unexpected_end, 2);

    expect_error(lex("OK \r"), SyntaxErrorKind::unexpected_end, 4);
    expect_error(lex("\"open"), SyntaxErrorKind::unexpected_end, 5);
}

// --- Limits --------------------------------------------------------------------

CRIMSON_TEST(imap_lexer, a_huge_atom_is_refused_without_buffering_it) {
    // Ten megabytes of atom, fed the way a network would. The lexer must give up
    // at the limit rather than hold the lot waiting for the atom to end.
    Lexer lexer;
    const std::string piece(64 * 1024, 'a');
    Token token;
    bool refused = false;
    for (int round = 0; round < 160 && !refused; ++round) {
        lexer.feed(bytes_of(piece));
        CHECK(lexer.buffered() <= lexer.limits().max_token_bytes + piece.size());
        const auto got = lexer.next(LexMode::normal, token);
        if (!got) {
            CHECK_EQ(got.error().kind, SyntaxErrorKind::token_too_long);
            refused = true;
        } else {
            CHECK_EQ(*got, LexStatus::need_more);
        }
    }
    CHECK(refused);
}

CRIMSON_TEST(imap_lexer, runs_of_spaces_are_bounded_too) {
    LexerLimits limits;
    limits.max_token_bytes = 16;
    CHECK(!lex(std::string(16, ' ') + "OK\r\n", LexMode::normal, limits).error);
    expect_error(lex(std::string(17, ' ') + "OK\r\n", LexMode::normal, limits),
                 SyntaxErrorKind::token_too_long, 16);
}

CRIMSON_TEST(imap_lexer, a_token_exactly_at_the_limit_is_accepted) {
    LexerLimits limits;
    limits.max_token_bytes = 8;
    CHECK(!lex("abcdefgh\r\n", LexMode::normal, limits).error);
    expect_error(lex("abcdefghi\r\n", LexMode::normal, limits), SyntaxErrorKind::token_too_long, 0);
    CHECK(!lex("\"abcdef\"\r\n", LexMode::normal, limits).error);
    expect_error(lex("\"abcdefg\"\r\n", LexMode::normal, limits), SyntaxErrorKind::token_too_long, 0);
}

CRIMSON_TEST(imap_lexer, deep_nesting_is_refused) {
    const std::string deep(1000, '(');
    expect_error(lex(deep), SyntaxErrorKind::nesting_too_deep, 128);

    // Depth is per line: a malformed line cannot push the next one down.
    const std::string lines = std::string(100, '(') + "\r\n" + std::string(100, '(') + "\r\n";
    CHECK(!lex(lines).error);
}

CRIMSON_TEST(imap_lexer, stray_closers_do_not_underflow) {
    const Tokenized result = lex(") ] ((\r\n");
    CHECK_MSG(!result.error, error_text(result));
}

// --- Modes ---------------------------------------------------------------------

CRIMSON_TEST(imap_lexer, astring_mode_keeps_brackets_inside_a_mailbox_name) {
    const Tokenized normal = lex("[Gmail]/Drafts\r\n", LexMode::normal);
    expect_kinds(normal, {TokenKind::lbracket, TokenKind::atom, TokenKind::rbracket, TokenKind::atom,
                          TokenKind::eol});

    const Tokenized astring = lex("[Gmail]/Drafts NIL 42\r\n", LexMode::astring);
    expect_kinds(astring, {TokenKind::atom, TokenKind::atom, TokenKind::atom, TokenKind::eol});
    CHECK_EQ(astring.tokens[0].bytes, std::string{"[Gmail]/Drafts"});
}

CRIMSON_TEST(imap_lexer, text_mode_takes_the_line_as_it_is) {
    // The reason modes exist. In normal mode "{5}" is a literal announcement
    // and the quote opens a string; as text, both are just characters.
    const std::string input = "  Try {5} and \"unbalanced ] [\r\n";
    const Tokenized result = lex(input, LexMode::text);
    expect_kinds(result, {TokenKind::text, TokenKind::eol});
    CHECK_EQ(result.tokens[0].bytes, std::string{"Try {5} and \"unbalanced ] ["});
    CHECK_EQ(result.tokens[0].spaces, std::uint32_t{2});
    CHECK_EQ(reassemble(result), input);
}

CRIMSON_TEST(imap_lexer, text_refuses_nul) {
    expect_error(lex(std::string{"ab\0c\r\n", 6}, LexMode::text), SyntaxErrorKind::invalid_character, 2);
}

CRIMSON_TEST(imap_lexer, code_modes_stop_at_the_closing_bracket) {
    const Tokenized name = lex("PERMANENTFLAGS", LexMode::code_name);
    CHECK_EQ(name.tokens[0].kind, TokenKind::atom);

    const Tokenized text = lex("some \"text {5}] rest\r\n", LexMode::code_text);
    CHECK_EQ(text.tokens[0].kind, TokenKind::text);
    CHECK_EQ(text.tokens[0].bytes, std::string{"some \"text {5}"});
    CHECK_EQ(text.tokens[1].kind, TokenKind::rbracket);
}

CRIMSON_TEST(imap_lexer, changing_mode_mid_token_rereads_it) {
    // A token part-way through arriving was being read for one mode; asked in
    // another, it is read again from its first byte, not from where the first
    // mode stopped.
    Lexer lexer;
    Token token;
    lexer.feed(bytes_of("abc {5"));
    CHECK_EQ(*lexer.next(LexMode::normal, token), LexStatus::token);  // abc
    // In normal mode "{5" is the start of a literal header, still arriving.
    CHECK_EQ(*lexer.next(LexMode::normal, token), LexStatus::need_more);
    // Asked as text instead, the same bytes are text.
    CHECK_EQ(*lexer.next(LexMode::text, token), LexStatus::need_more);  // no CRLF yet
    lexer.feed(bytes_of("} more\r\n"));
    CHECK_EQ(*lexer.next(LexMode::text, token), LexStatus::token);
    CHECK_EQ(token.kind, TokenKind::text);
    CHECK_EQ(token.raw, std::string{"{5} more"});
    CHECK(!lexer.in_literal());
}

CRIMSON_TEST(imap_lexer, a_failed_lexer_stays_failed) {
    Lexer lexer;
    Token token;
    lexer.feed(bytes_of("OK\n"));
    (void)lexer.next(LexMode::normal, token);
    const auto first = lexer.next(LexMode::normal, token);
    CHECK(!first);
    lexer.feed(bytes_of("a1 OK fine\r\n"));
    const auto again = lexer.next(LexMode::normal, token);
    CHECK(!again);
    CHECK_EQ(again.error().kind, first.error().kind);
}

CRIMSON_TEST(imap_lexer, literal_views_point_at_the_content) {
    Lexer lexer;
    Token token;
    lexer.feed(bytes_of("{5}\r\nhel"));
    CHECK_EQ(*lexer.next(LexMode::normal, token), LexStatus::token);
    CHECK_EQ(*lexer.next(LexMode::normal, token), LexStatus::token);
    CHECK_EQ(token.kind, TokenKind::literal_data);
    CHECK_EQ(std::string(reinterpret_cast<const char*>(token.data.data()), token.data.size()),
             std::string{"hel"});
    CHECK(lexer.in_literal());
    CHECK_EQ(*lexer.next(LexMode::normal, token), LexStatus::need_more);
    lexer.feed(bytes_of("lo\r\n"));
    CHECK_EQ(*lexer.next(LexMode::normal, token), LexStatus::token);
    CHECK_EQ(token.data.size(), std::size_t{2});
    CHECK_EQ(*lexer.next(LexMode::normal, token), LexStatus::token);
    CHECK_EQ(token.kind, TokenKind::literal_end);
    CHECK(!lexer.in_literal());
}
