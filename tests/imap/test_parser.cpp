// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#include <string>
#include <variant>
#include <vector>

#include "harness.h"
#include "imap/imap_test_support.h"
#include "protocols/imap/parser.h"

// The parser turns tokens into typed responses. These tests are about what a
// response means; test_lexer.cpp covers how bytes become tokens.

using crimson::imap::ContinuationRequest;
using crimson::imap::Response;
using crimson::imap::ResponseCodeKind;
using crimson::imap::StatusKind;
using crimson::imap::StatusResponse;
using crimson::imap::SyntaxErrorKind;
using crimson::imap::TaggedResponse;
using crimson::imap::UnknownResponse;
using crimson::imap::UntaggedResponse;
using crimson::test::imap::parse_all;
using crimson::test::imap::Parsed;

namespace {

const StatusResponse& untagged_status(const Parsed& parsed, std::size_t index) {
    const auto& untagged = std::get<UntaggedResponse>(parsed.responses.at(index));
    return std::get<StatusResponse>(untagged.body);
}

}  // namespace

CRIMSON_TEST(imap_parser, a_tagged_status_carries_its_tag_and_text) {
    const Parsed parsed = parse_all("a1 OK LOGIN completed\r\n");
    CHECK_MSG(!parsed.error, parsed.error_text());
    CHECK_EQ(parsed.responses.size(), std::size_t{1});

    const auto& tagged = std::get<TaggedResponse>(parsed.responses[0]);
    CHECK_EQ(tagged.tag, std::string{"a1"});
    CHECK_EQ(tagged.status.kind, StatusKind::ok);
    CHECK_EQ(tagged.status.text, std::string{"LOGIN completed"});
    CHECK_EQ(tagged.status.code.kind, ResponseCodeKind::none);
}

CRIMSON_TEST(imap_parser, every_status_keyword_is_recognised) {
    const Parsed parsed = parse_all(
        "* OK one\r\n* NO two\r\n* BAD three\r\n* PREAUTH four\r\n* BYE five\r\na1 ok lowercase\r\n");
    CHECK_MSG(!parsed.error, parsed.error_text());
    CHECK_EQ(parsed.responses.size(), std::size_t{6});
    CHECK_EQ(untagged_status(parsed, 0).kind, StatusKind::ok);
    CHECK_EQ(untagged_status(parsed, 1).kind, StatusKind::no);
    CHECK_EQ(untagged_status(parsed, 2).kind, StatusKind::bad);
    CHECK_EQ(untagged_status(parsed, 3).kind, StatusKind::preauth);
    CHECK_EQ(untagged_status(parsed, 4).kind, StatusKind::bye);
    // Keywords are case-insensitive, whatever a server feels like sending.
    CHECK_EQ(std::get<TaggedResponse>(parsed.responses[5]).status.kind, StatusKind::ok);
}

CRIMSON_TEST(imap_parser, a_status_may_have_no_text_at_all) {
    // iCloud and Fastmail both send exactly this. RFC 9051 says there should
    // be text; refusing the line would be worse than accepting it.
    const Parsed parsed = parse_all("* BYE\r\na2 OK\r\n");
    CHECK_MSG(!parsed.error, parsed.error_text());
    CHECK_EQ(parsed.responses.size(), std::size_t{2});
    CHECK_EQ(untagged_status(parsed, 0).kind, StatusKind::bye);
    CHECK_EQ(untagged_status(parsed, 0).text, std::string{});
}

CRIMSON_TEST(imap_parser, response_codes_with_no_arguments) {
    const Parsed parsed = parse_all("* OK [ALERT] Disk is nearly full\r\na3 OK [READ-WRITE] done\r\n");
    CHECK_MSG(!parsed.error, parsed.error_text());
    CHECK_EQ(untagged_status(parsed, 0).code.kind, ResponseCodeKind::alert);
    CHECK_EQ(untagged_status(parsed, 0).text, std::string{"Disk is nearly full"});

    const auto& tagged = std::get<TaggedResponse>(parsed.responses[1]);
    CHECK_EQ(tagged.status.code.kind, ResponseCodeKind::read_write);
    CHECK_EQ(tagged.status.text, std::string{"done"});
}

CRIMSON_TEST(imap_parser, numeric_response_codes) {
    const Parsed parsed = parse_all(
        "* OK [UIDVALIDITY 3857529045] UIDs valid\r\n"
        "* OK [UIDNEXT 4392] Predicted next UID\r\n"
        "* OK [UNSEEN 12] First unseen\r\n"
        "* OK [HIGHESTMODSEQ 715194045007] Highest\r\n");
    CHECK_MSG(!parsed.error, parsed.error_text());
    CHECK_EQ(untagged_status(parsed, 0).code.kind, ResponseCodeKind::uid_validity);
    CHECK_EQ(*untagged_status(parsed, 0).code.number, std::uint64_t{3857529045});
    CHECK_EQ(*untagged_status(parsed, 1).code.number, std::uint64_t{4392});
    CHECK_EQ(*untagged_status(parsed, 2).code.number, std::uint64_t{12});
    // 63-bit, as CONDSTORE's mod-sequences need.
    CHECK_EQ(*untagged_status(parsed, 3).code.number, std::uint64_t{715194045007});
}

CRIMSON_TEST(imap_parser, the_capability_response_code) {
    const Parsed parsed =
        parse_all("* OK [CAPABILITY IMAP4rev1 LITERAL+ AUTH=PLAIN] Dovecot ready.\r\n");
    CHECK_MSG(!parsed.error, parsed.error_text());
    const auto& code = untagged_status(parsed, 0).code;
    CHECK_EQ(code.kind, ResponseCodeKind::capability);
    CHECK(code.capabilities.has_value());
    CHECK_EQ(code.capabilities->names.size(), std::size_t{3});
    CHECK(code.capabilities->has("literal+"));   // case-insensitive
    CHECK(code.capabilities->has("AUTH=PLAIN"));
    CHECK(!code.capabilities->has("IDLE"));
    CHECK_EQ(untagged_status(parsed, 0).text, std::string{"Dovecot ready."});
}

CRIMSON_TEST(imap_parser, the_permanentflags_response_code) {
    const Parsed parsed = parse_all("* OK [PERMANENTFLAGS (\\Deleted \\Seen $Forwarded \\*)] Limited\r\n");
    CHECK_MSG(!parsed.error, parsed.error_text());
    const auto& code = untagged_status(parsed, 0).code;
    CHECK_EQ(code.kind, ResponseCodeKind::permanent_flags);
    CHECK(code.flags.has_value());
    CHECK(code.flags->deleted);
    CHECK(code.flags->seen);
    CHECK(!code.flags->draft);
    CHECK(code.flags->accepts_new_keywords);  // the \* that says keywords are allowed
    CHECK(code.flags->has("$forwarded"));
    CHECK_EQ(code.flags->keywords.size(), std::size_t{1});
}

CRIMSON_TEST(imap_parser, codes_with_arguments_keep_them_as_sent) {
    const Parsed parsed = parse_all(
        "a4 OK [APPENDUID 38505 3955] APPEND completed\r\n"
        "a5 OK [COPYUID 38505 304,319:320 3956:3958] Done\r\n"
        "* NO [BADCHARSET (US-ASCII \"UTF-8\")] Unsupported\r\n");
    CHECK_MSG(!parsed.error, parsed.error_text());

    const auto& append = std::get<TaggedResponse>(parsed.responses[0]).status.code;
    CHECK_EQ(append.kind, ResponseCodeKind::append_uid);
    CHECK_EQ(append.arguments.size(), std::size_t{2});
    CHECK_EQ(append.arguments[0], std::string{"38505"});
    CHECK_EQ(append.arguments[1], std::string{"3955"});

    const auto& copy = std::get<TaggedResponse>(parsed.responses[1]).status.code;
    CHECK_EQ(copy.kind, ResponseCodeKind::copy_uid);
    CHECK_EQ(copy.arguments[1], std::string{"304,319:320"});

    const auto& charset = untagged_status(parsed, 2).code;
    CHECK_EQ(charset.kind, ResponseCodeKind::badcharset);
    CHECK_EQ(charset.arguments.size(), std::size_t{2});
    CHECK_EQ(charset.arguments[1], std::string{"UTF-8"});  // the quotes are not part of it
}

CRIMSON_TEST(imap_parser, an_unknown_code_is_kept_not_refused) {
    const Parsed parsed = parse_all("* OK [XVENDOR some \"text {5}] and the message\r\n");
    CHECK_MSG(!parsed.error, parsed.error_text());
    const auto& code = untagged_status(parsed, 0).code;
    CHECK_EQ(code.kind, ResponseCodeKind::other);
    CHECK_EQ(code.name, std::string{"XVENDOR"});
    CHECK_EQ(untagged_status(parsed, 0).text, std::string{"and the message"});
}

CRIMSON_TEST(imap_parser, continuation_requests) {
    const Parsed parsed = parse_all("+ Ready for additional command text\r\n+ YGgGCSqGSIb3EgECAgIBAAD=\r\n+\r\n");
    CHECK_MSG(!parsed.error, parsed.error_text());
    CHECK_EQ(parsed.responses.size(), std::size_t{3});
    CHECK_EQ(std::get<ContinuationRequest>(parsed.responses[0]).text,
             std::string{"Ready for additional command text"});
    CHECK_EQ(std::get<ContinuationRequest>(parsed.responses[1]).text,
             std::string{"YGgGCSqGSIb3EgECAgIBAAD="});
    CHECK_EQ(std::get<ContinuationRequest>(parsed.responses[2]).text, std::string{});
}

CRIMSON_TEST(imap_parser, an_unknown_response_is_kept_not_refused) {
    // A session must survive an extension nobody has taught Crimson about.
    const Parsed parsed = parse_all("* XCONVERSATION (id 42) enabled\r\na6 OK done\r\n");
    CHECK_MSG(!parsed.error, parsed.error_text());
    CHECK_EQ(parsed.responses.size(), std::size_t{2});
    const auto& untagged = std::get<UntaggedResponse>(parsed.responses[0]);
    CHECK_EQ(std::get<UnknownResponse>(untagged.body).name, std::string{"XCONVERSATION"});
    CHECK_EQ(std::get<TaggedResponse>(parsed.responses[1]).status.kind, StatusKind::ok);
}

CRIMSON_TEST(imap_parser, an_unknown_response_with_a_literal_does_not_desynchronise) {
    // The important half of "unknown responses are skipped": the literal's
    // content must be consumed as content. Read as anything else, the bytes
    // after {5} would be taken for the next response.
    const Parsed parsed = parse_all("* XSTUFF {5}\r\nhello done\r\na7 OK still here\r\n");
    CHECK_MSG(!parsed.error, parsed.error_text());
    CHECK_EQ(parsed.responses.size(), std::size_t{2});
    const auto& tagged = std::get<TaggedResponse>(parsed.responses[1]);
    CHECK_EQ(tagged.tag, std::string{"a7"});
    CHECK_EQ(tagged.status.text, std::string{"still here"});
}

CRIMSON_TEST(imap_parser, malformed_responses_are_refused) {
    // No tag, no * and no +.
    CHECK_EQ(parse_all("(oops) OK\r\n").syntax_error()->kind, SyntaxErrorKind::unexpected_token);
    // A tag with no status keyword after it.
    CHECK_EQ(parse_all("a1 FROBNICATE\r\n").syntax_error()->kind, SyntaxErrorKind::unexpected_token);
    // A numeric code with no number.
    CHECK_EQ(parse_all("* OK [UIDNEXT] hm\r\n").syntax_error()->kind, SyntaxErrorKind::unexpected_token);
}

CRIMSON_TEST(imap_parser, the_end_of_the_connection_is_reported_not_invented) {
    const Parsed clean = parse_all("* OK hi\r\n");
    CHECK(clean.ended_cleanly);

    const Parsed cut = parse_all("* OK hi\r\na1 OK partial");
    CHECK(!cut.ended_cleanly);
    CHECK_EQ(cut.syntax_error()->kind, SyntaxErrorKind::unexpected_end);
    CHECK_EQ(cut.responses.size(), std::size_t{1});  // what did arrive is kept
}

CRIMSON_TEST(imap_parser, parsing_does_not_depend_on_how_the_input_is_split) {
    const std::string input =
        "* OK [CAPABILITY IMAP4rev1 IDLE] ready\r\n"
        "* XSTUFF {5}\r\nhello\r\n"
        "* OK [PERMANENTFLAGS (\\Seen \\*)] Limited\r\n"
        "a1 NO [ALERT] Quota {5} exceeded\r\n";

    const Parsed whole = parse_all(input);
    CHECK_MSG(!whole.error, whole.error_text());

    for (std::size_t split = 1; split < input.size(); ++split) {
        const Parsed divided = parse_all(input, {split, input.size() - split});
        CHECK_MSG(divided.summary() == whole.summary(),
                  "split at " + std::to_string(split) + ": " + divided.summary());
    }
    const Parsed trickled = parse_all(input, std::vector<std::size_t>(input.size(), 1));
    CHECK_MSG(trickled.summary() == whole.summary(), "one byte per read: " + trickled.summary());
}
