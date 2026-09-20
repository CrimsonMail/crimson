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

// --- Data responses ------------------------------------------------------------

CRIMSON_TEST(imap_parser, the_capability_response) {
    const Parsed parsed = parse_all(
        "* CAPABILITY IMAP4rev1 IMAP4rev2 LITERAL+ AUTH=PLAIN AUTH=XOAUTH2 X-GM-EXT-1\r\n");
    CHECK_MSG(!parsed.error, parsed.error_text());
    const auto& untagged = std::get<UntaggedResponse>(parsed.responses[0]);
    const auto& capabilities = std::get<crimson::imap::Capabilities>(untagged.body);
    CHECK_EQ(capabilities.names.size(), std::size_t{6});
    CHECK(capabilities.has("IMAP4rev2"));
    CHECK(capabilities.has("auth=xoauth2"));
    CHECK(!capabilities.has("IDLE"));
}

CRIMSON_TEST(imap_parser, list_responses) {
    const Parsed parsed = parse_all(
        "* LIST (\\HasNoChildren \\Sent) \"/\" \"Sent Items\"\r\n"
        "* LIST (\\HasChildren) \"/\" [Gmail]\r\n"
        "* LIST () NIL INBOX\r\n"
        "* LSUB (\\Noselect) \".\" \"news.\"\r\n");
    CHECK_MSG(!parsed.error, parsed.error_text());
    CHECK_EQ(parsed.responses.size(), std::size_t{4});

    const auto listing = [&parsed](std::size_t index) -> const crimson::imap::MailboxListing& {
        return std::get<crimson::imap::MailboxListing>(
            std::get<UntaggedResponse>(parsed.responses.at(index)).body);
    };

    CHECK_EQ(listing(0).name, std::string{"Sent Items"});
    CHECK_EQ(*listing(0).delimiter, '/');
    CHECK(listing(0).has_attribute("\\sent"));       // attributes are case-insensitive
    CHECK(!listing(0).has_attribute("\\Noselect"));

    // An unquoted mailbox name whose brackets belong to the name. This is the
    // case the lexer's astring mode exists for.
    CHECK_EQ(listing(1).name, std::string{"[Gmail]"});

    // NIL means a flat namespace, not a delimiter called "NIL".
    CHECK(!listing(2).delimiter.has_value());
    CHECK_EQ(listing(2).name, std::string{"INBOX"});
    CHECK_EQ(listing(2).attributes.size(), std::size_t{0});

    CHECK_EQ(*listing(3).delimiter, '.');
}

CRIMSON_TEST(imap_parser, status_responses) {
    const Parsed parsed = parse_all(
        "* STATUS blurdybloop (MESSAGES 231 UIDNEXT 44292 UNSEEN 3 HIGHESTMODSEQ 7183 XQUOTA 42)\r\n");
    CHECK_MSG(!parsed.error, parsed.error_text());
    const auto& status = std::get<crimson::imap::MailboxStatus>(
        std::get<UntaggedResponse>(parsed.responses[0]).body);
    CHECK_EQ(status.mailbox, std::string{"blurdybloop"});
    CHECK_EQ(*status.messages, std::uint32_t{231});
    CHECK_EQ(*status.uid_next, std::uint32_t{44292});
    CHECK_EQ(*status.unseen, std::uint32_t{3});
    CHECK_EQ(*status.highest_mod_sequence, std::uint64_t{7183});
    CHECK(!status.recent.has_value());
    // XQUOTA is unknown: its value still had to be consumed, or the closing
    // parenthesis would have been misread.
}

CRIMSON_TEST(imap_parser, search_responses) {
    const Parsed parsed = parse_all(
        "* SEARCH 2 84 882\r\n* SEARCH\r\n* SEARCH 2 5 (MODSEQ 917162500)\r\n");
    CHECK_MSG(!parsed.error, parsed.error_text());

    const auto results = [&parsed](std::size_t index) -> const crimson::imap::SearchResults& {
        return std::get<crimson::imap::SearchResults>(
            std::get<UntaggedResponse>(parsed.responses.at(index)).body);
    };
    CHECK_EQ(results(0).numbers.size(), std::size_t{3});
    CHECK_EQ(results(0).numbers[2], std::uint32_t{882});
    CHECK_EQ(results(1).numbers.size(), std::size_t{0});  // nothing matched
    CHECK_EQ(*results(2).mod_sequence, std::uint64_t{917162500});
}

CRIMSON_TEST(imap_parser, flags_and_counts) {
    const Parsed parsed = parse_all(
        "* FLAGS (\\Answered \\Seen $Forwarded)\r\n* 172 EXISTS\r\n* 1 RECENT\r\n* 44 EXPUNGE\r\n");
    CHECK_MSG(!parsed.error, parsed.error_text());
    CHECK_EQ(parsed.responses.size(), std::size_t{4});

    const auto& flags = std::get<crimson::imap::MailboxFlags>(
        std::get<UntaggedResponse>(parsed.responses[0]).body);
    CHECK(flags.flags.answered);
    CHECK(flags.flags.seen);
    CHECK(flags.flags.has("$Forwarded"));
    CHECK(!flags.flags.accepts_new_keywords);

    const auto count = [&parsed](std::size_t index) -> const crimson::imap::MailboxCount& {
        return std::get<crimson::imap::MailboxCount>(
            std::get<UntaggedResponse>(parsed.responses.at(index)).body);
    };
    CHECK_EQ(count(1).kind, crimson::imap::MailboxCount::Kind::exists);
    CHECK_EQ(count(1).number, std::uint32_t{172});
    CHECK_EQ(count(2).kind, crimson::imap::MailboxCount::Kind::recent);
    CHECK_EQ(count(3).kind, crimson::imap::MailboxCount::Kind::expunge);
    CHECK_EQ(count(3).number, std::uint32_t{44});
}

CRIMSON_TEST(imap_parser, a_mailbox_name_sent_as_a_literal) {
    // Names with 8-bit characters arrive as literals. The parser has to read
    // the content, not just note that a literal happened.
    const Parsed parsed = parse_all("* LIST () \"/\" {7}\r\nArchive\r\n");
    CHECK_MSG(!parsed.error, parsed.error_text());
    const auto& listing = std::get<crimson::imap::MailboxListing>(
        std::get<UntaggedResponse>(parsed.responses[0]).body);
    CHECK_EQ(listing.name, std::string{"Archive"});
}

// --- FETCH ---------------------------------------------------------------------

CRIMSON_TEST(imap_parser, fetch_metadata) {
    const Parsed parsed = parse_all(
        "* 12 FETCH (FLAGS (\\Seen $Forwarded) UID 4827313 RFC822.SIZE 4286 "
        "INTERNALDATE \"17-Jul-1996 02:44:25 -0700\" MODSEQ (7011))\r\n");
    CHECK_MSG(!parsed.error, parsed.error_text());
    const auto& fetch = std::get<crimson::imap::FetchResponse>(
        std::get<UntaggedResponse>(parsed.responses[0]).body);

    CHECK_EQ(fetch.sequence, std::uint32_t{12});
    CHECK_EQ(*fetch.uid, std::uint32_t{4827313});
    CHECK_EQ(*fetch.size, std::uint32_t{4286});
    CHECK(fetch.flags->seen);
    CHECK(fetch.flags->has("$Forwarded"));
    CHECK_EQ(*fetch.mod_sequence, std::uint64_t{7011});

    // 1996-07-17 02:44:25 at -0700 is 09:44:25 UTC.
    CHECK(fetch.internal_date.has_value());
    CHECK_EQ(fetch.internal_date->time_since_epoch().count(), std::int64_t{837596665});
}

CRIMSON_TEST(imap_parser, an_unreadable_internaldate_is_left_unset_not_refused) {
    const Parsed parsed = parse_all("* 1 FETCH (INTERNALDATE \"not a date at all yet\" UID 9)\r\n");
    CHECK_MSG(!parsed.error, parsed.error_text());
    const auto& fetch = std::get<crimson::imap::FetchResponse>(
        std::get<UntaggedResponse>(parsed.responses[0]).body);
    CHECK(!fetch.internal_date.has_value());
    CHECK_EQ(*fetch.uid, std::uint32_t{9});  // the rest of the message still arrives
}

CRIMSON_TEST(imap_parser, fetch_envelope) {
    const Parsed parsed = parse_all(
        "* 12 FETCH (ENVELOPE (\"Wed, 17 Jul 1996 02:23:25 -0700 (PDT)\" "
        "\"IMAP4rev1 WG mtg summary and minutes\" "
        "((\"Terry Gray\" NIL \"gray\" \"cac.washington.edu\")) "
        "((\"Terry Gray\" NIL \"gray\" \"cac.washington.edu\")) "
        "((\"Terry Gray\" NIL \"gray\" \"cac.washington.edu\")) "
        "((NIL NIL \"imap\" \"cac.washington.edu\")) "
        "((NIL NIL \"minutes\" \"CNRI.Reston.VA.US\")(\"John Klensin\" NIL \"KLENSIN\" \"MIT.EDU\")) "
        "NIL NIL \"<B27397-0100000@cac.washington.edu>\"))\r\n");
    CHECK_MSG(!parsed.error, parsed.error_text());
    const auto& envelope = *std::get<crimson::imap::FetchResponse>(
                                std::get<UntaggedResponse>(parsed.responses[0]).body)
                                .envelope;

    CHECK_EQ(envelope.subject, std::string{"IMAP4rev1 WG mtg summary and minutes"});
    CHECK_EQ(envelope.from.size(), std::size_t{1});
    CHECK_EQ(envelope.from[0].name, std::string{"Terry Gray"});
    CHECK_EQ(envelope.from[0].mailbox, std::string{"gray"});
    CHECK_EQ(envelope.from[0].host, std::string{"cac.washington.edu"});
    CHECK_EQ(envelope.to.size(), std::size_t{1});
    CHECK_EQ(envelope.cc.size(), std::size_t{2});
    CHECK_EQ(envelope.cc[1].mailbox, std::string{"KLENSIN"});
    CHECK_EQ(envelope.bcc.size(), std::size_t{0});   // NIL
    CHECK_EQ(envelope.in_reply_to, std::string{});   // NIL
    CHECK_EQ(envelope.message_id, std::string{"<B27397-0100000@cac.washington.edu>"});
    // The date stays as sent: RFC 5322 parsing is Step 6.
    CHECK_EQ(envelope.date, std::string{"Wed, 17 Jul 1996 02:23:25 -0700 (PDT)"});
}

CRIMSON_TEST(imap_parser, fetch_body_sections) {
    const std::string header = "Subject: hi\r\n\r\n";
    const Parsed parsed = parse_all(
        "* 12 FETCH (BODY[HEADER] {" + std::to_string(header.size()) + "}\r\n" + header +
        " BODY[TEXT]<0> \"partial\" BODY[1.2] NIL UID 7)\r\n");
    CHECK_MSG(!parsed.error, parsed.error_text());
    const auto& fetch = std::get<crimson::imap::FetchResponse>(
        std::get<UntaggedResponse>(parsed.responses[0]).body);

    CHECK_EQ(fetch.sections.size(), std::size_t{3});
    CHECK_EQ(fetch.sections[0].specifier, std::string{"HEADER"});
    CHECK_EQ(fetch.sections[0].content, header);
    CHECK(!fetch.sections[0].streamed);

    CHECK_EQ(fetch.sections[1].specifier, std::string{"TEXT"});
    CHECK_EQ(*fetch.sections[1].origin, std::uint32_t{0});
    CHECK_EQ(fetch.sections[1].content, std::string{"partial"});

    CHECK_EQ(fetch.sections[2].specifier, std::string{"1.2"});
    CHECK_EQ(fetch.sections[2].size, std::uint64_t{0});  // NIL: the part is absent
    CHECK_EQ(*fetch.uid, std::uint32_t{7});
}

CRIMSON_TEST(imap_parser, a_section_specifier_with_a_list_keeps_its_shape) {
    const Parsed parsed =
        parse_all("* 1 FETCH (BODY[HEADER.FIELDS (SUBJECT FROM)] {2}\r\nhi)\r\n");
    CHECK_MSG(!parsed.error, parsed.error_text());
    const auto& fetch = std::get<crimson::imap::FetchResponse>(
        std::get<UntaggedResponse>(parsed.responses[0]).body);
    CHECK_EQ(fetch.sections[0].specifier, std::string{"HEADER.FIELDS (SUBJECT FROM)"});
    CHECK_EQ(fetch.sections[0].content, std::string{"hi"});
}

CRIMSON_TEST(imap_parser, a_large_body_is_streamed_not_held) {
    // The point of the sink: a body with no useful upper bound must never
    // have to fit in memory.
    const std::string body(4096, 'x');
    crimson::imap::Parser::Limits limits;
    limits.max_inline_literal = 1024;

    std::string received;
    std::size_t calls = 0;
    bool finished = false;
    const std::string input =
        "* 1 FETCH (BODY[] {" + std::to_string(body.size()) + "}\r\n" + body + ")\r\n";

    crimson::test::imap::ChunkedSource source{input, std::vector<std::size_t>(input.size(), 64)};
    crimson::imap::ResponseReader reader{source};
    crimson::imap::Parser parser{reader, limits};
    parser.stream_large_literals(
        [&](std::string_view specifier, std::span<const std::byte> chunk, bool last) {
            CHECK_EQ(std::string{specifier}, std::string{});
            received.append(reinterpret_cast<const char*>(chunk.data()), chunk.size());
            finished = finished || last;
            ++calls;
        });

    crimson::imap::Response response;
    const auto got = parser.next(response);
    CHECK(got.has_value());
    const auto& fetch =
        std::get<crimson::imap::FetchResponse>(std::get<UntaggedResponse>(response).body);

    CHECK(fetch.sections[0].streamed);
    CHECK_EQ(fetch.sections[0].size, std::uint64_t{body.size()});
    CHECK(fetch.sections[0].content.empty());  // never held
    CHECK_EQ(received, body);                  // but delivered in full
    CHECK(finished);
    CHECK(calls > 1);  // in pieces, as it arrived
}

CRIMSON_TEST(imap_parser, bodystructure_is_noted_and_skipped_for_now) {
    // Step 7 parses this properly, with MIME. Until then its value must still
    // be consumed, or everything after it is misread.
    const Parsed parsed = parse_all(
        "* 3 FETCH (BODYSTRUCTURE ((\"TEXT\" \"PLAIN\" (\"CHARSET\" \"US-ASCII\") NIL NIL \"7BIT\" 1152 23)"
        "(\"TEXT\" \"PLAIN\" (\"CHARSET\" \"US-ASCII\" \"NAME\" \"cc.diff\") NIL NIL \"BASE64\" 4554 73) "
        "\"MIXED\") UID 9 X-GM-LABELS (\\Inbox \"Work stuff\"))\r\n");
    CHECK_MSG(!parsed.error, parsed.error_text());
    const auto& fetch = std::get<crimson::imap::FetchResponse>(
        std::get<UntaggedResponse>(parsed.responses[0]).body);
    CHECK_EQ(*fetch.uid, std::uint32_t{9});
    CHECK_EQ(fetch.unknown_items.size(), std::size_t{2});
    CHECK_EQ(fetch.unknown_items[0], std::string{"BODYSTRUCTURE"});
    CHECK_EQ(fetch.unknown_items[1], std::string{"X-GM-LABELS"});
}

CRIMSON_TEST(imap_parser, malformed_responses_are_refused) {
    const auto expect_refused = [](const Parsed& parsed, const char* what) {
        const auto error = parsed.syntax_error();
        CHECK_MSG(error.has_value(), std::string{what} + ": expected a syntax error, got " +
                                         parsed.error_text());
        if (error) {
            CHECK_EQ(error->kind, SyntaxErrorKind::unexpected_token);
        }
    };

    // No tag, no * and no +.
    expect_refused(parse_all("(oops) OK\r\n"), "no tag");
    // A tag with no status keyword after it.
    expect_refused(parse_all("a1 FROBNICATE\r\n"), "no status keyword");
    // A FETCH whose item list never closes.
    expect_refused(parse_all("* 12 FETCH (FLAGS (\\Seen)\r\n"), "unclosed fetch");
    // A LIST with no mailbox name.
    expect_refused(parse_all("* LIST (\\Noselect) \"/\"\r\n"), "list without a name");
}

CRIMSON_TEST(imap_parser, a_broken_response_code_does_not_cost_the_message) {
    // Structure inside a code is the server's business; Crimson's business is
    // not to drop a connection over it. A code that does not match its own
    // name, or never closes its bracket, is kept as an unrecognised code and
    // the line is read to its end.
    const Parsed parsed = parse_all(
        "* OK [UIDNEXT] no number here\r\n"
        "* OK [ALERT no closing bracket\r\n"
        "a1 OK still talking\r\n");
    CHECK_MSG(!parsed.error, parsed.error_text());
    CHECK_EQ(parsed.responses.size(), std::size_t{3});

    CHECK_EQ(untagged_status(parsed, 0).code.kind, ResponseCodeKind::other);
    CHECK_EQ(untagged_status(parsed, 0).code.name, std::string{"UIDNEXT"});
    CHECK_EQ(untagged_status(parsed, 0).text, std::string{"no number here"});

    CHECK_EQ(untagged_status(parsed, 1).code.name, std::string{"ALERT"});
    CHECK_EQ(untagged_status(parsed, 1).text, std::string{});  // the code ate the line

    CHECK_EQ(std::get<TaggedResponse>(parsed.responses[2]).status.text, std::string{"still talking"});
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
