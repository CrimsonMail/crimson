// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#include <algorithm>
#include <cstddef>
#include <filesystem>
#include <random>
#include <string>
#include <vector>

#include "harness.h"
#include "imap/imap_test_support.h"

// The Step 3 milestone: real IMAP server responses tokenize correctly however
// the network divides them.
//
// Every transcript in tests/imap/fixtures is tokenized whole, and then again
// with the input divided every way that matters: at each single byte position,
// one byte per read, and a thousand seeded random divisions. Every run must
// produce the same tokens, and the tokens must reassemble into the transcript
// byte for byte.
//
// The transcripts are real traffic recorded from mail providers by
// crimson-imap-probe, examples from RFC 3501 and RFC 9051, and hand-written
// edge cases. See tests/imap/README.md for where each came from.

using crimson::imap::TokenKind;
using crimson::test::imap::error_text;
using crimson::test::imap::fixture_directory;
using crimson::test::imap::Lexed;
using crimson::test::imap::read_file;
using crimson::test::imap::read_framed;
using crimson::test::imap::reassemble;
using crimson::test::imap::Tokenized;

namespace {

struct Fixture {
    std::string name;
    std::string bytes;
};

std::vector<Fixture> load_fixtures() {
    std::vector<Fixture> fixtures;
    const std::filesystem::path directory = fixture_directory();
    if (!std::filesystem::is_directory(directory)) {
        return fixtures;
    }
    for (const auto& entry : std::filesystem::directory_iterator{directory}) {
        if (entry.is_regular_file() && entry.path().extension() == ".imap") {
            fixtures.push_back({entry.path().filename().string(), read_file(entry.path())});
        }
    }
    std::sort(fixtures.begin(), fixtures.end(),
              [](const Fixture& a, const Fixture& b) { return a.name < b.name; });
    return fixtures;
}

// Names the first place two token streams differ, for a readable failure.
std::string first_difference(const Tokenized& expected, const Tokenized& actual) {
    const std::size_t shared = std::min(expected.tokens.size(), actual.tokens.size());
    for (std::size_t index = 0; index < shared; ++index) {
        if (!(expected.tokens[index] == actual.tokens[index])) {
            const Lexed& want = expected.tokens[index];
            const Lexed& got = actual.tokens[index];
            return "token " + std::to_string(index) + ": expected " +
                   std::string{to_string(want.kind)} + " \"" + want.bytes + "\" at " +
                   std::to_string(want.offset) + ", got " + std::string{to_string(got.kind)} +
                   " \"" + got.bytes + "\" at " + std::to_string(got.offset);
        }
    }
    if (expected.tokens.size() != actual.tokens.size()) {
        return std::to_string(expected.tokens.size()) + " tokens expected, " +
               std::to_string(actual.tokens.size()) + " produced (" + error_text(actual) + ")";
    }
    // Same tokens: then it is the ending that is wrong.
    return "stopped with " + error_text(actual) + (actual.ended_cleanly ? "" : ", not at a clean end");
}

void expect_same(const Fixture& fixture, const Tokenized& whole, const Tokenized& divided,
                 const std::string& how) {
    const bool same = whole.tokens == divided.tokens && divided.ended_cleanly && !divided.error;
    CHECK_MSG(same, fixture.name + ", " + how + ": " + first_difference(whole, divided));
}

}  // namespace

CRIMSON_TEST(imap_fixtures, the_fixtures_are_there) {
    const auto fixtures = load_fixtures();
    CHECK_MSG(fixtures.size() >= 5, "found " + std::to_string(fixtures.size()) + " fixtures in " +
                                        fixture_directory().string());
}

CRIMSON_TEST(imap_fixtures, each_tokenizes_cleanly_and_losslessly) {
    for (const Fixture& fixture : load_fixtures()) {
        const Tokenized whole = read_framed(fixture.bytes);
        CHECK_MSG(!whole.error, fixture.name + ": " + error_text(whole));
        CHECK_MSG(whole.ended_cleanly, fixture.name + " did not end between responses");
        CHECK_MSG(reassemble(whole) == fixture.bytes, fixture.name + " does not reassemble byte for byte");
        CHECK_MSG(!whole.tokens.empty() && whole.tokens.back().kind == TokenKind::eol,
                  fixture.name + " does not end with CRLF");
    }
}

CRIMSON_TEST(imap_fixtures, provider_greetings_are_untagged_ok) {
    // Every recorded provider session begins with a greeting and ends with
    // the tagged completion of LOGOUT, or the server closing after its BYE.
    for (const Fixture& fixture : load_fixtures()) {
        if (!fixture.name.ends_with("-prelogin.imap")) {
            continue;
        }
        const Tokenized whole = read_framed(fixture.bytes);
        CHECK_MSG(whole.tokens.size() >= 3, fixture.name);
        CHECK_MSG(whole.tokens[0].bytes == "*", fixture.name + " greeting is not untagged");
        const std::string& status = whole.tokens[1].bytes;
        CHECK_MSG(status == "OK" || status == "PREAUTH", fixture.name + " greeting status is " + status);
    }
}

CRIMSON_TEST(imap_fixtures, each_parses_into_typed_responses) {
    // Tokenizing is not understanding. Every transcript, including the real
    // provider sessions, must also come out as typed responses.
    for (const Fixture& fixture : load_fixtures()) {
        const crimson::test::imap::Parsed parsed = crimson::test::imap::parse_all(fixture.bytes);
        CHECK_MSG(!parsed.error, fixture.name + ": " + parsed.error_text());
        CHECK_MSG(parsed.ended_cleanly, fixture.name + " did not end between responses");
        CHECK_MSG(!parsed.responses.empty(), fixture.name + " produced no responses");
    }
}

CRIMSON_TEST(imap_fixtures, parsing_does_not_depend_on_the_division_either) {
    for (const Fixture& fixture : load_fixtures()) {
        const std::string whole = crimson::test::imap::parse_all(fixture.bytes).summary();
        for (std::size_t split = 1; split < fixture.bytes.size(); ++split) {
            const std::string divided =
                crimson::test::imap::parse_all(fixture.bytes,
                                               {split, fixture.bytes.size() - split})
                    .summary();
            CHECK_MSG(divided == whole, fixture.name + ", split at " + std::to_string(split));
        }
        const std::string trickled =
            crimson::test::imap::parse_all(fixture.bytes,
                                           std::vector<std::size_t>(fixture.bytes.size(), 1))
                .summary();
        CHECK_MSG(trickled == whole, fixture.name + ", one byte per read");
    }
}

CRIMSON_TEST(imap_fixtures, a_split_at_every_byte_changes_nothing) {
    for (const Fixture& fixture : load_fixtures()) {
        const Tokenized whole = read_framed(fixture.bytes);
        for (std::size_t split = 1; split < fixture.bytes.size(); ++split) {
            const Tokenized divided =
                read_framed(fixture.bytes, std::vector<std::size_t>{split, fixture.bytes.size() - split});
            expect_same(fixture, whole, divided, "split at " + std::to_string(split));
        }
    }
}

CRIMSON_TEST(imap_fixtures, one_byte_per_read_changes_nothing) {
    for (const Fixture& fixture : load_fixtures()) {
        const Tokenized whole = read_framed(fixture.bytes);
        const Tokenized trickled =
            read_framed(fixture.bytes, std::vector<std::size_t>(fixture.bytes.size(), 1));
        expect_same(fixture, whole, trickled, "one byte per read");
    }
}

CRIMSON_TEST(imap_fixtures, random_divisions_change_nothing) {
    // Seeded, so a failure reproduces exactly. Mostly small pieces, the size
    // that stresses resumption, with the occasional large read in between.
    std::mt19937 random{20260918};
    std::uniform_int_distribution<std::size_t> small{1, 8};
    std::uniform_int_distribution<std::size_t> large{9, 4096};
    std::uniform_int_distribution<int> pick{0, 9};

    for (const Fixture& fixture : load_fixtures()) {
        const Tokenized whole = read_framed(fixture.bytes);
        for (int round = 0; round < 1000; ++round) {
            std::vector<std::size_t> chunks;
            for (std::size_t total = 0; total < fixture.bytes.size();) {
                const std::size_t size = pick(random) == 0 ? large(random) : small(random);
                chunks.push_back(size);
                total += size;
            }
            const Tokenized divided = read_framed(fixture.bytes, chunks);
            expect_same(fixture, whole, divided, "random division " + std::to_string(round));
        }
    }
}
