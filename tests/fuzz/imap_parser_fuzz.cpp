// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// libFuzzer target for the IMAP parser. See ADR 0013.
//
//     scripts\fuzz.cmd imap_parser [seconds]
//
// Where the tokenizer's target checks that bytes become the same tokens
// however they are divided, this one checks the same of meaning: an input
// parsed whole and the same input parsed in pieces must produce the same
// responses, or the same error at the same place.
//
// That matters more here than it looks. The parser chooses the lexer's mode
// for every token, and a mode chosen a moment too early or late is exactly
// the kind of bug that only appears when a read boundary lands inside a
// response.

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <string_view>
#include <vector>

#include "imap/imap_test_support.h"

namespace {

using crimson::imap::Parser;
using crimson::test::imap::Parsed;
using crimson::test::imap::parse_all;

// Small enough that short inputs reach every limit.
constexpr Parser::Limits kLimits{256, 64};

void require(bool condition, const char* what) {
    if (!condition) {
        std::fprintf(stderr, "imap_parser_fuzz: %s\n", what);
        std::abort();
    }
}

std::vector<std::size_t> divisions(std::string_view input) {
    std::uint64_t state = 1469598103934665603ull;  // FNV-1a
    for (const char c : input) {
        state = (state ^ static_cast<unsigned char>(c)) * 1099511628211ull;
    }
    std::vector<std::size_t> sizes;
    for (std::size_t total = 0; total < input.size();) {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        const std::size_t size = 1 + static_cast<std::size_t>(state % 23);
        sizes.push_back(size);
        total += size;
    }
    return sizes;
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const std::string_view input{reinterpret_cast<const char*>(data), size};

    const Parsed whole = parse_all(input, {}, kLimits);
    const Parsed divided = parse_all(input, divisions(input), kLimits);
    require(whole.summary() == divided.summary(), "dividing the input changed the responses");

    if (input.size() <= 512) {
        const Parsed trickled = parse_all(input, std::vector<std::size_t>(input.size(), 1), kLimits);
        require(whole.summary() == trickled.summary(), "one byte per read changed the responses");
    }
    return 0;
}
