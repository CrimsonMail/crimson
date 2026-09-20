// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// libFuzzer target for the IMAP tokenizer. See ADR 0013.
//
//     scripts\fuzz.cmd imap_lexer [seconds]
//
// Every input is tokenized three ways — whole, divided at points derived from
// the input itself, and (when short) one byte per read — through the same
// ResponseReader the client uses, and then checked for three things:
//
//   1. Nothing crashes, and AddressSanitizer sees no bad memory access.
//   2. All three runs agree exactly: the same tokens, and the same error at
//      the same offset. Chunking must never change the result.
//   3. The tokens reassemble into the input, byte for byte, up to wherever
//      tokenizing stopped.
//
// A violation calls abort(), which libFuzzer records as a crash and saves the
// input that caused it.
//
// The limits are set far below the defaults so that short inputs can reach
// every limit's error path.

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <string_view>
#include <vector>

#include "imap/imap_test_support.h"

namespace {

using crimson::imap::LexerLimits;
using crimson::imap::LexMode;
using crimson::test::imap::lex;
using crimson::test::imap::read_framed;
using crimson::test::imap::reassemble;
using crimson::test::imap::Tokenized;

constexpr LexerLimits kLimits{256, 4096, 16};

void require(bool condition, const char* what) {
    if (!condition) {
        std::fprintf(stderr, "imap_lexer_fuzz: %s\n", what);
        std::abort();
    }
}

bool same_outcome(const Tokenized& a, const Tokenized& b) {
    if (!(a.tokens == b.tokens) || a.ended_cleanly != b.ended_cleanly ||
        a.error.has_value() != b.error.has_value()) {
        return false;
    }
    if (!a.error) {
        return true;
    }
    const auto x = a.syntax_error();
    const auto y = b.syntax_error();
    return x.has_value() && y.has_value() && x->kind == y->kind && x->offset == y->offset;
}

// Chunk sizes derived from the input, so the fuzzer's mutations move the
// boundaries too.
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
        const std::size_t size = 1 + static_cast<std::size_t>(state % 17);
        sizes.push_back(size);
        total += size;
    }
    return sizes;
}

void check_framed(std::string_view input) {
    const Tokenized whole = read_framed(input, kLimits);
    const Tokenized divided = read_framed(input, divisions(input), kLimits);
    require(same_outcome(whole, divided), "dividing the input changed the tokens");

    if (input.size() <= 512) {
        const Tokenized trickled = read_framed(input, std::vector<std::size_t>(input.size(), 1), kLimits);
        require(same_outcome(whole, trickled), "one byte per read changed the tokens");
    }

    const std::string rebuilt = reassemble(whole);
    require(input.substr(0, rebuilt.size()) == rebuilt, "tokens do not reassemble into the input");
    if (whole.ended_cleanly) {
        require(rebuilt.size() == input.size(), "a clean end left input unaccounted for");
    }
}

// The modes ResponseReader never chooses on its own get the same checks
// through the bare lexer.
void check_mode(std::string_view input, LexMode mode) {
    const Tokenized result = lex(input, mode, kLimits);
    const std::string rebuilt = reassemble(result);
    require(input.substr(0, rebuilt.size()) == rebuilt, "a lexer mode lost or invented bytes");
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const std::string_view input{reinterpret_cast<const char*>(data), size};
    check_framed(input);
    check_mode(input, LexMode::astring);
    check_mode(input, LexMode::code_text);
    return 0;
}
