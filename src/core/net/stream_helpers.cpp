// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#include "core/net/stream_helpers.h"

#include <algorithm>

namespace crimson::net {

namespace {

// Read and write buffers are sized to comfortably exceed a TCP segment while
// staying far below any allocation that would matter.
constexpr std::size_t kChunkBytes = 64 * 1024;

}  // namespace

VoidOutcome write_all(ByteStream& stream, std::span<const std::byte> src) noexcept {
    while (!src.empty()) {
        const WriteOutcome written = stream.write_some(src);
        if (!written) {
            return std::unexpected(written.error());
        }
        // Zero progress with no error would spin forever, and a count larger
        // than the buffer means the implementation is broken. Neither is
        // recoverable, so fail loudly instead of looping.
        if (*written == 0 || *written > src.size()) {
            return std::unexpected(NetError::logic(NetOp::send));
        }
        src = src.subspan(*written);
    }
    return {};
}

VoidOutcome read_exactly(ByteStream& stream, std::span<std::byte> dst) noexcept {
    while (!dst.empty()) {
        const ReadOutcome result = stream.read(dst);
        if (!result) {
            return std::unexpected(result.error());
        }
        if (result->bytes > dst.size()) {
            return std::unexpected(NetError::logic(NetOp::recv));
        }

        dst = dst.subspan(result->bytes);
        if (dst.empty()) {
            break;  // filled; a simultaneous eof is not an error here
        }
        if (result->eof) {
            return std::unexpected(NetError::truncated(NetOp::recv));
        }
        if (result->bytes == 0) {
            // ByteStream::read promises not to do this on a non-empty buffer.
            return std::unexpected(NetError::logic(NetOp::recv));
        }
    }
    return {};
}

ReadOutcome read_to_eof(ByteStream& stream, std::vector<std::byte>& out,
                        std::size_t max_bytes) {
    std::size_t total = 0;

    while (total < max_bytes) {
        const std::size_t want = std::min(kChunkBytes, max_bytes - total);
        out.resize(total + want);

        const ReadOutcome result = stream.read(std::span{out}.subspan(total, want));
        if (!result) {
            out.resize(total);
            return std::unexpected(result.error());
        }
        if (result->bytes > want) {
            out.resize(total);
            return std::unexpected(NetError::logic(NetOp::recv));
        }

        total += result->bytes;
        out.resize(total);

        if (result->eof) {
            return ReadResult{total, true};
        }
        if (result->bytes == 0) {
            return std::unexpected(NetError::logic(NetOp::recv));
        }
    }

    // Stopped at the cap rather than at end of stream.
    return ReadResult{total, false};
}

}  // namespace crimson::net
