// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef CRIMSON_TESTS_NET_SCRIPTED_STREAM_H
#define CRIMSON_TESTS_NET_SCRIPTED_STREAM_H

#include <algorithm>
#include <cstddef>
#include <string_view>
#include <vector>

#include "core/net/byte_stream.h"

// An in-memory ByteStream whose chunking is dictated rather than observed.
//
// This is a Step 1 deliverable, not a convenience. write_all's partial-write
// loop and read_exactly's short-read loop are the two pieces of logic every
// protocol layer will depend on, and neither can be triggered reliably over a
// real socket: loopback almost always accepts a whole small buffer in one send
// and delivers it in one recv. Testing them against a real connection would be
// testing whether the kernel happened to fragment, which is not a test.
//
// A fake that hands over exactly one byte per call makes both loops run their
// full length, deterministically, in microseconds, with no threads and no
// sockets. It is also the template for the replay stream Step 2 needs to test
// the Schannel record layer without a server.

namespace crimson::test {

class ScriptedStream final : public crimson::net::ByteStream {
public:
    ScriptedStream() = default;

    // Data the stream will hand back from read().
    ScriptedStream& give(std::span<const std::byte> data) {
        source_.insert(source_.end(), data.begin(), data.end());
        return *this;
    }

    ScriptedStream& give(std::string_view text) {
        const auto* bytes = reinterpret_cast<const std::byte*>(text.data());
        source_.insert(source_.end(), bytes, bytes + text.size());
        return *this;
    }

    // Maximum bytes returned per read() call. 1 exercises the short-read path
    // hardest. Zero means "as much as the caller asked for".
    ScriptedStream& read_chunk(std::size_t bytes) {
        read_chunk_ = bytes;
        return *this;
    }

    // Maximum bytes accepted per write_some() call. 1 makes write_all loop once
    // per byte.
    ScriptedStream& write_chunk(std::size_t bytes) {
        write_chunk_ = bytes;
        return *this;
    }

    // Fail the Nth read (1-based) instead of returning data.
    ScriptedStream& fail_read_at(std::size_t call, crimson::net::NetError error) {
        fail_read_at_ = call;
        read_error_ = error;
        return *this;
    }

    ScriptedStream& fail_write_at(std::size_t call, crimson::net::NetError error) {
        fail_write_at_ = call;
        write_error_ = error;
        return *this;
    }

    // Report a zero-byte, non-EOF read, which ByteStream::read forbids. Used to
    // prove the helpers refuse to spin on a misbehaving implementation rather
    // than hanging.
    ScriptedStream& stall_at(std::size_t call) {
        stall_at_ = call;
        return *this;
    }

    [[nodiscard]] const std::vector<std::byte>& written() const noexcept {
        return written_;
    }

    [[nodiscard]] std::string_view written_text() const noexcept {
        return std::string_view{reinterpret_cast<const char*>(written_.data()),
                                written_.size()};
    }

    [[nodiscard]] std::size_t read_calls() const noexcept { return read_calls_; }
    [[nodiscard]] std::size_t write_calls() const noexcept { return write_calls_; }
    [[nodiscard]] bool shutdown_called() const noexcept { return shutdown_called_; }
    [[nodiscard]] bool closed() const noexcept { return closed_; }

    crimson::net::ReadOutcome read(std::span<std::byte> destination) noexcept override {
        ++read_calls_;

        if (fail_read_at_ != 0 && read_calls_ == fail_read_at_) {
            return std::unexpected(read_error_);
        }
        if (stall_at_ != 0 && read_calls_ == stall_at_) {
            return crimson::net::ReadResult{0, false};  // contract violation, on purpose
        }
        if (destination.empty()) {
            return crimson::net::ReadResult{0, false};
        }
        if (position_ >= source_.size()) {
            return crimson::net::ReadResult{0, true};
        }

        std::size_t available = source_.size() - position_;
        std::size_t count = std::min(destination.size(), available);
        if (read_chunk_ != 0) {
            count = std::min(count, read_chunk_);
        }

        std::copy_n(source_.begin() + static_cast<std::ptrdiff_t>(position_), count,
                    destination.begin());
        position_ += count;

        // Report EOF together with the final bytes when the source is exhausted,
        // which is the case TlsStream will have to handle in Step 2.
        const bool exhausted = position_ >= source_.size();
        return crimson::net::ReadResult{count, exhausted && report_eof_with_data_};
    }

    // By default the stream reports EOF on a separate, later call, which is what
    // a socket usually does. Enable this to deliver bytes and EOF together.
    ScriptedStream& eof_with_final_bytes(bool enabled) {
        report_eof_with_data_ = enabled;
        return *this;
    }

    crimson::net::WriteOutcome write_some(
        std::span<const std::byte> source) noexcept override {
        ++write_calls_;

        if (fail_write_at_ != 0 && write_calls_ == fail_write_at_) {
            return std::unexpected(write_error_);
        }
        if (source.empty()) {
            return std::size_t{0};
        }

        std::size_t count = source.size();
        if (write_chunk_ != 0) {
            count = std::min(count, write_chunk_);
        }

        try {
            written_.insert(written_.end(), source.begin(),
                            source.begin() + static_cast<std::ptrdiff_t>(count));
        } catch (...) {
            return std::unexpected(
                crimson::net::NetError::logic(crimson::net::NetOp::send));
        }
        return count;
    }

    crimson::net::VoidOutcome shutdown_send() noexcept override {
        shutdown_called_ = true;
        return {};
    }

    void close() noexcept override { closed_ = true; }

private:
    std::vector<std::byte> source_;
    std::vector<std::byte> written_;
    std::size_t position_ = 0;
    std::size_t read_chunk_ = 0;
    std::size_t write_chunk_ = 0;
    std::size_t read_calls_ = 0;
    std::size_t write_calls_ = 0;
    std::size_t fail_read_at_ = 0;
    std::size_t fail_write_at_ = 0;
    std::size_t stall_at_ = 0;
    bool report_eof_with_data_ = false;
    bool shutdown_called_ = false;
    bool closed_ = false;
    crimson::net::NetError read_error_{};
    crimson::net::NetError write_error_{};
};

}  // namespace crimson::test

#endif  // CRIMSON_TESTS_NET_SCRIPTED_STREAM_H
