// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef CRIMSON_TESTS_NET_FRAGMENTING_STREAM_H
#define CRIMSON_TESTS_NET_FRAGMENTING_STREAM_H

#include <algorithm>
#include <cstddef>
#include <memory>
#include <vector>

#include "core/net/byte_stream.h"

// A ByteStream that sits between two others and chops traffic into tiny
// pieces.
//
//     TlsStream  ->  FragmentingStream (1 byte per read)  ->  TcpStream  ->  server
//
// This is why TlsStream holds a unique_ptr<ByteStream> rather than a TcpStream:
// any stream can go underneath it. With one byte per read, every TLS record —
// including every handshake message — arrives split across hundreds of reads,
// which drives the SEC_E_INCOMPLETE_MESSAGE and SECBUFFER_EXTRA handling
// through its full length against a genuine server and a genuine handshake.
// Over an ordinary connection the network delivers whole records almost every
// time, and those paths would barely run.
//
// It can also record what is written through it after a chosen moment, so a
// test can inspect the actual TLS records TlsStream produced.

namespace crimson::test {

class FragmentingStream final : public crimson::net::ByteStream {
public:
    // A chunk size of 0 means "pass through unchanged".
    FragmentingStream(std::unique_ptr<crimson::net::ByteStream> inner, std::size_t read_chunk,
                      std::size_t write_chunk = 0)
        : inner_(std::move(inner)), read_chunk_(read_chunk), write_chunk_(write_chunk) {}

    crimson::net::ReadOutcome read(std::span<std::byte> dst) noexcept override {
        ++reads_;
        if (read_chunk_ != 0 && dst.size() > read_chunk_) {
            dst = dst.first(read_chunk_);
        }
        auto result = inner_->read(dst);
        if (result) {
            bytes_read_ += result->bytes;
        }
        return result;
    }

    crimson::net::WriteOutcome write_some(std::span<const std::byte> src) noexcept override {
        ++writes_;
        if (write_chunk_ != 0 && src.size() > write_chunk_) {
            src = src.first(write_chunk_);
        }
        auto result = inner_->write_some(src);
        if (result && capturing_) {
            try {
                captured_.insert(captured_.end(), src.begin(),
                                 src.begin() + static_cast<std::ptrdiff_t>(*result));
            } catch (...) {
                capture_failed_ = true;
            }
        }
        return result;
    }

    crimson::net::VoidOutcome shutdown_send() noexcept override { return inner_->shutdown_send(); }
    void close() noexcept override { inner_->close(); }

    // Record everything written from now on.
    void start_capture() {
        captured_.clear();
        capturing_ = true;
    }

    [[nodiscard]] std::size_t reads() const noexcept { return reads_; }
    [[nodiscard]] std::size_t writes() const noexcept { return writes_; }
    [[nodiscard]] std::size_t bytes_read() const noexcept { return bytes_read_; }
    [[nodiscard]] const std::vector<std::byte>& captured() const noexcept { return captured_; }
    [[nodiscard]] bool capture_failed() const noexcept { return capture_failed_; }

private:
    std::unique_ptr<crimson::net::ByteStream> inner_;
    std::size_t read_chunk_;
    std::size_t write_chunk_;
    std::size_t reads_ = 0;
    std::size_t writes_ = 0;
    std::size_t bytes_read_ = 0;
    bool capturing_ = false;
    bool capture_failed_ = false;
    std::vector<std::byte> captured_;
};

}  // namespace crimson::test

#endif  // CRIMSON_TESTS_NET_FRAGMENTING_STREAM_H
