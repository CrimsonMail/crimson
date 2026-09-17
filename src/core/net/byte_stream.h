// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef CRIMSON_CORE_NET_BYTE_STREAM_H
#define CRIMSON_CORE_NET_BYTE_STREAM_H

#include <cstddef>
#include <expected>
#include <span>

#include "core/net/net_error.h"

// The seam the rest of Crimson is written against. TcpStream implements it now;
// TlsStream will implement it in Step 2, holding a unique_ptr<ByteStream> so
// the Schannel record layer can be tested against an in-memory replay stream
// with no socket and no network. Protocol code above this never learns which
// it is talking to.
//
// A runtime interface rather than a template. A virtual call costs a couple of
// nanoseconds against a syscall costing microseconds, so the dispatch is free
// in practice, while a template would push the IMAP tokenizer and MIME parser
// into headers and leak TlsStream<TcpStream> upward through every layer that
// touches a connection. See ADR 0007.
//
// Note that inheriting from this does not imply heap allocation: TcpStream is a
// concrete value, moved out of its factory by std::expected.

namespace crimson::net {

// The result of a successful read.
//
// EOF lives in the value channel rather than being signalled by a zero return,
// because Step 2 needs to express "here are N bytes AND the peer is done":
// Schannel's DecryptMessage can return application data together with
// SEC_I_CONTEXT_EXPIRED (TLS close_notify) from one input buffer. With the
// recv() convention of 0-means-EOF, TlsStream would have to hide a pending_eof
// flag and fabricate an extra round trip.
//
// It also removes an unstated precondition: recv(s, buf, 0) legitimately
// returns 0, so under the 0-means-EOF convention an empty destination buffer
// looks exactly like a closed connection. Here {0, false} is a well-formed
// "nothing happened".
struct ReadResult {
    std::size_t bytes = 0;
    bool eof = false;
};

using ReadOutcome = std::expected<ReadResult, NetError>;
using WriteOutcome = std::expected<std::size_t, NetError>;
using VoidOutcome = std::expected<void, NetError>;

class ByteStream {
public:
    virtual ~ByteStream() = default;

    ByteStream(const ByteStream&) = delete;
    ByteStream& operator=(const ByteStream&) = delete;

    // Reads into `dst`, blocking until at least one byte arrives, the peer
    // closes, or the operation fails.
    //
    // Contract, which read_exactly() and write_all() rely on: if `dst` is
    // non-empty, an implementation never returns {0, false}. It returns bytes,
    // or eof, or an error. A blocking stream that returned "no bytes, not
    // finished, no error" would make every helper loop spin, so the helpers
    // treat it as NetCat::logic rather than looping forever.
    //
    // `bytes` and `eof` are not mutually exclusive.
    [[nodiscard]] virtual ReadOutcome read(std::span<std::byte> dst) noexcept = 0;

    // Attempts one write. May transfer fewer bytes than requested; that is
    // normal and not an error. Callers that need the whole buffer delivered use
    // write_all() from stream_helpers.h rather than reimplementing the loop.
    [[nodiscard]] virtual WriteOutcome write_some(std::span<const std::byte> src) noexcept = 0;

    // Signals "no more data from this side" and keeps receiving.
    //
    // This is the first half of an orderly close: shutdown_send(), then read to
    // EOF, then close(). Skipping the drain and calling close() with unread
    // data in the receive buffer makes Windows send an RST, which aborts the
    // connection and can discard data the peer has not read yet.
    [[nodiscard]] virtual VoidOutcome shutdown_send() noexcept = 0;

    // Releases the underlying resource. Idempotent, and safe to call after a
    // failure. Must only be called by the thread that owns the stream.
    virtual void close() noexcept = 0;

protected:
    ByteStream() = default;
    ByteStream(ByteStream&&) noexcept = default;
    ByteStream& operator=(ByteStream&&) noexcept = default;
};

}  // namespace crimson::net

#endif  // CRIMSON_CORE_NET_BYTE_STREAM_H
