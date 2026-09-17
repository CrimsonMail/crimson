// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef CRIMSON_CORE_NET_STREAM_HELPERS_H
#define CRIMSON_CORE_NET_STREAM_HELPERS_H

#include <cstddef>
#include <span>
#include <vector>

#include "core/net/byte_stream.h"

// Free functions rather than ByteStream members, deliberately.
//
// Keeping the vtable at four methods means TlsStream implements four things and
// inherits these for free, so there is exactly one partial-write loop in
// Crimson and no implementation can get it subtly wrong. A fake stream for
// tests likewise implements four methods, not seven.

namespace crimson::net {

// Writes the whole buffer, looping over partial writes.
//
// The reason this exists at all: send() may accept fewer bytes than requested,
// including on a blocking socket. The folklore that a blocking send is
// all-or-nothing is false, and protocol code must never have to care. IMAP can
// hand over "A001 CAPABILITY\r\n" and rely on all of it arriving.
[[nodiscard]] VoidOutcome write_all(ByteStream& stream,
                                    std::span<const std::byte> src) noexcept;

// Fills the whole buffer, looping over short reads.
//
// A peer that closes before the buffer is full yields NetCat::truncated, which
// is what an IMAP literal ("{4281}" followed by exactly 4281 bytes) needs: a
// short read there is a protocol failure, not a normal end of stream.
[[nodiscard]] VoidOutcome read_exactly(ByteStream& stream,
                                       std::span<std::byte> dst) noexcept;

// Reads until the peer closes, appending into `out`.
//
// Returns the total byte count, and whether EOF was genuinely reached: if
// `eof` is false the `max_bytes` cap stopped the read early, which the caller
// can distinguish rather than guess at.
//
// Not noexcept, because it grows `out`. Every other helper here is
// allocation-free and therefore noexcept.
[[nodiscard]] ReadOutcome read_to_eof(ByteStream& stream,
                                      std::vector<std::byte>& out,
                                      std::size_t max_bytes);

}  // namespace crimson::net

#endif  // CRIMSON_CORE_NET_STREAM_HELPERS_H
