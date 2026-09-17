// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef CRIMSON_PLATFORM_WINDOWS_NET_CANCEL_H
#define CRIMSON_PLATFORM_WINDOWS_NET_CANCEL_H

#include <cstdint>
#include <memory>

// Interrupting a worker blocked in recv, from another thread.
//
// Step 1 does not need full cancellation, but it must not foreclose it. When a
// user quits Crimson or cancels a sync, a worker may be parked in a blocking
// recv, and something has to wake it.
//
// WHY shutdown AND NOT closesocket. These look interchangeable and are not:
//
//   shutdown(fd, SD_BOTH) from another thread is the supported escape hatch.
//   The blocked recv returns promptly, with 0 or WSAESHUTDOWN. The descriptor
//   is not released, so it cannot be reused underneath the blocked call.
//
//   closesocket() while another thread is blocked on that socket is not safe.
//   Pending blocking calls are cancelled with no notification, AND the SOCKET
//   value becomes immediately available for reuse. Another thread calling
//   socket() or accept() can be handed the same numeric value, at which point
//   the blocked recv is reading an unrelated connection. That is silent data
//   corruption, not a crash, and in a mail client it means one account's bytes
//   arriving on another account's stream.
//
// So: cancel() holds a mutex across the shutdown, and TcpStream::close() holds
// the same mutex while clearing the descriptor. shutdown can therefore never
// fire on a recycled handle. The rule that falls out of this, and which the
// rest of Crimson must honour:
//
//     closesocket is called only by the thread that owns the stream.
//     Any other thread may only call cancel().
//
// Note that shutdown does NOT reliably interrupt a pending connect(). The
// connect path re-checks cancel_requested() between short WSAPoll slices
// instead; see tcp_stream.cpp.

namespace crimson::net::win {

// Defined in cancel.cpp. Left incomplete here so this header needs no Windows
// headers and a future sync worker in core/ can hold a CancelHandle without
// acquiring a dependency on Winsock.
struct CancelState;

namespace detail {

// Socket descriptors cross this boundary as uintptr_t rather than SOCKET,
// which keeps the header SDK-free. SOCKET is UINT_PTR, so this is exact and
// not a lossy reinterpretation.
[[nodiscard]] std::shared_ptr<CancelState> make_cancel_state(std::uintptr_t socket);

// Atomically removes the descriptor from the shared state and returns it, so
// the caller can close it knowing cancel() can no longer see it. Returns the
// invalid-socket sentinel if it was already taken.
[[nodiscard]] std::uintptr_t take_cancel_socket(CancelState& state) noexcept;

}  // namespace detail

// A copyable, thread-safe token for interrupting one connection.
//
// Cheap to copy and safe to call from any thread, including after the stream
// has been closed, in which case cancel() is a no-op. A default-constructed
// handle is inert.
class CancelHandle {
public:
    CancelHandle() noexcept = default;

    explicit CancelHandle(std::shared_ptr<CancelState> state) noexcept
        : state_(std::move(state)) {}

    // Requests cancellation and wakes a blocked read or write.
    //
    // Safe to call repeatedly and from any thread. Returns immediately; the
    // worker observes the interruption as an error or EOF from its next
    // completed call.
    void cancel() const noexcept;

    [[nodiscard]] bool cancel_requested() const noexcept;

    [[nodiscard]] bool valid() const noexcept { return state_ != nullptr; }

private:
    std::shared_ptr<CancelState> state_;
};

}  // namespace crimson::net::win

#endif  // CRIMSON_PLATFORM_WINDOWS_NET_CANCEL_H
