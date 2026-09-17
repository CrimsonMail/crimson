// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef CRIMSON_PLATFORM_WINDOWS_NET_CANCEL_H
#define CRIMSON_PLATFORM_WINDOWS_NET_CANCEL_H

#include <cstdint>
#include <memory>

// Interrupting a connection from another thread.
//
// Step 1 does not need a full cancellation framework, but it must not foreclose
// one. When a user quits Crimson or cancels a sync, a worker may be parked in a
// blocking recv or partway through a 20-second connect, and something has to
// wake it.
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
//   corruption rather than a crash, and in a mail client it means one account's
//   bytes arriving on another account's stream.
//
// So cancel() holds a mutex across the shutdown, and TcpStream::close() holds
// the same mutex while clearing the descriptor. shutdown can therefore never
// fire on a recycled handle. The rule that falls out of this, and which the rest
// of Crimson must honour:
//
//     closesocket is called only by the thread that owns the stream.
//     Any other thread may only call cancel().
//
// Connect is a separate problem, because shutdown does not reliably interrupt a
// pending connect(). A handle can be created before connecting and passed to
// TcpStream::connect, which re-checks cancel_requested() between short WSAPoll
// slices; see connect_with_deadline in tcp_stream.cpp.

namespace crimson::net::win {

// Defined in cancel.cpp. Left incomplete here so this header needs no Windows
// headers, which means a future sync worker in core/ can hold a CancelHandle
// without acquiring a dependency on Winsock.
struct CancelState;

// A copyable, thread-safe token for interrupting one connection.
//
// Cheap to copy and safe to call from any thread, including after the stream has
// been closed, in which case cancel() is a no-op. A default-constructed handle
// is inert, so code that does not care about cancellation can ignore it
// entirely.
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

    // For the platform implementation. CancelState is incomplete outside
    // cancel.cpp, so this is inert to any other caller.
    [[nodiscard]] const std::shared_ptr<CancelState>& state() const noexcept {
        return state_;
    }

private:
    std::shared_ptr<CancelState> state_;
};

// Creates a handle that is not yet bound to a socket.
//
// Intended to be created before connecting, so a controlling thread can cancel
// an in-flight connect:
//
//     const CancelHandle cancel = make_cancel_handle();
//     // hand `cancel` to the UI, then on this thread:
//     auto stream = TcpStream::connect(endpoint, options, cancel);
[[nodiscard]] CancelHandle make_cancel_handle();

namespace detail {

// Socket descriptors cross this boundary as uintptr_t rather than SOCKET, which
// keeps the header free of Windows types. SOCKET is UINT_PTR, so the
// representation is exact rather than a lossy reinterpretation.

// Binds a socket to the handle so cancel() can reach it.
//
// Returns false if cancellation was already requested, which lets the connect
// loop abandon a socket it has only just created instead of waiting out the
// deadline on a connection nobody wants any more.
[[nodiscard]] bool attach_cancel_socket(CancelState& state,
                                        std::uintptr_t socket) noexcept;

// Unbinds without closing, for a candidate socket that failed to connect. The
// caller still owns and must close the descriptor.
void detach_cancel_socket(CancelState& state) noexcept;

// Atomically removes the descriptor and returns it, so the caller can close it
// knowing cancel() can no longer see it. Returns the invalid-socket sentinel if
// it was already taken.
[[nodiscard]] std::uintptr_t take_cancel_socket(CancelState& state) noexcept;

}  // namespace detail

}  // namespace crimson::net::win

#endif  // CRIMSON_PLATFORM_WINDOWS_NET_CANCEL_H
