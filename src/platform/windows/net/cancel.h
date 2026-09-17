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
// WHY CancelIoEx. The obvious candidates were measured rather than assumed,
// because the folklore here is wrong:
//
//   shutdown(fd, SD_BOTH) from another thread DOES NOT WORK on Windows. This is
//   the advice usually given, and it is what the POSIX habit suggests, but it is
//   simply untrue here: measured, shutdown returns success and the blocked recv
//   keeps waiting, returning only when the peer eventually closes 6 seconds
//   later. It interrupts nothing.
//
//   closesocket() does cancel pending calls, and is unsafe. The SOCKET value
//   becomes immediately available for reuse, so another thread calling socket()
//   or accept() can be handed the same numeric value while the first thread is
//   still blocked in recv on it. That is silent cross-connection data
//   corruption rather than a crash — in a mail client, one account's bytes
//   arriving on another account's stream.
//
//   CancelIoEx(handle, nullptr) works. Measured: the blocked recv returns
//   WSAEINTR after ~212 ms, which is the 200 ms the canceller waited. It
//   cancels pending operations without releasing the descriptor, so there is no
//   reuse window.
//
// The mutex is still the correctness argument. cancel() holds it across the
// CancelIoEx and TcpStream::close() holds it while clearing the descriptor, so
// the cancel can never be issued against a handle the owner has already closed
// and Windows has already handed to someone else. The rule that falls out of
// this, and which the rest of Crimson must honour:
//
//     closesocket is called only by the thread that owns the stream.
//     Any other thread may only call cancel().
//
// KNOWN RACE. CancelIoEx only cancels operations that are already pending. If a
// cancel lands in the window between a reader checking the flag and actually
// entering recv, there is nothing to cancel and the read blocks until the
// SO_RCVTIMEO safety net expires. The window is a few instructions wide, and
// readers check the flag immediately before and after the call to narrow it
// further. Eliminating it entirely needs overlapped I/O, which Step 1 scopes
// out; the bound in the meantime is ConnectOptions::read_timeout.
//
// Connect is handled differently again: it re-checks cancel_requested() between
// short WSAPoll slices, so it needs no socket-level interruption at all.

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

// Atomically removes the descriptor and returns it, so the caller can close it
// knowing cancel() can no longer see it. Returns the invalid-socket sentinel if
// it was already taken.
[[nodiscard]] std::uintptr_t take_cancel_socket(CancelState& state) noexcept;

}  // namespace detail

}  // namespace crimson::net::win

#endif  // CRIMSON_PLATFORM_WINDOWS_NET_CANCEL_H
