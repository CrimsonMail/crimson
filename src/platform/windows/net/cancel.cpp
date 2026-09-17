// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#include "platform/windows/net/cancel.h"

#include "platform/windows/net/win_sockets.h"

#include <atomic>
#include <mutex>

namespace crimson::net::win {

struct CancelState {
    // Serializes shutdown (from any thread) against closesocket (owner only).
    // This mutex is the entire correctness argument of this file: without it,
    // cancel() can call shutdown on a descriptor the owner has already closed
    // and Windows has already handed to someone else.
    std::mutex mutex;

    // Guarded by `mutex`. INVALID_SOCKET before a socket is attached and again
    // once the owner has taken it back.
    SOCKET socket = INVALID_SOCKET;

    // Readable without the mutex, so the connect loop can poll it cheaply
    // between WSAPoll slices.
    std::atomic<bool> requested{false};
};

CancelHandle make_cancel_handle() {
    return CancelHandle{std::make_shared<CancelState>()};
}

namespace detail {

bool attach_cancel_socket(CancelState& state, std::uintptr_t socket) noexcept {
    const std::lock_guard<std::mutex> guard{state.mutex};
    if (state.requested.load(std::memory_order_acquire)) {
        // Cancelled between creating the socket and attaching it. Report the
        // race so the caller abandons this candidate rather than connecting.
        return false;
    }
    state.socket = static_cast<SOCKET>(socket);
    return true;
}

void detach_cancel_socket(CancelState& state) noexcept {
    const std::lock_guard<std::mutex> guard{state.mutex};
    state.socket = INVALID_SOCKET;
}

std::uintptr_t take_cancel_socket(CancelState& state) noexcept {
    const std::lock_guard<std::mutex> guard{state.mutex};
    const SOCKET taken = state.socket;
    state.socket = INVALID_SOCKET;
    return static_cast<std::uintptr_t>(taken);
}

}  // namespace detail

void CancelHandle::cancel() const noexcept {
    if (state_ == nullptr) {
        return;
    }

    // Publish the flag first, so a connect loop polling between poll slices
    // observes the request even if no socket is currently attached.
    state_->requested.store(true, std::memory_order_release);

    const std::lock_guard<std::mutex> guard{state_->mutex};
    if (state_->socket != INVALID_SOCKET) {
        // Holding the mutex guarantees the owner is not concurrently inside
        // closesocket, so this descriptor is still ours and cannot have been
        // recycled. The return value is ignored deliberately: shutdown on an
        // already-reset connection fails with WSAENOTCONN, which is the normal
        // case when the peer got there first and is not worth reporting.
        ::shutdown(state_->socket, SD_BOTH);
    }
}

bool CancelHandle::cancel_requested() const noexcept {
    return state_ != nullptr && state_->requested.load(std::memory_order_acquire);
}

}  // namespace crimson::net::win
