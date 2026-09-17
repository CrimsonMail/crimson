# ADR 0009 — Cancel blocked I/O with CancelIoEx under a mutex

Status: Accepted
Date:   2026-09-18

## Context

Crimson's workers block. A sync worker sits in `recv` waiting for an IMAP
response; with IDLE it will sit there for up to 29 minutes. Meanwhile the user
quits the application, disables an account, or cancels a sync, and something has
to wake that thread.

Step 1 does not need a full cancellation framework, but it must not foreclose
one — an API with no interruption point at all is a rewrite later.

The mechanisms were measured rather than assumed, because the usual advice turns
out to be wrong on Windows.

## Decision

A copyable `CancelHandle` sharing a `CancelState` that holds a mutex, the socket
descriptor, and an atomic flag. `cancel()` sets the flag and then, under the
mutex, calls `CancelIoEx(handle, nullptr)`.

**The rule this establishes:** `closesocket` is called only by the thread owning
the stream. Any other thread may only call `cancel()`.

### What was measured

| Mechanism | Result |
|---|---|
| `shutdown(fd, SD_BOTH)` from another thread | **Does not work.** Returned success; the blocked `recv` kept waiting and returned only when the peer closed 6 s later |
| `CancelIoEx(handle, nullptr)` | **Works.** Blocked `recv` returned `WSAEINTR` after 212 ms — the 200 ms the canceller waited |
| Short `SO_RCVTIMEO` plus flag polling | Works, 213 ms |

`shutdown` is the mechanism most sources recommend and the one the POSIX habit
suggests. On Windows it simply does not interrupt a blocked `recv`. Crimson's
first implementation was built on that assumption and its cancellation test
failed, taking 4,013 ms instead of ~100 ms.

### Why not the other two

`closesocket` does cancel pending calls, and is genuinely dangerous here. The
descriptor becomes immediately available for reuse, so another thread calling
`socket()` or `accept()` can be handed the same numeric value while the first
thread is still blocked in `recv` on it. That is silent cross-connection data
corruption rather than a crash — in a mail client, one account's bytes arriving
on another account's stream.

Short `SO_RCVTIMEO` with flag polling works and needs no cross-thread socket
call at all, which is genuinely attractive. Rejected on power: a 200 ms slice
means five wakeups per second per connection. With IMAP IDLE holding connections
open for tens of minutes across several accounts, that is a meaningful battery
cost on a laptop for a client that is, by design, doing nothing.

### Why the mutex

It is the correctness argument, not a detail. `cancel()` holds it across the
`CancelIoEx`, and `TcpStream::close()` holds it while clearing the descriptor.
A cancel therefore can never be issued against a handle the owner has already
closed and Windows has already reassigned.

## Consequences

- **A known, narrow race remains.** `CancelIoEx` only cancels operations already
  pending. If a cancel lands between a reader checking the flag and entering
  `recv`, there is nothing to cancel and the read blocks until `SO_RCVTIMEO`
  expires. Readers check the flag immediately before and after the call to
  narrow the window to a few instructions. Closing it entirely requires
  overlapped I/O, which Step 1 scopes out; the bound meanwhile is
  `ConnectOptions::read_timeout`, 60 s by default.
- A cancelled read surfaces as `WSAEINTR` or `WSA_OPERATION_ABORTED`, both
  translated to `NetCat::cancelled` so callers need not know which.
- `SO_RCVTIMEO` is still set as a safety net, so no thread blocks forever if a
  cancel is missed or a middlebox blackholes an idle connection.
- `SO_SNDTIMEO` is deliberately never set. A timed-out blocking `send` leaves
  the connection in a documented indeterminate state, with an unknown number of
  bytes transferred — unrecoverable for `write_all`, which must know where to
  resume.
- `connect` is cancelled differently, by re-checking the flag between short
  `WSAPoll` slices, since there is no pending socket operation to cancel during
  address racing. Latency there is bounded by the 200 ms slice.
- `cancel.h` keeps `CancelState` incomplete and passes descriptors as
  `std::uintptr_t`, so it needs no Windows headers and a future sync worker in
  `core/` can hold a handle without depending on Winsock.
- A test asserts that a cancel unblocks a blocked read within 1.5 s. If this
  behaviour ever regresses — a future Windows build, a layered service provider
  — it fails there rather than as a frozen window in front of a user.
