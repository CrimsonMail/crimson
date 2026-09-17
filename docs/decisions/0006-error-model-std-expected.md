# ADR 0006 — Use std::expected for recoverable failures

Status: Accepted
Date:   2026-09-18

## Context

A mail client fails constantly and normally. Servers refuse connections, networks
disappear mid-sync, certificates expire, tokens go stale, messages arrive
malformed. None of these are bugs; they are ordinary states the client must
handle and report.

Crimson needed one error philosophy before the first networking line was
written, because retrofitting one across protocol, storage and interface layers
is a rewrite.

## Decision

Recoverable failures are returned as `std::expected<T, E>`. Exceptions are
reserved for allocation failure and genuine programmer error.

The transport layer's error type is `crimson::net::NetError`: a trivially
copyable 8-byte aggregate carrying the native code, the operation that failed,
the category, and a retry classification.

Two conventions that matter more than the type:

**Never call `.value()`.** Its rvalue overload throws `bad_expected_access`,
which reintroduces exceptions through the back door. Use `operator*`, which does
not throw.

**The transport API is `noexcept`.** This is honest rather than decorative:
`NetError` is trivially copyable, `TcpStream`'s move is `noexcept`, and nothing
on those paths allocates. An escaped exception is therefore a hard crash rather
than a silently broken contract.

`NetError` carries a `Retry` enum rather than a `bool retryable`, because one
bool is too coarse. `WSAEWOULDBLOCK` and `WSAECONNREFUSED` are both "retryable"
and mean entirely different things: poll this same socket again, versus abandon
this address and try another. Collapsing them forces every caller to re-derive
the difference from the native code, which defeats the point of a structured
error. The four values are `no`, `same_socket`, `new_connection` and
`new_candidate`; the connector's address failover is built directly on the last
one.

## Alternatives considered

**Exceptions.** Terser at call sites and no error-channel plumbing for move-only
types. Rejected because network failure is control flow here, not an exceptional
condition. The connect loop tries each resolved address in turn and records why
each failed; with exceptions that becomes try/catch inside a loop, which reads
badly and reverses the usual cost model by making the common path expensive.

**A hand-rolled `Result<T>`.** Full control over the shape, and portable to any
compiler. Rejected because it means writing and testing `and_then`, `transform`,
move semantics and reference handling — real work that is not email, to arrive
at something the standard already provides. C++23 is already a project
requirement (ADR 0001).

**Error codes with out-parameters.** Cheap and C-like, and easy to ignore. The
`[[nodiscard]]` on `std::expected` means a dropped error is a compiler warning,
which under `/WX` is a build failure.

## Consequences

- Requires `/std:c++latest` on MSVC, since `<expected>` is gated behind
  `_HAS_CXX23`. Already implied by ADR 0001.
- Every fallible call site is visibly fallible. More verbose than exceptions,
  and the verbosity is the feature.
- `std::expected` is move-only when `T` is, which suits `TcpStream` exactly.
- Errors must be captured immediately on the failure path, before any cleanup
  call, because `WSAGetLastError` is the shared Win32 last-error slot. That
  discipline is a consequence of this model and is enforced by review.
- Higher layers will need their own domain error types. `NetError` deliberately
  stops at the transport boundary and carries its native code as a plain `int`
  so it does not drag the Windows SDK upward.
