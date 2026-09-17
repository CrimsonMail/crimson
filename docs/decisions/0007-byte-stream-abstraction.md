# ADR 0007 — A runtime ByteStream interface, with EOF in the value channel

Status: Accepted
Date:   2026-09-18

## Context

Everything above the transport — IMAP, SMTP, and eventually JMAP — should
consume bytes without knowing whether they arrive over a plain socket, a TLS
session, or a recorded fixture. That seam has to exist before TLS arrives in
Step 2, because retrofitting it afterwards means touching every protocol layer.

The question was its shape: a runtime interface, a compile-time template, or
hand-rolled type erasure. And separately, how a stream reports that the peer has
finished.

## Decision

A four-method abstract base class, `crimson::net::ByteStream`, with `read`,
`write_some`, `shutdown_send` and `close`.

`read` returns `ReadResult { std::size_t bytes; bool eof; }` in the value
channel rather than signalling end of stream with a zero return.

Helpers — `write_all`, `read_exactly`, `read_to_eof` — are non-virtual free
functions taking `ByteStream&`.

### Why a runtime interface

A virtual call costs a couple of nanoseconds against a syscall costing
microseconds, so the dispatch is free in any sense that matters. The template
alternative has real, compounding costs: `ImapSession`, `MimeParser` and every
layer holding a connection would become templates, the protocol code would move
into headers, and `TlsStream<TcpStream>` would propagate upward through every
signature. The interface layer must hold a connection whose type is decided at
runtime — plaintext against a test server, TLS against a real one — so it would
need type erasure regardless, meaning both mechanisms get paid for.

Hand-rolled type erasure is a worse `virtual` with more code to maintain.

Note that inheriting from `ByteStream` does not imply heap allocation:
`TcpStream` is a concrete value, moved out of its factory by `std::expected`.
`TlsStream` will hold a `std::unique_ptr<ByteStream>` so the Schannel record
layer can be exercised against an in-memory replay stream with no socket and no
network — one small allocation per connection, against a TLS handshake.

### Why EOF belongs in the value channel

The `recv` convention of "0 means the peer closed" cannot express *both* at
once, and Step 2 needs exactly that. Schannel's `DecryptMessage` can return
application data together with `SEC_I_CONTEXT_EXPIRED` (TLS close_notify) from a
single input buffer. Under the zero convention, `TlsStream` would have to hide a
`pending_eof` flag and fabricate an extra round trip to deliver information it
already had.

It also removes an unstated precondition: `recv(s, buf, 0)` returns zero
legitimately, so an empty destination buffer is indistinguishable from a closed
connection. With the struct, `{0, false}` is a well-formed "nothing happened".

EOF as a distinct *error* was rejected outright: it conflates normal termination
with failure, and discards the bytes-then-EOF case entirely.

### Why helpers are free functions

Keeping the vtable at four methods means `TlsStream` implements four things and
inherits the rest. There is exactly one partial-write loop in Crimson, so no
implementation can get it subtly wrong, and a fake stream for tests implements
four methods rather than seven.

## Alternatives considered

**`concept ByteStreamLike` plus templates.** Zero dispatch cost and full
inlining, neither of which is exploitable when every call is a syscall. Costs
described above. Deferring this loses nothing: a template helper can be added
later over the same concept if a hot path ever justifies it.

**Manual vtable struct (type erasure).** Value semantics with no visible
inheritance. Buys nothing here, since connections are heap-lived and long-lived
anyway, and costs hand-written machinery.

**`expected<size_t>` with 0 meaning EOF.** Familiar from `recv`, and this was
the original sketch. Rejected once the Schannel interaction was thought through.

## Consequences

- A blocking `read` must never return `{0, false}` on a non-empty buffer. That
  is now a documented part of the contract, and the helpers treat a violation as
  `NetCat::logic` rather than looping forever — a stalled stream fails loudly
  instead of spinning.
- `byte_stream.h` and `net_error.h` include no Windows headers, so protocol code
  and its fake-stream tests compile without the Windows SDK. This is what makes
  the eventual parser test suites portable.
- `ScriptedStream` in the test suite is a direct consequence: partial writes and
  short reads cannot be provoked reliably over loopback, so the fake is the only
  way to exercise those loops deterministically.
- `~ByteStream` must stay virtual, since `TlsStream` will own its inner stream
  polymorphically.
