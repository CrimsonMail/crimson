# Crimson Networking Guide

The transport layer: what it provides, the rules it enforces, and why it is
shaped the way it is.

This layer knows nothing about email. It resolves names, opens TCP connections
and moves bytes. No IMAP, no SMTP, no message parsing appears anywhere below
`src/protocols/`.

---

## Layering

```
        IMAP / SMTP / JMAP          (later steps)
                 |
                 v
          crimson::net::ByteStream  <- the seam everything above is written to
                 |
        +--------+--------+
        v                 v
     TcpStream        TlsStream     (Step 2)
                          |
                          v
                      TcpStream
```

`ByteStream` has four methods: `read`, `write_some`, `shutdown_send`, `close`.
`write_all`, `read_exactly` and `read_to_eof` are free functions over it, so
there is exactly one partial-write loop in the codebase and `TlsStream` inherits
it rather than reimplementing it.

The split between `src/core/net/` and `src/platform/windows/net/` is enforced by
the build, not by convention: `Crimson.Core` does not link
`Crimson.Platform.Windows`, so core code physically cannot reach Winsock.
`byte_stream.h` and `net_error.h` include no Windows headers at all, which is
what will let the IMAP tokenizer and its tests compile without the Windows SDK.

See [ADR 0007](../decisions/0007-byte-stream-abstraction.md) for why this is a
runtime interface and not a template.

---

## Ownership rules

**One socket, one owner.** `SocketHandle` is move-only and closes on
destruction. Move-assignment closes the existing socket first — the case that
otherwise leaks invisibly until the process runs out of handles.

**`closesocket` belongs to the owning thread, and to no one else.** This is the
most important rule in the layer. A descriptor closed while another thread is
blocked on it becomes immediately available for reuse, and that thread can end
up reading an unrelated connection. In a mail client that means one account's
bytes arriving on another account's stream: silent corruption, not a crash.

**Any other thread may only call `cancel()`.** `CancelHandle` is copyable and
safe from anywhere. It holds a mutex across its `CancelIoEx` call, and
`TcpStream::close()` holds the same mutex while clearing the descriptor, so a
cancel can never reach a handle the owner has already closed.

---

## Threading rules

**One connection is owned and used by one thread at a time.** Reads and writes
are not internally synchronized and concurrent calls are not supported. The
single exception is `CancelHandle`.

**Network work never runs on the UI thread.** Nothing in Step 1 enforces this
yet because there is no interface, but the API is built for it: every call is
blocking and bounded, and intended for a worker.

---

## Timeouts and deadlines

| Setting | Default | Why |
|---|---|---|
| `attempt_delay` | 250 ms | RFC 8305 Connection Attempt Delay; the stagger between overlapping attempts |
| `candidate_timeout` | 5 s | Long enough for a slow mobile link, short enough to retire a blackholed address |
| `overall_timeout` | 20 s | A name with many addresses cannot compound into minutes |
| `read_timeout` (`SO_RCVTIMEO`) | 60 s | Safety net, not a protocol deadline; nothing blocks forever |
| write timeout | **never set** | A timed-out blocking `send` leaves the connection in an indeterminate state with an unknown number of bytes transferred, which `write_all` cannot resume from |

`TCP_NODELAY` is on by default. Mail protocols are request-response with small
commands, exactly the shape Nagle's algorithm and delayed ACK combine to punish,
costing up to ~200 ms per command. `SO_KEEPALIVE` is off until IMAP IDLE needs
it.

---

## Diagnostics

Structured `key=value` lines on stderr:

```
component=net level=info event=dns_resolved host=example.com port=80 candidates=4 elapsed_ms=12
component=net level=info event=tcp_connected host=example.com address=172.66.147.243 family=ipv4 port=80 winner=2 started=3 candidates=4 elapsed_ms=522
```

**Metadata only. Never payload bytes.** Step 1 has no secrets to leak, which is
exactly why the rule is set now: this same layer will shortly carry `LOGIN`
commands, bearer tokens and message bodies. Raw protocol tracing, when it
arrives, is a separate subsystem with explicit redaction, not a flag on this one.

---

## Measured Windows behaviour

Assumptions that turned out to be wrong, kept here so they are not re-assumed.
All measured on Windows 11 25H2, build 26200.

| Claim | Reality |
|---|---|
| `shutdown(SD_BOTH)` from another thread unblocks a blocked `recv` | **False.** Returns success and does nothing; the read returned only when the peer closed 6 s later |
| `CancelIoEx(handle, nullptr)` unblocks a blocked `recv` | True — returned `WSAEINTR` after 212 ms |
| A refused loopback connection is instant | **False.** ~2,030 ms, uniformly across ports 1, 9, 47821 and 59999 |
| `WSAPoll` reports a failed connect | True on this build — `revents = POLLWRNORM｜POLLERR｜POLLHUP` |
| `$(DefaultPlatformToolset)` selects the newest MSVC | **False** on VS 2026; it does not exist there, and the fallback resolves to `v100` |

---

## Answers to the Step 1 review questions

**1. Why does Winsock require startup and cleanup?**
`WSAStartup` negotiates a version with the provider and initializes per-process
state; `WSACleanup` releases it. The calls are reference counted, which is why
Crimson has exactly one `WinsockScope` in `main` rather than one per connection:
the final `WSACleanup` invalidates every socket in the process, so a connection
closing must not be able to trigger it. It is also not a function-local static,
which would be destroyed during exit while a detached worker might still be in
`recv`.

**2. Why is a socket wrapper useful?**
It makes closing automatic and unforgettable. The connect path creates a socket
per attempt and abandons most of them; with raw `SOCKET` values, every early
return is a potential leak. It also encapsulates two Windows details that
produce quiet bugs — see questions 3 and 4.

**3. Why movable but not copyable?**
Copying would mean two objects each believing they must close the same
descriptor, giving a double close — which, given how fast Windows recycles
descriptors, can close someone else's socket. Move expresses the truth: there is
one owner, and it can be transferred.

**4. `INVALID_SOCKET` versus `SOCKET_ERROR`?**
`INVALID_SOCKET` is `(SOCKET)~0`, returned by `socket`/`WSASocketW`/`accept`
when no socket could be created. `SOCKET_ERROR` is `-1`, returned by operations
on an existing socket such as `connect`, `recv` and `send`. They are routinely
interchanged. Note also that `SOCKET` is `UINT_PTR` — unsigned — so the POSIX
habit of testing `fd < 0` is always false.

**5. How does `WSAGetLastError` fit in?**
It *is* `GetLastError`: one per-thread Win32 slot, not a separate Winsock one.
Any intervening Win32 or CRT call can overwrite it, including `closesocket` in a
cleanup path, a logging call, or an allocation. Crimson therefore captures it
into a `NetError` as the first statement of every failure path, and `net_log`
saves and restores it across each call as a second line of defence.

**6. Why `getaddrinfo` (here, `GetAddrInfoW`) instead of hardcoding IPv4?**
Because IPv6 exists and a mail client cannot decide its users' networks. The
wide version additionally performs IDN-to-punycode encoding, which is needed the
first time somebody has an account at a host like `müller.de`. It also returns
the system's preferred ordering, which reflects policy Crimson should not
second-guess.

**7. Why does one hostname resolve to several addresses?**
Load balancing, geographic distribution, redundancy, and dual-stack. Large mail
providers return many; `example.com` returns four.

**8. What happens if the first address cannot connect?**
Crimson does not wait to find out. Attempts are overlapped: the next address
starts 250 ms after the previous without abandoning it, and the first to connect
cleanly wins. Sequential iteration measured 10.3 s on a host with broken IPv6;
overlapping measured ~520 ms. See
[ADR 0008](../decisions/0008-overlapped-connection-attempts.md).

**9. Why can `send` write fewer bytes than requested?**
The socket send buffer is finite. Once it fills, the kernel accepts what fits
and reports that count. The belief that a blocking `send` is all-or-nothing is
false — non-paged pool pressure and very large buffers both produce short
writes. `write_all` loops so no protocol code has to care.

**10. What does `recv` returning zero mean?**
The peer performed an orderly shutdown: it sent FIN and will send no more. It is
not an error, and it is not the same as a reset. Crimson reports it as
`ReadResult{0, true}` — a *successful* read that happens to carry end of stream.

**11. Why are TCP read boundaries meaningless to IMAP?**
TCP guarantees ordered bytes and says nothing about grouping. One `recv` can
return half a response, three responses, or the tail of one and the head of the
next. A parser that treats a read boundary as a message boundary works on a
quiet local network and fails in production. This is why the tokenizer in Step 3
must be incremental, and why the test suite includes a server that delivers a
reply one byte at a time.

**12. Why does retry policy live above the socket layer?**
Because the right policy depends on what is being attempted. An interactive
fetch should fail fast so the user sees something; a background sync should back
off; an SMTP submission must not blindly retry at all, because a message the
server accepted before the connection dropped would be delivered twice.
`TcpStream` reports what happened, with a `Retry` classification as advice, and
the caller decides. Hidden retries inside the transport would be invisible and
wrong for most callers.

**13. Why keep blocking network work off the UI thread?**
A 20 s connect on the UI thread is a 20 s frozen window. Windows will offer to
kill the application. Interface threads must stay responsive, so all network
work belongs on workers that publish events.

**14. What owns the socket at every point?**
`WSASocketW` returns a raw descriptor that is adopted by a `SocketHandle`
immediately. During the connect race each pending attempt owns its own
`SocketHandle`; losers are closed when the vector is cleared. The winner's
handle is moved into the `TcpStream`, which owns it until destruction.
`CancelState` holds a *copy of the value* under a mutex — never ownership — and
`close()` clears that copy before closing, so the two can never collide.

**15. What will TLS wrap in Step 2?**
`TlsStream` implements the same `ByteStream` interface and holds a
`std::unique_ptr<ByteStream>`, so it wraps `TcpStream` without either knowing
about the other. Protocol code above changes not at all. The `unique_ptr` rather
than a concrete member is deliberate: it lets the Schannel record layer be
tested against an in-memory replay stream with no socket and no network. The
`ReadResult{bytes, eof}` shape exists for the same step, because
`DecryptMessage` can return application data and close_notify together.

---

## What this layer deliberately does not do

No TLS, no protocol parsing, no HTTP, no proxies, no UDP, no DNS caching, no
connection pooling, no IOCP, no thread pool, no retry policy, no telemetry.

The operating system already caches DNS; a second cache would immediately raise
questions about TTLs, negative caching, VPN transitions and Wi-Fi changes for no
benefit. Connection pooling and IOCP are performance work that no measurement
has yet asked for.

The test for whether this layer is finished is not whether it is complete in
some abstract sense. It is whether Schannel can wrap it without redesign.
