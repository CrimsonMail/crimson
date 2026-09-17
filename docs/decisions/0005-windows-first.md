# ADR 0005 — Windows first, portability preserved

Status: Accepted
Date:   2026-09-18

## Context

Crimson needs to pick a platform. [ADR 0004](0004-no-third-party-mail-libraries.md)
rules out cross-platform frameworks, so there is no Qt to make one codebase run
everywhere — each platform means native interface and platform code.

Attempting three platforms at once with one developer means three shallow
implementations. Hard-coding Windows assumptions throughout, however, means a
rewrite if Crimson is ever ported.

## Decision

Target **Windows 11 x64 first**, and keep the portable core free of platform
types.

The core depends on narrow interfaces; the platform layer implements them:

```
src/core/          ByteStream, Storage, SecureStore, Clock   (portable)
src/platform/windows/
                   TcpStream / TlsStream   (Winsock + Schannel)
                   EseStorage              (ESE)
                   DpapiSecureStore        (DPAPI)
                   Win32 shell             (Win32 + Direct2D + DirectWrite)
```

Two rules make this real rather than aspirational:

1. **No Windows headers in core.** `<winsock2.h>` and `<windows.h>` appear only
   behind `src/platform/`. Core types carry native error codes as plain `int`,
   never as SDK typedefs, so core headers stay SDK-free and can be compiled and
   tested without the Windows SDK.
2. **The dependency direction is enforced by the build, not by review.**
   `Crimson.Core` does not link `Crimson.Platform.Windows`, so core code
   physically cannot reach Winsock. A convention would erode; a link error does
   not.

This is deliberately *not* a portability abstraction layer. Nothing is
generalized speculatively. The interfaces exist because the core needs them, and
they happen to be implementable elsewhere.

## Alternatives considered

**Cross-platform from day one.** Triples the platform work for a single
developer and would leave all three implementations weak.

**Windows-only with no seam.** Faster in the short term. Winsock calls in the
IMAP session, `HWND` in domain types, ESE cursors in the sync engine — all
individually convenient, and collectively a rewrite. The seam costs little when
built from the start and is very expensive to retrofit.

**Electron or a web stack.** Instantly portable, and excluded by ADR 0004 —
also contrary to the goal of a native client with native performance.

## Consequences

- The interface and platform layers are rewritten per platform. Accepted: with
  no cross-platform framework, that work exists regardless.
- The mail engine — protocols, parsers, sync, threading, search — ports without
  modification, and that is the majority of Crimson's value.
- The core is testable against in-memory fakes rather than real sockets and
  databases, which makes protocol tests fast and deterministic. This benefit
  arrives immediately, long before any port.
- Each platform interface costs a little design effort up front to define
  properly.
- `platform/macos/` and `platform/linux/` remain genuinely possible without
  touching the engine. No commitment is made to building them.
