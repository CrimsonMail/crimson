# ADR 0008 — Overlap connection attempts across resolved addresses

Status: Accepted
Date:   2026-09-18

## Context

A hostname usually resolves to several addresses across both families.
`imap.gmail.com` and `example.com` alike return a mix of AAAA and A records, and
the client has to pick one that works.

The obvious implementations both fail badly on a specific, very common network:
a host with a router-advertised IPv6 address but no working IPv6 route. This is
ordinary consumer Wi-Fi, and it is what the machine Crimson is being developed
on does. Such a host resolves AAAA records happily and then blackholes the SYN —
no refusal, no unreachable, just silence.

Measured on that machine, connecting to `example.com:80`:

| Approach | Time |
|---|---|
| Blocking connect | ~21 s per dead address (SYN at 0 s, 3 s, 9 s) |
| Sequential attempts, 5 s deadline each | **10,318 ms** |
| Overlapped attempts, 250 ms stagger | **~520 ms** |

`SO_SNDTIMEO` does not apply to `connect` on Windows, so a blocking connect
cannot be shortened after the fact.

## Decision

Implement RFC 8305 ("Happy Eyeballs v2"), which is what browsers and mature mail
clients do:

1. **Interleave by family.** The resolver's first address is kept first, since
   the system already applied its address-selection policy, and families
   alternate from there. A broken family cannot occupy every early slot.
2. **Stagger, do not serialize.** Each attempt starts one `attempt_delay`
   (250 ms, the RFC default) after the previous one, *without* abandoning those
   already pending.
3. **Race them.** All pending attempts are polled by a single `WSAPoll`. The
   first to complete cleanly wins; the rest are closed immediately.

Each attempt still carries its own deadline, because a blackholed SYN never
reports anything and would otherwise hold a slot until the overall deadline.
`max_in_flight` caps simultaneous attempts so a name with a long address list
cannot emit a burst of SYNs.

This needs no threads and no IOCP. The sockets were already non-blocking to
support deadlines; polling several instead of one is the natural extension, and
`connect` remains synchronous to its caller.

## Alternatives considered

**Blocking connect, accept the default.** Simplest, and unshippable: 21 s before
the first fallback.

**Sequential attempts with per-address deadlines.** This was the original plan
and it is a real improvement on blocking — it fixes the 21 s case. It does not
fix this one, because it still pays for every dead address in turn: measured
10.3 s. Rejected after measurement.

**`ConnectEx`.** Would work, and needs `WSAIoctl` to obtain the function pointer
per family, an explicit `bind` first, an `OVERLAPPED` with an event, and
`SO_UPDATE_CONNECT_CONTEXT` afterwards — without which `getpeername` and
`shutdown` misbehave. That is IOCP-shaped machinery for no benefit until
overlapped I/O is used throughout.

**Shortening the per-address deadline.** A one-line change that reaches ~3 s.
Rejected because the number is a guess applied to every network: short enough to
skip dead addresses is also short enough to abandon a slow but working mobile
link.

## Consequences

- Crimson opens more sockets than strictly necessary, briefly. On a healthy
  network the first attempt usually wins and the second never starts.
- A host with working IPv6 still prefers it, because the resolver's preferred
  address keeps its 250 ms head start.
- `getsockopt(SO_ERROR)` must be consulted for every socket the poll reports
  ready. A failed connect can surface as `POLLWRNORM` together with `POLLERR`
  and `POLLHUP`, so trusting `revents` alone yields a socket that looks
  connected and fails on the first `recv`.
- Losing and failed attempts must be closed promptly. Two tests assert the
  process handle count does not grow across repeated successful and failed
  connections.
- Cancellation during the race is handled by polling the flag between poll
  slices rather than by touching a socket, since the shared cancel state holds
  one descriptor. Only the winner is attached to it.
- A measured aside worth recording: a refused loopback connection on Windows
  takes about 2,030 ms, uniformly across ports. "Loopback refuses instantly" is
  false, and a test written on that assumption fails for reasons that have
  nothing to do with the code under test.
