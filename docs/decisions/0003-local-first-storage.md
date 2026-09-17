# ADR 0003 — Local-first storage with a sync engine

Status: Accepted
Date:   2026-09-18

## Context

The straightforward way to build a mail client is to let the interface talk to
the mail server: open a folder, issue a `FETCH`, display the result. It is also
the decision that makes a client permanently slow and useless offline, and it
cannot be undone later without rewriting both the interface and the protocol
layer.

Server round-trips are tens to hundreds of milliseconds at best. Any interface
that waits on one feels broken, and an interface built on the assumption that
data is remote has no path to offline support.

## Decision

The interface **never** talks to a mail server. It reads a local store, and a
background sync engine keeps that store current.

```
UI
 │
 ▼
Local mail model
 │
 ▼
Local store  ◄──  Sync engine  ◄──  IMAP / SMTP
```

Consequences of this shape, which are the actual point:

- Opening a mailbox is a local query. It does not depend on the network.
- Every user action applies to the local store **first**, then enqueues a
  durable operation for the server. Marking a message read is instant and
  survives being offline.
- The local state change and the queued operation commit in **one transaction**
  (see [ADR 0002](0002-use-esent.md)). A crash between them would diverge the
  client from the server permanently.
- Sync workers publish typed events; the interface reacts to them. Protocol
  objects never reach the interface — `MailMessage` is a domain type, not an
  IMAP `FETCH` response.
- Retry policy lives in the sync engine, never in the transport. The transport
  reports what happened; the engine decides what to do about it.

## Alternatives considered

**Direct interface-to-server access.** Simpler to start, and the reason many
hand-written mail clients feel sluggish. Offline support cannot be retrofitted
onto it.

**Cache-on-read.** Fetch from the server, keep a copy for next time. Better, but
the first view of anything is still a network wait, and there is no coherent
answer for what a user action means while offline.

**Full mirror before use.** Downloading an entire account, bodies and
attachments included, before the client is usable is unacceptable for a mailbox
of any size. Metadata syncs first; bodies load lazily, newest first.

## Consequences

- Substantially more work up front: a store, a sync engine, an operation queue
  and conflict handling all exist before the first message is displayed.
- Conflicts become real and must be reasoned about. Flag changes usually merge;
  moves and deletes need explicit resolution.
- The store is the contract between the engine and the interface, which means
  schema changes ripple. This is the intended trade: a clear seam.
- Additional backends (JMAP, Microsoft Graph) can be added behind the sync
  engine without the interface noticing.
- The client stays usable when the network disappears, which is the whole
  purpose.
