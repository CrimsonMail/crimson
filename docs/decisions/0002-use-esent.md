# ADR 0002 — Use ESE/ESENT for local metadata

Status: Accepted
Date:   2026-09-18

## Context

Crimson needs a local transactional store for mail metadata: accounts,
mailboxes, message headers, UID mappings, flags, thread relationships, search
postings, sync state and the pending-operation queue.

The requirements are ordinary database requirements. Crash recovery matters
particularly: a local mailbox state change and the queued server operation that
corresponds to it must commit atomically, or the client can end up permanently
diverged from the server — a bug class that is very hard to diagnose after the
fact.

[ADR 0004](0004-no-third-party-mail-libraries.md) rules out bundling SQLite.

## Decision

Use **ESE (Extensible Storage Engine, `esent.dll`)** for metadata.

ESE ships with Windows and provides tables, columns, indexes, transactions,
write-ahead logging, crash recovery and cursor navigation. It is the engine
behind Windows Search and Active Directory, so it is well-proven at far larger
scale than a mail client needs.

Raw RFC 5322 messages and large body parts do **not** go in ESE. They live in a
separate content-addressed blob store on disk, with ESE holding the hashes. Mail
metadata is queried constantly and is small; message bodies are large, written
once and read rarely, and belong in files.

## Alternatives considered

**SQLite.** The obvious choice and a better API. Excluded by ADR 0004. Worth
noting that this is the decision most likely to be questioned, and the one where
the dependency rule costs the most in developer convenience.

**A custom B-tree store.** Writing a crash-safe transactional store with
write-ahead logging is a serious project, and getting durability subtly wrong
means silent mail loss. ADR 0004 draws the line at things whose failure modes
are unsafe rather than merely inconvenient; a storage engine is on the unsafe
side.

**Flat files with an index, or a Maildir-style layout.** Simple and inspectable,
but provides no transactions. The atomic "update local state and queue the
server operation" requirement is exactly what it cannot give.

## Consequences

- The ESE API is low-level, C-style and awkward, with a steep learning curve and
  far less documentation and community knowledge than SQLite. This is the real
  cost.
- Sessions, databases, tables, cursors and transactions all need RAII wrappers
  before any storage code is written.
- ESE is Windows-only, so it sits behind the storage interface described in
  [ADR 0005](0005-windows-first.md); a future port replaces this layer rather
  than the sync engine above it.
- Schema migrations must be designed from the start, since users' mail cannot be
  discarded on upgrade.
- Backup and compaction behaviour is ESE's, and must be understood rather than
  assumed.
