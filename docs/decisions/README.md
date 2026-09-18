# Architecture Decision Records

An ADR records a decision that would be expensive to reverse, and the reasoning
that made it the right call at the time. The point is not the conclusion — it is
that future maintainers (including future you) can see what was considered and
what was rejected, and can tell the difference between a deliberate choice and
an accident.

## When to write one

Write an ADR when a decision:

- constrains code that has not been written yet;
- is hard to undo once code depends on it;
- will otherwise be re-litigated every few months;
- or looks wrong without context, so someone will "fix" it.

Do not write one for routine choices with an obvious default.

## Format

```
# ADR NNNN — Title

Status: Proposed | Accepted | Superseded by ADR NNNN | Deprecated
Date:   YYYY-MM-DD

## Context
## Decision
## Alternatives considered
## Consequences
```

Larger proposals that need discussion before a decision belong in
[`docs/rfcs/`](../rfcs/) first; the resulting decision is then recorded here.

## Records

| # | Decision | Status |
|---|---|---|
| [0001](0001-use-cpp23.md) | Use C++23 with MSVC | Accepted |
| [0002](0002-use-esent.md) | Use ESE/ESENT for local metadata | Accepted |
| [0003](0003-local-first-storage.md) | Local-first storage with a sync engine | Accepted |
| [0004](0004-no-third-party-mail-libraries.md) | No third-party libraries | Accepted |
| [0005](0005-windows-first.md) | Windows first, portability preserved | Accepted |
| [0006](0006-error-model-std-expected.md) | Use `std::expected` for recoverable failures | Accepted |
| [0007](0007-byte-stream-abstraction.md) | A runtime `ByteStream` interface, EOF in the value channel | Accepted |
| [0008](0008-overlapped-connection-attempts.md) | Overlap connection attempts across resolved addresses | Accepted |
| [0009](0009-connection-cancellation-model.md) | Cancel blocked I/O with `CancelIoEx` under a mutex | Accepted |
| [0010](0010-schannel-for-tls.md) | TLS through Schannel, as a `ByteStream` over a `ByteStream` | Accepted |
| [0011](0011-certificate-validation-delegated-to-schannel.md) | Certificate validation is delegated to Schannel | Accepted |

An ADR is never edited to change its decision. Supersede it with a new record
and update the status of the old one.
