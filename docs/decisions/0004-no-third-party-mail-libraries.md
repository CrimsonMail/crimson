# ADR 0004 — No third-party libraries

Status: Accepted
Date:   2026-09-18

## Context

Crimson could be assembled from existing parts. MailKit and MimeKit handle IMAP,
SMTP and MIME; OpenSSL handles TLS; SQLite handles storage; Qt or Electron
handles the interface; a WebView renders HTML mail. That client could probably
be working in weeks.

Crimson's purpose is to own those systems. The goal is a client whose behaviour
is fully understood by its author, where a protocol bug can be traced to a line
of Crimson's own code, and where the mail engine is not a black box.

## Decision

Crimson takes **no third-party libraries and no package manager**. No vcpkg, no
NuGet, no Conan. The binary links against Windows system DLLs and nothing else.

**Implemented in Crimson:** IMAP, SMTP, MIME, RFC 5322, OAuth 2.0 flows, SASL
mechanisms, the sync engine, local storage, the search index, conversation
threading, the restricted HTML/CSS mail renderer, the test harness, and the
interface.

**Taken from Windows:** TLS (Schannel), cryptographic primitives and RNG (CNG),
credential storage (DPAPI / Credential Manager), the storage engine
([ADR 0002](0002-use-esent.md)), Unicode text shaping (DirectWrite), rendering
(Direct2D), image decoding (WIC) and DNS.

The dividing line is **not** difficulty — it is what happens when the
implementation is subtly wrong.

A bug in Crimson's IMAP parser means mail displays incorrectly: visible,
debuggable, fixable. A bug in a hand-rolled TLS stack or AES implementation
means credentials leak silently while everything appears to work. Cryptography,
TLS, certificate validation, secure random number generation and Unicode
shaping all fail in ways that are invisible from the outside, so Crimson uses
vetted operating system implementations for those and writes the rest itself.

Build tooling is not a runtime dependency; MSBuild and the Windows SDK are part
of the toolchain, not the product. Development infrastructure — GitHub Actions,
CI images — is covered by the supply-chain model, not by this ADR.

## Alternatives considered

**Use the established libraries.** Faster, more correct sooner, and the right
answer for almost any commercial project. It is simply not this project.

**Permit "small, safe" dependencies.** This has no stable boundary. Every
dependency is small and safe in isolation, and the rule erodes within a year.
A hard rule with an explicit, reasoned exception list survives contact with
reality; a soft preference does not.

**Write the cryptography too.** Maximally consistent, and irresponsible in
software that holds mail credentials. The failure modes are silent.

## Consequences

- Crimson takes far longer to become useful. This is accepted, and it is the
  point of the project.
- The author owns every protocol bug — which is also the intended outcome.
- Parsers are the primary attack surface and get correspondingly heavy treatment:
  explicit limits, fuzzing, sanitizers and CodeQL.
- Adding a dependency is an architectural event requiring an RFC and a new ADR
  superseding this one. It is never a detail inside a pull request.
- The SBOM stays small and genuinely readable, which becomes a security feature
  rather than a compliance artifact.
- Some work is knowingly duplicated. An HTML renderer, a search index and a
  storage abstraction are each substantial projects; Crimson builds restricted
  versions scoped to what a mail client actually needs, not general-purpose
  equivalents.
