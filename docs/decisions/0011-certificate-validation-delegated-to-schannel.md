# ADR 0011 — Certificate validation is delegated to Schannel

Status: Accepted
Date:   2026-09-18

## Context

Deciding whether to trust a server's certificate is the security-critical part
of TLS. Getting the encryption right is worth nothing if Crimson will happily
encrypt to an impostor.

Two approaches were available. Schannel can validate automatically during the
handshake. Or Crimson can ask for manual validation and do it itself: fetch the
peer certificate, build the chain with `CertGetCertificateChain`, and check it
with `CertVerifyCertificateChainPolicy`.

The choice was delegated to "whatever is more efficient while still following
the guidelines". The guidelines settle it. The research document lists
certificate validation among the things never to reimplement, and
[ADR 0004](0004-no-third-party-mail-libraries.md) draws its line at code whose
failure is silent. A manual chain check that is subtly wrong does not fail: it
accepts a forged certificate and every connection keeps working.

## Decision

Schannel validates. Crimson does not.

- The credential sets `SCH_CRED_AUTO_CRED_VALIDATION`, and the handshake never
  requests `ISC_REQ_MANUAL_CRED_VALIDATION`.
- The configured hostname is passed as `pszTargetName`, which makes Schannel
  both send it as SNI and check the certificate against it. An
  internationalised name is first converted to its ASCII-compatible form with
  `IdnToAscii`, since that is how certificates list such names.
- **Revocation is checked, and soft-fails.** `SCH_CRED_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT`
  checks every certificate but the root; `SCH_CRED_IGNORE_NO_REVOCATION_CHECK`
  and `SCH_CRED_IGNORE_REVOCATION_OFFLINE` tolerate revocation information that
  cannot be fetched. A certificate known to be revoked fails. A captive portal or
  a network that blocks OCSP does not break every connection. This is the
  policy browsers use.
- The peer certificate is still read after the handshake, for diagnostics only.

## What was measured

Against badssl.com, which serves deliberately broken TLS:

| Server | Result | Certificate problem? | Retry |
|---|---|---|---|
| `expired.badssl.com` | `SEC_E_CERT_EXPIRED` | yes | no |
| `wrong.host.badssl.com` | `SEC_E_WRONG_PRINCIPAL` | yes | no |
| `self-signed.badssl.com` | `SEC_E_UNTRUSTED_ROOT` | yes | no |
| `untrusted-root.badssl.com` | `SEC_E_UNTRUSTED_ROOT` | yes | no |
| `revoked.badssl.com` | `CRYPT_E_REVOKED` | yes | no |

The revoked case matters most: it shows the soft-fail flags tolerate
*unreachable* revocation data without also hiding a certificate that *is*
revoked.

Connecting by IP address fails too, though not as first expected. SNI cannot
carry an address, so a server fronting many names receives no name at all,
cannot choose a certificate, and aborts with an alert before sending one —
`SEC_E_ILLEGAL_MESSAGE` from a CDN. A server with a default certificate would
produce `SEC_E_WRONG_PRINCIPAL` instead. Either way the connection is refused,
which is correct.

## Alternatives considered

**Manual validation.** More control, and the precondition for a future "trust
this self-signed certificate anyway" prompt. Rejected for now: roughly four
times the code, all of it on the path where a mistake is invisible.

**Hard-fail revocation.** Stricter on paper; in practice it turns every network
that blocks OCSP into a total outage, which teaches users to disable security
rather than rely on it.

**No revocation checking.** Schannel's default. Rejected, because the revoked
case above would then connect.

## Consequences

- Failures arrive as precise codes, and `is_certificate_error()` lets the
  interface say "the server's certificate has expired" rather than "couldn't
  connect". Certificate failures are classified as permanent: retrying an
  expired certificate changes nothing.
- The trust store is Windows'. That includes roots an organisation deploys by
  Group Policy, so a corporate mail server using an internal certificate
  authority works without anything Crimson-specific.
- Crimson has no way yet to accept a self-signed certificate for a home server.
  When it does, it will add a user decision *after* Schannel has rejected the
  certificate, keyed to that exact certificate — never replace Schannel's check.
- `SEC_E_ILLEGAL_MESSAGE` is ambiguous between a corrupted record and a server
  refusing the handshake outright, and is classified for the former. The sync
  engine's backoff bounds the cost when it is the latter.
