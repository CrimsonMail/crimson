# ADR 0010 — TLS through Schannel, as a ByteStream over a ByteStream

Status: Accepted
Date:   2026-09-18

## Context

Every protocol Crimson will speak needs TLS: IMAP on 993, SMTP submission on
465 and 587, and the HTTPS endpoints OAuth uses. The research document rules
out implementing TLS ("do not reimplement TLS 1.3 … certificate validation"),
and [ADR 0004](0004-no-third-party-mail-libraries.md) rules out OpenSSL and its
relatives. That leaves the TLS stack Windows ships: Schannel, reached through
SSPI.

The layering question was already answered by
[ADR 0007](0007-byte-stream-abstraction.md): TLS had to fit the existing
`ByteStream` seam without the transport beneath it changing. Step 2 was the
test of whether that seam was right.

## Decision

`TlsStream` implements `ByteStream` and owns a `std::unique_ptr<ByteStream>`.
It uses Schannel through SSPI: `InitializeSecurityContextW` for the handshake,
`EncryptMessage` and `DecryptMessage` for records, `ApplyControlToken` for
close_notify.

**`wrap()` is the primitive, `connect()` is sugar.** IMAP on 143 and SMTP on 587
start in plaintext and upgrade the same connection after `STARTTLS`, so TLS must
be able to adopt a stream that already exists.

**Credentials use `SCH_CREDENTIALS` with a disable-list.** SSL 3.0, TLS 1.0 and
TLS 1.1 are disabled; everything else is allowed, so TLS 1.3 — and any later
version Windows adds — is used without a change here. RFC 8314 requires TLS 1.2
or better for mail. The deprecated `SCHANNEL_CRED` can only express an
enable-list, which would freeze the protocol set at whatever was listed.

**One credential handle, shared.** `TlsCredentials` copies share a single
handle, released with the last copy, and every stream holds one. Schannel keys
its session cache on the credential, so sharing it is what allows resumption.

**The record layer keeps two buffers**: undecrypted ciphertext, which may hold a
partial record or several, and decrypted plaintext not yet returned. Records are
written with `write_all` because a partially written record desynchronises the
peer permanently, while `write_some` still reports the plaintext count it
consumed.

## What was measured

Against real servers, before tests were written:

| Observation | Consequence |
|---|---|
| `example.com` negotiated TLS 1.3, `TLS_AES_256_GCM_SHA384` | The disable-list lets 1.3 through |
| A TLS 1.3 connection to `example.com` surfaced `SEC_I_RENEGOTIATE` from `DecryptMessage` before any data | Schannel reports a TLS 1.3 NewSessionTicket that way. It is routine, not a TLS 1.2 renegotiation, and must be fed back through the handshake with the extra bytes. Treated as an error, it would break the first read from any TLS 1.3 server that issues tickets |
| `SEC_I_CONTEXT_EXPIRED` arrived with the final data | `ReadResult{bytes, eof}` was built for exactly this and needed no change |
| TLS 1.0- and 1.1-only servers are refused, but the code depends on the machine: `SEC_E_ALGORITHM_MISMATCH` on Windows 11 25H2, `SEC_E_ILLEGAL_MESSAGE` on GitHub's Windows Server 2025 runner | The server's reply depends on the client's cipher list. Offered a CBC suite TLS 1.0 can use, it answers in TLS 1.0 and Schannel rejects the version; offered none — presumably the runner's case — it sends a handshake_failure alert. Tests assert the refusal, not the code |
| Handshake and response through a stream delivering one byte per read and per write | Identical result, over more than a thousand reads; record reassembly holds |
| 48 KiB written in one call | Whole application-data records on the wire, none over the RFC 8446 limit of 2^14 + 256 bytes, none torn — checked by parsing the raw bytes |

## Alternatives considered

**OpenSSL, BoringSSL, wolfSSL, mbedTLS.** Mature and portable, and excluded by
ADR 0004.

**A TLS implementation of Crimson's own.** Never. Its failure mode is silent:
a subtle mistake leaks credentials while every connection appears to work.

**WinHTTP.** An HTTP client, not a stream. It would serve OAuth and nothing
else.

**`TlsStream<TcpStream>` as a template, or a concrete `TcpStream` member.**
Either would have made the fragmenting interposer impossible, and with it the
most valuable test in the suite.

## Consequences

- **The Step 1 seam held.** `byte_stream.h`, the stream helpers and
  `tcp_stream.*` are unchanged. The transport layer gained new `NetOp` and
  `NetCat` values and one `case` label, and the build gained `secur32.lib`,
  `crypt32.lib` and `normaliz.lib`.
- TLS is Windows-only, but only behind `ByteStream`. A port replaces
  `TlsStream`; nothing above it changes.
- Schannel's behaviour tracks the Windows release. The `SEC_I_RENEGOTIATE`
  behaviour above is an example of something that changed with TLS 1.3 support.
- Handshake tests need the public internet, since Crimson deliberately has no
  TLS server of its own. `CRIMSON_SKIP_NETWORK_TESTS` lets the rest of the suite
  run offline. badssl.com has outages of its own — resets and dropped
  handshakes for every client, OpenSSL included — so a badssl.com test that
  gets no verdict from Schannel after retrying is skipped, not failed. Anything
  Schannel does decide is still asserted exactly.
- Three include-order and build facts, each of which fails without naming its
  cause, are owned by `win_security.h` and documented there:
  `SECURITY_WIN32` before `<sspi.h>`; `SCHANNEL_USE_BLACKLISTS` — without which
  `SCH_CREDENTIALS` does not exist — plus `UNICODE_STRING` before
  `<schannel.h>`; and `IdnToAscii` linking from `normaliz.lib`, not
  `kernel32.lib`.
- Ciphertext held while waiting for a record is capped at 256 KB. A peer that
  never completes a message cannot grow the buffer without bound.
