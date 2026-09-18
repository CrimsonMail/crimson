# Crimson

A native, local-first desktop communication client for Windows.

Crimson keeps your mail on your machine. It reads from a local store, works
without a network, and talks to mail servers through its own protocol
implementations rather than a bundled mail library.

## Status

**Early development. Not yet usable as a mail client.**

Crimson is being built from the bottom up. The networking foundation is in
place — DNS resolution, TCP connections, a byte-stream abstraction, and TLS 1.2
and 1.3 through Windows' own Schannel. There is no IMAP, no SMTP, no storage and
no user interface yet.

Follow [Crimson Development](https://github.com/orgs/CrimsonMail/projects) for
current progress, or read [the architecture docs](docs/architecture/) to see
where this is going.

## Design principles

Crimson implements the interesting parts itself and leans on the operating
system for the parts where reimplementation would be unsafe.

**Written for Crimson:** IMAP, SMTP, MIME, RFC 5322, OAuth 2.0 flows,
synchronization, local storage, search indexing, conversation threading, the
restricted HTML mail renderer, and the user interface.

**Taken from Windows:** TLS (Schannel), cryptographic primitives (CNG),
credential storage (DPAPI / Credential Manager), text shaping (DirectWrite),
rendering (Direct2D) and image decoding (WIC).

There are no third-party libraries and no package manager. Crimson links
against Windows system DLLs and nothing else.

A few rules hold everywhere in the codebase:

- The interface never talks to a mail server. It reads the local store, and a
  background sync engine updates that store.
- Mail is hostile input. Every parser has explicit depth and allocation limits.
- Original message bytes are preserved, so improved parsers can reparse old mail.
- HTML mail never executes JavaScript, and remote content is blocked by default.
- Credentials and tokens never reach a log file.

## Building

Requires **Windows 11 x64** and **Visual Studio 2026** with the
*Desktop development with C++* workload, which supplies MSVC v145, the
Windows 11 SDK and AddressSanitizer.

```
winget install --id Microsoft.VisualStudio.Community --override "--quiet --wait --norestart --add Microsoft.VisualStudio.Workload.NativeDesktop --includeRecommended"
```

From an ordinary command prompt — the scripts locate Visual Studio themselves,
so no special developer prompt is needed:

```
scripts\build.cmd                  Debug
scripts\build.cmd Release
scripts\build.cmd Debug asan       with AddressSanitizer

scripts\test.cmd                   all tests
scripts\test.cmd Debug tcp_stream  only matching tests
```

Or drive MSBuild directly from an **x64 Native Tools Command Prompt**:

```
msbuild Crimson.sln /p:Configuration=Debug /p:Platform=x64
x64\Debug\Crimson.Tests.exe
```

Crimson builds with `/W4 /WX`, so any compiler warning fails the build.

To watch the transport layer work against a real server:

```
x64\Debug\crimson-net-smoke.exe example.com 80
x64\Debug\crimson-net-smoke.exe --tls example.com 443
```

The TLS tests talk to public servers, including deliberately broken ones at
badssl.com. To run the suite offline, set `CRIMSON_SKIP_NETWORK_TESTS=1`; those
tests are then reported as skipped rather than passed. A badssl.com test is also
skipped, with the reason, when that service is having an outage.

## Repository layout

```
src/core/                 portable domain and application logic
src/platform/windows/     Win32, Winsock, Schannel, ESE, DPAPI
tests/                    unit, protocol and integration tests
tools/                    development and diagnostic utilities
docs/architecture/        design documentation
docs/decisions/           architecture decision records
docs/rfcs/                design proposals
build/                    shared MSBuild property sheets
```

## Documentation

- [Networking design](docs/architecture/networking.md)
- [Architecture decision records](docs/decisions/)
- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)
- [Changelog](CHANGELOG.md)

## Contributing

Crimson is in a stage where the architecture is still moving quickly. If you
want to help, read [CONTRIBUTING.md](CONTRIBUTING.md) and open a discussion
before starting anything substantial — it saves everyone rework.

## Security

Do not report vulnerabilities in public issues. Use the **Security** tab to
open a private report. See [SECURITY.md](SECURITY.md).

## License

[Mozilla Public License 2.0](LICENSE).
