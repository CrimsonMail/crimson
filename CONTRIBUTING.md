# Contributing to Crimson

Thanks for your interest. Crimson is early enough that the architecture still
moves quickly, so a short conversation before you write code will usually save
you rework.

## Before you start

| You want to | Go here |
|---|---|
| Ask a question | Discussions → Q&A |
| Suggest an idea | Discussions → Ideas |
| Report a bug | Issues → Bug report |
| Propose an architectural change | Discussions → Development, then an RFC |
| Report a vulnerability | **Security tab**, privately — never an issue |

Issues are for actionable work. Speculative discussion belongs in Discussions
so the backlog stays meaningful.

For anything beyond a small fix, comment on the issue before starting so two
people don't build the same thing.

## Building

Requires Windows 11 x64 and Visual Studio 2026 with the *Desktop development
with C++* workload. From an **x64 Native Tools Command Prompt**:

```
msbuild Crimson.sln /p:Configuration=Debug /p:Platform=x64
x64\Debug\Crimson.Tests.exe
```

Crimson builds with `/W4 /WX /permissive-`. Warnings are errors; do not
suppress one without a comment saying why.

Before opening a pull request, run the tests and build Release as well as
Debug. CI runs both.

## The dependency rule

**Crimson does not take third-party libraries.** Not Boost, not OpenSSL, not
SQLite, not a test framework. This is the central constraint of the project,
not an oversight — see
[ADR 0004](docs/decisions/0004-no-third-party-mail-libraries.md).

Use the C++ standard library and Windows system APIs. If you believe something
genuinely cannot be built or replaced, open an RFC first. Adding a dependency
is an architectural decision, never a detail inside a pull request.

## Branches and pull requests

Short-lived branches off `main`:

```
feature/imap-tokenizer
fix/socket-resource-leak
refactor/network-errors
docs/networking-design
test/loopback-harness
```

`main` is protected: no direct pushes, pull request required, CI must pass.

Pull requests are squash-merged, **so your PR title becomes permanent
changelog history.** Write it as a description of the change:

```
Good:  Fix IMAP literal parsing across fragmented reads
Good:  Prevent remote images from loading by default
Bad:   fix parser
Bad:   updates
```

Keep pull requests focused. A reviewable PR does one thing.

## Code style

`.editorconfig` covers formatting: 4-space indent, UTF-8, CRLF, 100-column
soft limit.

Naming follows the Crimson naming guide:

- **No brand prefixes in code.** `TcpStream`, not `CrimsonTcpStream`. The
  repository already belongs to Crimson; repeating it is noise.
- Namespaces carry the identity instead: `crimson::net`, `crimson::imap`.
- Files are technical and lowercase: `tcp_stream.cpp`, not `CrimsonTcpStream.cpp`.
- Use ordinary email vocabulary for anything user-facing — Inbox, Archive,
  Drafts. Do not rename standard concepts to fit the theme.

Every source file starts with the MPL-2.0 notice:

```cpp
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
```

## Architectural rules

These are enforced in review because violating them is expensive to undo:

- Interface code does not include protocol internals, and protocol code does
  not include Win32 UI headers.
- No networking on the UI thread.
- Passwords and tokens never enter logs. Protocol logging redacts secrets.
- `Message-ID` is never a database primary key — it can be missing, duplicated
  or forged. Use local identifiers.
- Parsers have explicit depth and allocation limits, and no UI side effects.
  A parser returns warnings; policy layers decide what to show.
- Raw message bytes are preserved so mail can be reparsed later.
- Every optional server capability has a fallback path.
- Network changes update the local store before the interface hears about them.
- Outgoing actions become durable before transmission.
- TLS and cryptography use vetted Windows APIs, never a hand-rolled version.

## Tests

New code needs tests. Crimson uses its own harness in `tests/` — no external
framework.

Protocol and parser code especially needs adversarial tests: fragmented input
across arbitrary read boundaries, truncated messages, malformed encodings and
hostile nesting. TCP delivers a byte stream, so never write a test that assumes
one read returns one protocol message.

## Recognition

Code is not the only contribution that counts. Documentation, triage, bug
reproduction, design, accessibility testing, localization, protocol test cases
and security research are all recognized, and you can opt out of public
contributor lists at any time.
