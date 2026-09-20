# ADR 0013 — Parsers are fuzzed with MSVC's libFuzzer

Status: Accepted
Date:   2026-09-18

## Context

The research document names the IMAP, SMTP, RFC 5322, MIME, HTML and CSS
parsers as the highest-risk code in the client. All of them read input from
strangers, and the first of them, the IMAP tokenizer, now exists.

Hand-written tests cover the cases someone thought of. Fuzzing covers the ones
nobody did. It feeds the parser mutated input, guided by which code paths each
input reaches, and checks that nothing breaks.

[ADR 0004](0004-no-third-party-mail-libraries.md) rules out third-party
libraries. The question was whether fuzzing needs one.

## Decision

Fuzz with **libFuzzer as shipped in MSVC**. `/fsanitize=fuzzer` has been part
of the toolset since Visual Studio 2019 16.9, alongside AddressSanitizer, so it
is no more a third-party dependency than the compiler. It was measured on
toolset v145 (MSVC 14.51) before this decision: the runtime libraries ship
with the toolset, and a trivial target ran about 2 million inputs in 6 seconds.

Each fuzz target:

- **Is built with `/fsanitize=fuzzer,address`**, so memory errors are caught
  as they happen rather than as mysterious crashes later.
- **Compiles the code under test directly** instead of linking the library,
  because libFuzzer steers by coverage, and only code compiled with the flag
  reports it.
- **Checks properties, not just survival.** The IMAP tokenizer target
  tokenizes every input whole, at divisions derived from the input, and one
  byte per read. It requires identical results each time, and tokens that
  reassemble into the input. A parser that never crashes but answers
  differently depending on how the network divided its input would pass a
  crash-only fuzzer.
- **Shares checking code with the unit tests**, so the fuzzer and the tests
  enforce the same properties.
- **Uses tightened limits**, so short inputs reach every limit's error path.
- **Lives outside `Crimson.sln`**, so pull-request builds do not pay for the
  instrumentation.

`scripts\fuzz.cmd <target> [seconds]` builds and runs a target locally. The
working corpus persists in `obj\fuzz\<target>\corpus`, seeded from committed
inputs and the test fixtures. The nightly workflow fuzzes for ten minutes. A
crash fails the job, `workflow-health` opens a ci-health issue, and the
crashing input is kept as an artifact so the failure reproduces exactly.

## Alternatives considered

**A hand-written mutation driver in the test suite.** No external tooling, but
without coverage feedback it mostly re-tests the same shallow paths. It was
the fallback if `/fsanitize=fuzzer` had not worked on v145. It did.

**OSS-Fuzz or ClusterFuzzLite.** Continuous fuzzing on someone else's
infrastructure, built around Linux and clang. Crimson is Windows-first, and
the parsers would have to build there. Worth revisiting once the parsers are
portable enough to build on Linux.

**Fuzz in every pull request.** A minute of fuzzing finds little that a night
of fuzzing would not, and it adds a slow, non-deterministic check to every
change.

## Consequences

- Every future parser gets a target in `tests/fuzz/` and an entry in
  `scripts\fuzz.cmd`, from the start, following this one.
- A fuzz crash is reproduced by running the target on the saved input:
  `x64\Release\crimson-fuzz-imap-lexer.exe <file>`. The input then becomes a
  seed, or a unit test, once fixed.
- The fuzz targets are built only by `scripts\fuzz.cmd` and the nightly
  workflow, so a change that breaks one shows up the next morning, not in
  the pull request.
