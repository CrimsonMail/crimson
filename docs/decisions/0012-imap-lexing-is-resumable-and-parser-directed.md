# ADR 0012 — IMAP lexing is resumable and parser-directed

Status: Accepted
Date:   2026-09-18

## Context

IMAP looks line-oriented until literals appear. A `{4281}` at the end of a line
announces 4281 bytes of raw content, which may contain CRLFs, quotes and
anything else. The research document is explicit: do not build IMAP around
reading lines and splitting them.

TCP does not help. One read can return half a token, or the end of one response
and the start of the next. A tokenizer that assumes a read boundary means
anything works on a quiet local network and fails in production.

The subtler problem is that IMAP cannot be tokenized without context. After
`OK`, `NO`, `BAD`, `PREAUTH`, `BYE` or `+`, the rest of the line is free text.
That text can contain an unbalanced `"`, stray brackets, or `{5}`. A tokenizer
that ignores context reads that `{5}` as a literal announcement and swallows
five bytes of the next response. From then on every response is misread. This
is not hypothetical: Outlook's greeting ends in a bracketed base64 blob, and
the RFC lets an unknown response code carry arbitrary text. The same ambiguity
applies to brackets: `[Gmail]/Drafts` is a legal unquoted mailbox name, and
also looks like a bracket, an atom, a bracket and an atom.

## Decision

**Two layers.** `imap::Lexer` is a pure state machine with no I/O.
`imap::ResponseReader` adds reading from any `ByteStream` and just enough
knowledge of a response's shape to lex it correctly.

**The caller chooses the mode.** `Lexer::next(mode, token)` reads the next
token as grammar (`normal`), as an astring (`[` and `]` belong to the name), or
as text (the rest of the line, or up to a response code's `]`). The Step 4
parser knows the grammar, so it will choose modes itself. Until then,
`ResponseReader::next` chooses them from the response's shape: a tag, `*` or
`+`, then text after a status keyword or `+`, with response codes handled
specially. Structured codes such as `PERMANENTFLAGS` are tokenized; any other
code's arguments are text.

**Resumable at any byte.** `feed()` accepts input in pieces of any size, and
`next()` returns `need_more` whenever a token is incomplete. A token part-way
through arriving is resumed from where examination stopped, not rescanned, so
one-byte reads stay linear. Every decision depends only on bytes already
examined, never on where a read happened to end. That makes chunking
irrelevant by construction. The tests then check it rather than assume it,
splitting real traffic at every byte position.

**Literals are streamed.** `literal_begin` carries the size. The content
arrives as `literal_data` views into the lexer's buffer, then `literal_end`. A
50 MB body never has to fit in memory, which Step 7's streaming to disk
depends on.

**Lossless.** Each token records the spaces before it and its raw bytes, so
the token stream reassembles into exactly the bytes received. This is the
strongest invariant the tests and the fuzzer can check. It also follows the
project rule that original bytes are preserved.

**Bounded.** `LexerLimits` caps token size (64 KiB), announced literal size
(2 GiB) and nesting depth (128). Numbers are refused past 63 bits. A server is
untrusted input.

**A syntax error ends the connection.** After one, the framing cannot be
trusted, so the lexer stays failed. `SyntaxError` has no retry classification:
reconnecting is always the answer, and whether to try again is the sync
engine's decision.

## Alternatives considered

**Read a line, then split it.** This is the design the research document
warns against. It breaks on literals, and on anything that looks like a line
ending inside one.

**A context-free tokenizer, with the parser repairing mistakes.** A literal
cannot be repaired after the fact: once five bytes have been swallowed, they
are gone from the next response.

**A recursive-descent parser reading directly from the stream.** It would
merge Steps 3 and 4 and make chunking a parser concern everywhere. Keeping the
lexer I/O-free is what lets it be fed a byte at a time by tests and by the
fuzzer.

**Buffering literals whole.** Simpler for small ones, and a memory exhaustion
waiting to happen for large ones. A consumer that wants a small literal whole
can concatenate the pieces.

## Consequences

- The lexer is portable C++ in `Crimson.Protocols`, which links only
  `Crimson.Core`. Reaching for Winsock from protocol code fails to link.
- Token strings are reused across calls, so a long session does not allocate
  per token. `literal_data` views are valid only until the next `feed()` or
  `next()`, and consumers must copy or write them before then.
- Response framing in `ResponseReader::next` is deliberately minimal and
  lenient. It tolerates `* BYE` with no text (iCloud and Fastmail send exactly
  that) and stray closing brackets. It refuses a response that starts with
  anything but a tag, `*` or `+`.
- The mode a token is read in changes what the token is. The Step 4 parser
  must choose modes from the grammar. Tokenizing everything in `normal` mode
  would reintroduce the problem this ADR exists to prevent.
