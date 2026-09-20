# Crimson IMAP Guide

How Crimson reads IMAP: what exists, the rules it enforces, and what real
servers were measured doing. Step 3 built the tokenizer. The parser, commands
and sessions follow in Step 4.

---

## Layering

```
        commands, session                    (Step 4, in progress)
                     |
                     v
        imap::Parser           <- typed responses; chooses the lexer's mode
                     |                            from the grammar
                     v
        imap::ResponseReader   <- reads any ByteStream; can also frame
                     |            responses on its own, without a parser
                     v
        imap::Lexer            <- pure, no I/O; resumable at any byte
                     |
        crimson::net::ByteStream   (TcpStream, TlsStream, test streams)
```

The lexer and the reader live in `Crimson.Protocols` (`src/protocols/`), a
library that references `Crimson.Core` and nothing else. Protocol code cannot
reach Winsock or Schannel: it talks to the network only through `ByteStream`.

See [ADR 0012](../decisions/0012-imap-lexing-is-resumable-and-parser-directed.md)
for why the design is shaped this way.

---

## Tokens

| Kind | Example | Notes |
|---|---|---|
| `atom` | `CAPABILITY` `\Seen` `$Forwarded` `a1` `*` `+` | Flags, tags and the `*` and `+` markers all arrive as atoms |
| `number` | `4392` | Digits only, up to 2^63 - 1; more is an error, not a wrap |
| `quoted` | `"a \"b\""` | `value()` is unescaped. Only `\"` and `\\` are valid escapes |
| `nil` | `NIL` `nil` | Any case. `raw` keeps the server's spelling |
| `literal_begin` | `{216}` or `~{6}` | `number` is the size; `binary` marks a literal8 |
| `literal_data` | — | A view into the lexer's buffer, valid until the next call |
| `literal_end` | — | The line continues after it |
| `lparen` `rparen` `lbracket` `rbracket` | `(` `)` `[` `]` | |
| `text` | `Gimap ready for requests` | Free text, only in the text modes |
| `eol` | CRLF | Bare CR or bare LF is an error |

Every token records `spaces_before` and its `raw` bytes. Tokenizing is
lossless: the tokens reassemble into exactly what the server sent.

---

## Modes

The caller decides how the next token is read. This is the heart of the
design: IMAP means different things by the same bytes in different places.

| Mode | Reads | Used for |
|---|---|---|
| `normal` | Atoms, numbers, NIL, quoted strings, literals, `( ) [ ]` | The grammar |
| `astring` | As normal, but `[` and `]` belong to atoms, and `NIL` or `42` are just strings | Mailbox names: `[Gmail]/Drafts` unquoted |
| `text` | The rest of the line, whatever it holds | Human-readable text |
| `resp_text` | Text, unless the line continues with `[` | Just after a status keyword |
| `code_name` | A response code's name | Just after `[` |
| `code_text` | Text up to `]` or the end of the line | An unknown code's arguments |

`ResponseReader::next()` chooses the mode from the response's own shape:

```
a1 OK [READ-WRITE] SELECT completed
^^ ^^ ^^^^^^^^^^^^ ^^^^^^^^^^^^^^^^
|  |  |            text mode: the rest of the line
|  |  a response code: resp_text sees "[", then code_name, code_text, "]"
|  a status keyword, so a code or free text follows
a tag, "*" or "+"
```

Codes with structured arguments, such as `CAPABILITY`, `PERMANENTFLAGS`,
`UIDVALIDITY`, `APPENDUID` and `COPYUID`, have their arguments tokenized as
grammar. Every other code's arguments are text, because RFC 9051 lets an
unknown code carry anything up to its `]`. Data responses (`* 12 FETCH ...`)
are read in normal mode to the end of the line, literals included.

`ResponseReader::read(mode, token)` is the lower level: one token in a mode the
caller chooses. The Step 4 parser will use it.

---

## Limits

| Limit | Default | Why |
|---|---|---|
| `max_token_bytes` | 64 KiB | One atom, quoted string, text or run of spaces. Literals are exempt: they are streamed |
| `max_literal_bytes` | 2 GiB | Larger announcements are refused before any content is read |
| `max_depth` | 128 | Nested `(` and `[`. Real BODYSTRUCTUREs stay in single digits |

Each limit is checked at the same byte whatever the chunking, so a response
fails the same way whether it arrived whole or one byte at a time.

A syntax error leaves the lexer failed. The connection's framing can no longer
be trusted, and the only safe response is to drop it.

---

## Measured provider behaviour

Recorded on 2026-09-18 with `crimson-imap-probe`, before login: the greeting,
`CAPABILITY` and `LOGOUT`. All six negotiated TLS 1.3 with
`TLS_AES_256_GCM_SHA384`, and every response tokenized without error. The
recordings are the `*-prelogin.imap` fixtures.

| Provider | Greeting | Notable |
|---|---|---|
| Gmail | `* OK Gimap ready for requests from <client IP> <session id>` | **Names the connecting machine's public IP**, which is why recordings are redacted. No capabilities in the greeting |
| Outlook / Office 365 | `* OK Microsoft Exchange IMAP4 service ready. <id> (...) [<base64>]` | A bracketed base64 blob at the **end** of the text (the backend's host name, in UTF-16), which must stay text. Advertises `LOGINDISABLED` and only `AUTH=XOAUTH2`: no password login at all |
| iCloud | `* OK [CAPABILITY ...] (<id>) <host>` | Capabilities in a greeting code. `* BYE` and `a2 OK` with **no text**, which RFC 9051 does not allow and the reader accepts |
| Yahoo | `* OK Welcome! IMAP Server up and ready to accept your request` | `APPENDLIMIT=41697280`, `UIDONLY`, `OBJECTID`, `PARTIAL` |
| Fastmail | `* OK IMAP4 ready` | Advertises **`IMAP4rev2`**, `CONDSTORE` and `QRESYNC`. `* BYE` with no text |
| GMX | `* OK [CAPABILITY ...] IMAP server ready H migmx112 ...` | `LITERAL-` rather than `LITERAL+` |

Two of these facts matter well beyond tokenizing. Outlook cannot be used with
a password at all, so Step 5's OAuth is required for it, not optional. And
servers really do send status responses without the text the grammar demands.

---

## Tools

```
x64\Debug\crimson-imap-probe.exe                         imap.gmail.com, printed
x64\Debug\crimson-imap-probe.exe outlook.office365.com   another provider
x64\Debug\crimson-imap-probe.exe --record file.imap host also write a fixture
scripts\fuzz.cmd imap_lexer 600                          fuzz the tokenizer
scripts\fuzz.cmd imap_parser 600                         fuzz the parser
```

The probe sends `CAPABILITY` and `LOGOUT` and nothing else, never credentials.
See [tests/imap/README.md](../../tests/imap/README.md) for adding a recording
as a fixture, and [ADR 0013](../decisions/0013-fuzz-parsers-with-msvc-libfuzzer.md)
for fuzzing.

---

## Responses

`imap::Parser` turns tokens into typed values: `TaggedResponse`,
`UntaggedResponse` and `ContinuationRequest`, where an untagged response is a
status, capabilities, a mailbox listing, a mailbox status, search results, a
fetch result, a count, a flag list, or something Crimson does not recognise.

```cpp
crimson::imap::ResponseReader reader{stream};
crimson::imap::Parser parser{reader};

crimson::imap::Response response;
while (auto got = parser.next(response)) {
    if (*got == crimson::imap::ParseStatus::end) break;   // the server closed
    // ... std::visit over the response
}
```

**It chooses the lexer's mode from the grammar**, which is the whole point of
the modes: a mailbox name is read as an astring, so `[Gmail]/Drafts` unquoted
keeps its brackets, while the same bytes elsewhere would be three tokens.

**It is forgiving about meaning and strict about structure.** An unknown
response, an unknown response code and an unknown FETCH item are all kept
rather than refused — servers send extensions constantly, and one of them must
not end a session. A code that contradicts its own name, or never closes its
bracket, is kept as an unrecognised code and the line is read to its end. But
a response that cannot be read at all is a `SyntaxError`, and the connection
goes: the framing can no longer be trusted.

**An unknown response is skipped as grammar, not as text.** It may contain a
literal, and a literal's content has to be consumed as content. Skipped as
text, its bytes would be read as the next response.

**Large bodies are streamed.** A `BODY[...]` section over
`Limits::max_inline_literal` (1 MiB) is handed to a sink in the pieces it
arrives in, and only its size is recorded on the response. Step 7 writes those
straight to disk.

**Limits are counted in units the network cannot change.** This is subtler
than it sounds, and the fuzzer caught it the first time it ran: counting
literal chunks against an item limit makes the same response pass or fail
depending on how it was divided in transit.

What the parser deliberately leaves alone: `BODYSTRUCTURE` and a bare `BODY`
are noted as items the server offered and skipped, because their nested part
descriptions belong with MIME in Step 7. Envelope strings stay exactly as
sent; Step 6 parses the real headers, including encoded words. `INTERNALDATE`
is the one date IMAP defines itself, so it is parsed here — and one that
cannot be read leaves the field unset rather than refusing the message.

---

## What this layer deliberately does not do

No command serialization, no authentication, no session state: those are the
rest of Step 4. No MIME, no RFC 5322 header parsing, no local store.
