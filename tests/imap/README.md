# IMAP test fixtures

`fixtures/` holds IMAP server transcripts: the bytes a server sent, exactly as
sent, CRLFs included. `.gitattributes` keeps them byte-exact (`-text -diff`),
so Git never converts their line endings.

`test_fixtures.cpp` tokenizes every `.imap` file here, whole and divided every
way that matters: at each byte position, one byte per read, and a thousand
seeded random divisions. It requires the same tokens every time and a
byte-for-byte reassembly. Adding a file adds it to all of that.

## Where they came from

| Files | Source |
|---|---|
| `gmail-`, `outlook-`, `icloud-`, `yahoo-`, `fastmail-`, `gmx-prelogin.imap` | Real traffic, recorded with `crimson-imap-probe` on 2026-09-18: the greeting and the responses to `CAPABILITY` and `LOGOUT`. No login, no credentials, no mail |
| `rfc9051-select.imap` | The SELECT example in RFC 9051 section 6.3.2 |
| `rfc3501-fetch.imap` | The FETCH examples in RFC 3501 section 7.4.2, plus a `BODY[HEADER]` literal containing that example message's header |
| `edge-*.imap` | Hand-written: free text and response codes that break a tokenizer without context, literals of every awkward kind, and data responses from across the RFCs |

The fuzzer also uses this directory as seed input, alongside
`tests/fuzz/corpus/imap_lexer/`.

## Recording a new provider

```
x64\Debug\crimson-imap-probe.exe --record tests\imap\fixtures\<provider>-prelogin.imap <host>
```

The probe replaces every IPv4 and IPv6 address in the recording with a
documentation address (`192.0.2.x`, `2001:db8::x`) before writing it. Gmail's
greeting, for one, names the public IP of the machine that connected, and that
must never be committed. A dotted version number that happens to be a valid
IPv4 address is replaced too; that costs a little fidelity and never leaks an
address.

Before committing a recording, read it. The probe redacts addresses; it cannot
know what else a server might choose to say.

The probe refuses to record traffic containing a literal, because redaction
changes lengths and would break the literal's `{n}`. Nothing before login sends
one.
