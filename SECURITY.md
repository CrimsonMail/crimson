# Security Policy

Crimson handles mail credentials, OAuth tokens, private messages and
attachments. Security reports are taken seriously and handled privately.

## Reporting a vulnerability

**Do not open a public issue for a security problem.**

Use GitHub private vulnerability reporting: go to the
[Security tab](https://github.com/CrimsonMail/crimson/security/advisories/new)
and open a draft advisory. This is visible only to maintainers.

Useful things to include, as far as you have them:

- What the problem is and why it matters
- Affected version, commit or component
- Steps to reproduce, ideally a minimal case
- A sample message or protocol trace, **with your own credentials removed**
- Any suggested fix

If you are sending a mail sample that triggers the problem, scrub addresses and
message contents you do not want retained.

## What to expect

Crimson is currently maintained by one person, so please allow reasonable time
for a reply. In general:

| Stage | Aim |
|---|---|
| Acknowledgement | Within a few days |
| Initial assessment | Once reproduced |
| Fix and release | Depends on severity and complexity |
| Public advisory | After a fix ships, coordinated with you |

Severity is assessed on confidentiality, integrity and availability impact,
whether interaction is required, remote exploitability, and whether credentials
or mail contents are exposed. Automation never decides severity.

## Credit

You choose how you are credited: **publicly by name or handle, anonymously, or
not at all.** Your preference is respected, and you will never be named in an
advisory without permission.

## Supported versions

Crimson has **no released versions yet**. This table will list supported
versions once 0.1 ships.

| Version | Supported |
|---|---|
| unreleased (`main`) | Current development |

Until there is a release, report issues against `main`.

## Scope

**In scope** — anything that could expose mail, credentials or tokens, or let a
message compromise the client:

- Memory safety in the IMAP, SMTP, RFC 5322, MIME, HTML or CSS parsers
- Credential or token disclosure, including via logs or crash reports
- TLS validation or certificate verification flaws
- OAuth flow weaknesses, such as redirect or PKCE handling
- HTML mail escaping the restricted renderer, or silently loading remote content
- Attachment handling that bypasses Windows security expectations
- Local store or blob store exposure
- Update mechanism weaknesses, once an updater exists

**Out of scope:**

- Vulnerabilities in Windows itself — report those to Microsoft
- Findings that require an already-compromised machine or administrator access
- Missing hardening with no demonstrated impact
- Automated scanner output with no analysis
- Social engineering of maintainers or contributors

## Release verification

Once Crimson publishes releases, this section will document SHA-256 checksums,
the SPDX SBOM, artifact attestation verification and the code-signing identity.
Not applicable yet — there are no release artifacts to verify.

## Security practices

For context on how Crimson protects the path from source to your machine, see
the [architecture documentation](docs/architecture/). In short: `main` is
protected and requires review-gated pull requests, CodeQL and secret scanning
run continuously, GitHub Actions run with a read-only token by default and
third-party actions are pinned to commit SHAs, and TLS and cryptography use
Windows APIs rather than custom implementations.
