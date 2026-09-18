## What this changes

<!--
Describe the change and why it is needed.

Note: pull requests are squash-merged, so the PR *title* becomes permanent
changelog history. Write it as a description of the change:

  Good:  Fix IMAP literal parsing across fragmented reads
  Bad:   fix parser
-->

## Related issue

<!-- "Closes #123", or "Part of #123" for one step of a larger piece of work. -->

## How this was tested

<!--
What you actually ran, not what you intended to run. For protocol or parser
work, say which adversarial cases are covered — fragmented reads, truncated
input, malformed encodings.
-->

## Checklist

- [ ] Builds clean at `/W4 /WX` in both Debug and Release
- [ ] `Crimson.Tests.exe` passes
- [ ] New code has tests, and parser changes have adversarial tests
- [ ] No new third-party dependency (see [ADR 0004](../docs/decisions/0004-no-third-party-mail-libraries.md))
- [ ] No credentials, tokens or message contents can reach a log
- [ ] Documentation and ADRs updated if this changes a design decision
- [ ] Labelled `breaking-change` if it affects profile format, schema, or any public API
- [ ] Labelled with exactly one `changelog:` category (or `performance`), or `skip-changelog` — the PR metadata check enforces this

## Breaking changes

<!-- Delete if none. Otherwise: what breaks, and what users must do about it. -->
