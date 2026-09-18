# Requests for Comments

An RFC proposes a significant change *before* it is built, so the design can be
argued about while that is still cheap.

## RFC or ADR?

They are two ends of the same process:

| | RFC | ADR |
|---|---|---|
| Written | Before the decision | When the decision is made |
| Purpose | Explore options and invite challenge | Record what was chosen and why |
| Changes | Revised freely while in draft | Never edited; superseded by a new one |
| Lives in | `docs/rfcs/` | [`docs/decisions/`](../decisions/) |

An accepted RFC is followed by an ADR that records the decision it reached. A
choice with an obvious default needs neither.

## When to write one

When a change would be expensive to undo, or would constrain code nobody has
written yet. For example:

- the local mail store's schema, or its migration model;
- how the sync engine reconciles offline changes with the server;
- an extension or plugin system;
- anything that would add a third-party dependency — which also requires
  superseding [ADR 0004](../decisions/0004-no-third-party-mail-libraries.md);
- a second platform.

Bug fixes, refactors and features that fit the existing architecture do not
need one.

## Process

1. **Start in [Discussions → Development](https://github.com/orgs/CrimsonMail/discussions/categories/development)**
   if the idea is still forming. An RFC is for a concrete proposal.
2. **Copy [`0000-template.md`](0000-template.md)** to
   `NNNN-short-title.md`, taking the next free number.
3. **Open a pull request** with it, labelled `skip-changelog`. The pull request
   is where the review happens; revise the document in place.
4. **Resolve it** by setting the status and merging:

| Status | Meaning |
|---|---|
| Draft | Under discussion |
| Accepted | Agreed; an ADR records the decision and implementation can start |
| Rejected | Not going ahead. Kept, with the reason, so it is not proposed again unknowingly |
| Withdrawn | The author stopped pursuing it |
| Implemented | Built and merged |

Rejected RFCs are merged rather than closed, because the record of why
something was *not* done is often the more valuable one.

## Index

| # | Title | Status |
|---|---|---|
| — | No RFCs yet | — |
