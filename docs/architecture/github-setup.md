# CrimsonMail GitHub Setup

What is configured, what is scripted, and what has to be clicked.

Most of the operating model lives in this repository as files — issue forms,
workflows, labels, Dependabot, community health files — and is reviewed like
code. The rest is GitHub configuration, and some of it has no API.

---

## Configured as files (already in the repository)

| Area | Where |
|---|---|
| Community health | `README.md`, `CONTRIBUTING.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`, `CHANGELOG.md`, `LICENSE` |
| Issue intake | `.github/ISSUE_TEMPLATE/*.yml` — blank issues disabled, questions routed to Discussions |
| Pull requests | `.github/PULL_REQUEST_TEMPLATE.md` |
| Labels | `.github/labels.yml` |
| Action updates | `.github/dependabot.yml` |
| CI | `.github/workflows/{pr,main,nightly,codeql}.yml` |

---

## Scriptable through the API

These are applied with `gh`, and each result should be checked rather than
assumed.

```
repository        public, description, topics:
                  email, email-client, imap, smtp, windows, cpp, open-source
merge settings    squash only; merge commits and rebase disabled;
                  delete branches on merge
ruleset on main   pull request required, force pushes blocked, deletion blocked,
                  conversation resolution required, required status checks
                  wired to the pr.yml job names
                  -- deliberately NO second-approval requirement yet:
                     with one maintainer it would only teach people to bypass it
actions           default GITHUB_TOKEN permission set to read-only
security          secret scanning, push protection, private vulnerability
                  reporting, Dependabot alerts
labels            synchronized from .github/labels.yml
issue types       Bug, Feature, Task, RFC, Research, Documentation, Refactor
                  (organization level; these do have a REST API)
```

**Ordering matters.** The initial commit has to be pushed *before* the ruleset
requiring pull requests is applied, or the first push is rejected by a rule that
exists to protect a branch with nothing on it.

---

## Must be done in the web UI

Not laziness — these have no usable API.

### 1. Crimson Development project

Projects v2 is GraphQL-only, and the API **cannot create or edit a project's
Status field**. The columns below have to be created by hand.

Create an organization project named **Crimson Development**, then set the
Status field options, in this order:

```
Triage        new, not yet assessed
Backlog       accepted, not scheduled
Ready         scoped, ready to be picked up
In Progress   being worked on
In Review     has an open pull request
Blocked       waiting on something external
Done          finished
```

Then create these views:

| View | Filter | Group by |
|---|---|---|
| Triage | `status:Triage` | Repository |
| Backlog | `status:Backlog` | Priority |
| Ready | `status:Ready` | Effort |
| Current | `status:"In Progress","In Review"` | Status |
| Blocked | `status:Blocked` | Area |
| Bugs | `type:Bug is:open` | Priority |
| Release | `target-release:<current>` | Status |
| Roadmap | — | Roadmap layout, by target date |
| Recently Done | `status:Done` | — |

Finally, under the project's workflows, enable:

- **Auto-add** items from `CrimsonMail/crimson`, setting Status to `Triage`
- **Auto-archive** items in `Done` after 30 days, so the project stays fast

### 2. Organization issue fields

Organization settings → Planning:

```
Priority     P0 Critical, P1 High, P2 Normal, P3 Low
Effort       XS, S, M, L, XL
Start date   date
Target date  date
```

Triage sets Priority; reporters are deliberately never asked for it.

### 3. Discussions categories

Enable Discussions on the organization, then create:

```
Announcements   announcement format
General         open-ended
Ideas           before something is a concrete proposal
Q&A             question/answer format
Development     architecture and implementation
Design          interface and interaction
Extensions      reserved for later
```

The issue forms already link to Q&A, Ideas and Development, so those three
should exist before the first external issue is filed.

### 4. Contact address

`CODE_OF_CONDUCT.md` points enforcement reports at the address on the
organization profile, falling back to the repository's Security tab. Add a
contact to the profile, or amend that line, before inviting contributors.

---

## Deliberately not configured yet

From the strategy's own "what not to configure yet" list, plus a few more:

```
merge queue                 needs several merges a day to be worth anything
CODEOWNERS                  needs more than one owner
teams                       needs more than one member
required approvals          would only teach bypassing with a single maintainer
release environments        nothing is released yet
reusable workflows          one repository has nothing to share with itself
repository properties       need several repositories to be worth targeting
organization rulesets       same
Crimson Bot                 workflow YAML is not painful yet
crash pipeline              needs a shipped build and a symbol store
SBOM / attestation /
signing                     need a release artifact to attest to
```

`CrimsonMail/.github` should exist early for the organization profile README and
shared defaults, but it is a separate repository and not covered here.
