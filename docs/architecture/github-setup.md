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

## Runbook: creating and configuring the repository

Requires the GitHub CLI, authenticated:

```
winget install --id GitHub.cli
gh auth login --hostname github.com --git-protocol https --web
```

**Order matters.** The first push has to land *before* the ruleset requiring
pull requests exists, or it is rejected by a rule protecting a branch with
nothing on it yet.

### 1. Create and push

```
gh repo create CrimsonMail/crimson --public --source . --remote origin --push \
  --description "A native, local-first desktop communication client for Windows."
```

### 2. Topics

```
gh repo edit CrimsonMail/crimson --add-topic email --add-topic email-client \
  --add-topic imap --add-topic smtp --add-topic windows --add-topic cpp \
  --add-topic open-source
```

### 3. Merge settings

Squash only, so `main` carries one commit per logical change and the squash
title becomes the changelog entry.

```
gh repo edit CrimsonMail/crimson \
  --enable-squash-merge --enable-merge-commit=false --enable-rebase-merge=false \
  --delete-branch-on-merge --enable-wiki=false
```

### 4. Labels

```
./scripts/sync-labels.ps1                 # show what would change
./scripts/sync-labels.ps1 -Apply          # apply it
```

### 5. Security features

Nested fields go in as JSON. `gh api -f` flattens keys, so bracket notation
like `-f a[b]=c` does not reliably produce a nested object.

```
gh api -X PATCH repos/CrimsonMail/crimson --input - <<'JSON'
{
  "security_and_analysis": {
    "secret_scanning": { "status": "enabled" },
    "secret_scanning_push_protection": { "status": "enabled" }
  }
}
JSON

gh api -X PUT repos/CrimsonMail/crimson/private-vulnerability-reporting
```

Dependabot alerts are on by default for public repositories; confirm under
Settings → Code security.

### 6. Actions token default

Read-only, widened per workflow. Never `write-all`.

```
gh api -X PUT repos/CrimsonMail/crimson/actions/permissions/workflow \
  -f default_workflow_permissions=read \
  -F can_approve_pull_request_reviews=false
```

### 7. Protect `main`

Do this only after the first push, and after at least one CI run has reported
its check names — required checks are matched by name, so naming a check that
has never run blocks every merge.

The `rules` array cannot be expressed with `-f` flags; send JSON.

```
gh api -X POST repos/CrimsonMail/crimson/rulesets --input - <<'JSON'
{
  "name": "main",
  "target": "branch",
  "enforcement": "active",
  "conditions": { "ref_name": { "include": ["~DEFAULT_BRANCH"], "exclude": [] } },
  "rules": [
    { "type": "deletion" },
    { "type": "non_fast_forward" },
    {
      "type": "pull_request",
      "parameters": {
        "required_approving_review_count": 0,
        "dismiss_stale_reviews_on_push": true,
        "require_code_owner_review": false,
        "require_last_push_approval": false,
        "required_review_thread_resolution": true,
        "allowed_merge_methods": ["squash"]
      }
    }
  ]
}
JSON
```

No second-approval requirement yet. With one maintainer it would only teach
bypassing, which is worse than not having the rule. Raise
`required_approving_review_count` to 1 when there is a second person.

Required status checks are deliberately absent from this ruleset. They are
matched by check name, so adding one before that check has ever reported blocks
every merge with no obvious cause. Add them once the PR workflow has run at
least once and the names are known, either in the UI or by including a
`required_status_checks` rule.

### 8. Organization issue types

These have a REST API, unlike the project fields below.

```
for t in Bug Feature Task RFC Research Documentation Refactor; do
  gh api -X POST orgs/CrimsonMail/issue-types -f name="$t" -F is_enabled=true
done
```

If this returns 404 or 422, the endpoint shape has moved; set them under
Organization settings → Planning instead. It is seven fields entered once.

### Check it took

```
gh repo view CrimsonMail/crimson
gh label list --repo CrimsonMail/crimson
gh api repos/CrimsonMail/crimson/rulesets
git push origin main          # should now be REJECTED
```

That last line is the real test. If a direct push to `main` succeeds, the
ruleset is not doing anything.

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
