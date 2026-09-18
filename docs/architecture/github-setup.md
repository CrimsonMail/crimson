# CrimsonMail GitHub Setup

What is configured, what is scripted, and what has to be clicked.

Most of the operating model lives in this repository as files — issue forms,
workflows, labels, Dependabot, community health files — and is reviewed like
code. The rest is GitHub configuration, and some of it has no API.

---

## Configured as files (already in the repository)

| Area | Where |
|---|---|
| Community health | `README.md`, `CONTRIBUTING.md`, `SECURITY.md`, `SUPPORT.md`, `CODE_OF_CONDUCT.md`, `CONTRIBUTORS.md`, `CHANGELOG.md`, `LICENSE` |
| Issue intake | `.github/ISSUE_TEMPLATE/*.yml` — blank issues disabled, questions routed to Discussions |
| Discussion forms | `.github/DISCUSSION_TEMPLATE/{ideas,q-a,development}.yml` |
| Pull requests | `.github/PULL_REQUEST_TEMPLATE.md` |
| Labels | `.github/labels.yml`, applied with `scripts/sync-labels.ps1` |
| Area labelling | `.github/labeler.yml` (paths), issue-form Area answers |
| Release notes | `.github/release.yml` — categories keyed on `changelog:` labels |
| Action updates | `.github/dependabot.yml` |
| Design proposals | `docs/rfcs/` |
| CI | `.github/workflows/{pr,main,nightly,codeql,dependency-review}.yml` |
| Automation | `.github/workflows/{issue-triage,labeler,pr-metadata,workflow-health,welcome}.yml` |
| Release | `.github/workflows/{release,release-checklist}.yml`, `scripts/{generate-sbom,draft-changelog}.ps1` |
| Workflow hardening | `scripts/check-workflows.py`, run on every pull request |

---

## Runbook: creating and configuring the repository

Requires the GitHub CLI, authenticated:

```powershell
winget install --id GitHub.cli
```

```powershell
gh auth login --hostname github.com --git-protocol https --web
```

**Order matters.** The first push has to land *before* the ruleset requiring
pull requests exists, or it is rejected by a rule protecting a branch with
nothing on it yet.

### 1. Create and push

```powershell
gh repo create CrimsonMail/crimson --public --source . --remote origin --push --description "A native, local-first desktop communication client for Windows."
```

### 2. Topics

```powershell
gh repo edit CrimsonMail/crimson --add-topic email --add-topic email-client --add-topic imap --add-topic smtp --add-topic windows --add-topic cpp --add-topic open-source
```

### 3. Merge settings

Squash only, so `main` carries one commit per logical change and the squash
title becomes the changelog entry.

```powershell
gh repo edit CrimsonMail/crimson --enable-squash-merge --enable-merge-commit=false --enable-rebase-merge=false --delete-branch-on-merge --enable-wiki=false
```

### 4. Labels

Dry run first; it changes nothing without `-Apply`.

```powershell
.\scripts\sync-labels.ps1
```

```powershell
.\scripts\sync-labels.ps1 -Apply
```

### 5. Security features

Nested fields go in as JSON. `gh api -f` flattens keys, so bracket notation like
`-f a[b]=c` does not reliably produce a nested object.

Commands here are PowerShell, since that is the shell on a Windows-first
project. PowerShell has no heredoc, so JSON bodies are piped in as a
single-quoted string — single quotes stop PowerShell interpolating, and the
double quotes inside are left alone.

```powershell
'{"security_and_analysis":{"secret_scanning":{"status":"enabled"},"secret_scanning_push_protection":{"status":"enabled"}}}' | gh api -X PATCH repos/CrimsonMail/crimson --input -
```

```powershell
gh api -X PUT repos/CrimsonMail/crimson/private-vulnerability-reporting
```

For a longer body, a PowerShell here-string (`@'` … `'@`, with the closing
delimiter at column zero) is more readable and works the same way.

Dependabot alerts are on by default for public repositories; confirm under
Settings → Code security.

### 6. Actions token default

Read-only, widened per workflow. Never `write-all`.

```powershell
gh api -X PUT repos/CrimsonMail/crimson/actions/permissions/workflow -f default_workflow_permissions=read -F can_approve_pull_request_reviews=false
```

### 7. Protect `main`

Do this only after the first push, and after at least one CI run has reported
its check names — required checks are matched by name, so naming a check that
has never run blocks every merge.

The `rules` array cannot be expressed with `-f` flags; send JSON.

```powershell
@'
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
'@ | gh api -X POST repos/CrimsonMail/crimson/rulesets --input -
```

The closing `'@` must be at column zero, on its own line. Indenting it is a
PowerShell parse error.

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

```powershell
foreach ($t in 'Bug','Feature','Task','RFC','Research','Documentation','Refactor') {
  gh api -X POST orgs/CrimsonMail/issue-types -f name=$t -F is_enabled=true
}
```

If this returns 404 or 422, the endpoint shape has moved; set them under
Organization settings → Planning instead. It is seven fields entered once.

### Check it took

```powershell
gh repo view CrimsonMail/crimson
```

```powershell
gh label list --repo CrimsonMail/crimson
```

Then confirm the ruleset actually bites. This push must be **rejected**:

```powershell
git push origin main
```

That last line is the real test. If a direct push to `main` succeeds, the
ruleset is not doing anything.

---

## Step 2 additions

Configuration introduced with the automation and release pipeline. All
PowerShell, one command per block.

### 9. Sync the new labels

The PR metadata check needs the `changelog:` labels to exist before any pull
request can pass it — including the pull request that adds the check. Run this
from a checkout that has the updated `labels.yml`, i.e. on the
`ci/github-automation` branch or after it merges:

```powershell
.\scripts\sync-labels.ps1 -Apply
```

### 10. Require the checks

Only once every check below has reported on at least one pull request.
Required checks are matched by name, so naming one that has never run blocks
every merge, and the error does not say why.

| Check | Workflow |
|---|---|
| `Build and test (Debug)` | `pr.yml` |
| `Build and test (Release)` | `pr.yml` |
| `Lint workflows` | `pr.yml` |
| `Changelog metadata` | `pr-metadata.yml` |
| `Dependency review` | `dependency-review.yml` |
| `Analyze C++` | `codeql.yml` |

Each is pinned to `integration_id` 15368, the GitHub Actions app, so a
different app posting a passing status with the same name cannot satisfy the
rule. Find the ruleset's id:

```powershell
$id = (gh api repos/CrimsonMail/crimson/rulesets | ConvertFrom-Json | Where-Object name -eq 'main').id
```

Then replace it with the same rules plus the required checks. `PUT` replaces the
whole ruleset, which is why the existing rules are repeated:

```powershell
@'
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
    },
    {
      "type": "required_status_checks",
      "parameters": {
        "strict_required_status_checks_policy": false,
        "required_status_checks": [
          { "context": "Build and test (Debug)", "integration_id": 15368 },
          { "context": "Build and test (Release)", "integration_id": 15368 },
          { "context": "Lint workflows", "integration_id": 15368 },
          { "context": "Changelog metadata", "integration_id": 15368 },
          { "context": "Dependency review", "integration_id": 15368 },
          { "context": "Analyze C++", "integration_id": 15368 }
        ]
      }
    }
  ]
}
'@ | gh api -X PUT "repos/CrimsonMail/crimson/rulesets/$id" --input -
```

`strict_required_status_checks_policy` is off: with one maintainer and squash
merges, forcing every branch to be rebased onto the latest `main` before
merging adds friction without catching anything the checks on `main` itself
would not.

### 11. Immutable releases

Once a release is published, its tag and assets are locked. This is what
`release.yml`'s draft-then-publish flow is built around:

```powershell
gh api -X PUT repos/CrimsonMail/crimson/immutable-releases
```

Confirm it took:

```powershell
gh api repos/CrimsonMail/crimson/immutable-releases
```

### 12. The organization's `.github` repository

Prepared locally at `F:\CrimsonMail\.github`: the organization profile page and
default community files for any future repository that lacks its own.

```powershell
cd F:\CrimsonMail\.github
```

```powershell
gh repo create CrimsonMail/.github --public --source . --remote origin --push --description "Organization profile and default community files for CrimsonMail."
```

### What cannot be tested from a pull request

`workflow_run` and `pull_request_target` workflows run from the definition on
`main`, so `workflow-health`, `labeler` and `welcome` only start working once
merged. `release.yml` runs only on a pushed tag, and `release-checklist.yml`
only when dispatched:

```powershell
gh workflow run release-checklist.yml --repo CrimsonMail/crimson -f version=0.1.0
```

---

## Must be done in the web UI

Not laziness — these have no usable API.

### 1. Crimson Development project

Projects v2 is GraphQL-only, and the API **cannot create or edit a project's
Status field**. The columns below have to be created by hand.

Create an organization project named **Crimson Development**, then set the
Status field options, in this order:

```text
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

There is deliberately no `project-sync.yml` workflow doing this instead. A
workflow's `GITHUB_TOKEN` cannot write to organization Projects, so it would
need a long-lived personal access token stored as a secret — which the
advanced infrastructure strategy says to avoid — to reproduce what these
built-in workflows do for free.

### 2. Organization issue fields

Organization settings → Planning:

```text
Priority     P0 Critical, P1 High, P2 Normal, P3 Low
Effort       XS, S, M, L, XL
Start date   date
Target date  date
```

Triage sets Priority; reporters are deliberately never asked for it.

### 3. Discussions categories

Enable Discussions on the organization and choose **`CrimsonMail/crimson` as
the source repository** — organization discussions are stored in a repository,
and the discussion forms in `.github/DISCUSSION_TEMPLATE/` only apply in the
repository that holds them.

Then create these categories. Each form's file name has to equal its
category's slug, so **Ideas, Q&A and Development must keep exactly those
names** (slugs `ideas`, `q-a`, `development`) or their forms silently stop
appearing:

```text
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

```text
merge queue                 needs several merges a day to be worth anything
CODEOWNERS                  needs more than one owner
teams                       needs more than one member
required approvals          would only teach bypassing with a single maintainer
release environments        one maintainer publishes by hand, and release.yml
                            already stops at a draft
reusable workflows          one repository has nothing to share with itself
repository properties       need several repositories to be worth targeting
organization rulesets       same
project-sync workflow       the Project's built-in workflows do it without a PAT
code signing                needs a certificate and somewhere stronger than a
                            repository secret to keep its key
Crimson Bot                 workflow YAML is not painful yet
crash pipeline              needs a shipped application and a symbol store
stale-issue closing         age is a prompt for review, never a reason to close
```
