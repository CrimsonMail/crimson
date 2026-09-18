<#
.SYNOPSIS
    Drafts a CHANGELOG.md section for a release from merged pull requests.

.DESCRIPTION
    Crimson's changelog is generated from merged pull request metadata at
    release time, not maintained by hand (the changelog specification's
    "Model B"). This asks GitHub for the release notes it would generate for
    the tag — which follow the categories in .github/release.yml, keyed on the
    `changelog:` labels that pr-metadata.yml requires — and rewrites them into
    Keep a Changelog form.

    It prints the section. It changes nothing: paste it at the top of
    CHANGELOG.md in a pull request, and edit the wording there. The output is a
    draft for a maintainer, not the final text.

    The tag does not need to exist yet.

.PARAMETER Tag
    The version being released, with or without the leading "v".

.PARAMETER PreviousTag
    The release to compare against. GitHub picks the previous tag if omitted.

.PARAMETER Target
    Branch or commit the release will be cut from. Defaults to main.

.PARAMETER FromFile
    Read a saved generate-notes response (JSON, or the bare markdown body)
    instead of calling GitHub. For working offline, and for testing.

.EXAMPLE
    ./scripts/draft-changelog.ps1 -Tag 0.2.0

.EXAMPLE
    ./scripts/draft-changelog.ps1 -Tag 0.2.0 -PreviousTag 0.1.0 | Set-Clipboard
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$Tag,
    [string]$PreviousTag,
    [string]$Repo = 'CrimsonMail/crimson',
    [string]$Target = 'main',
    [string]$FromFile,
    [datetime]$Date = (Get-Date)
)

$ErrorActionPreference = 'Stop'

$version = $Tag.TrimStart('v')
$tagName = "v$version"

# --- Get GitHub's generated notes -------------------------------------------------

if ($FromFile) {
    $raw = Get-Content -Raw -LiteralPath $FromFile
    $body = if ($raw.TrimStart().StartsWith('{')) { ($raw | ConvertFrom-Json).body } else { $raw }
}
else {
    if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
        throw "The GitHub CLI is not installed. Install it with: winget install --id GitHub.cli"
    }
    $arguments = @('api', '-X', 'POST', "repos/$Repo/releases/generate-notes",
                   '-f', "tag_name=$tagName", '-f', "target_commitish=$Target")
    if ($PreviousTag) { $arguments += @('-f', "previous_tag_name=v$($PreviousTag.TrimStart('v'))") }
    $json = & gh @arguments
    if ($LASTEXITCODE -ne 0) { throw "GitHub refused to generate notes for $tagName." }
    $body = ($json | ConvertFrom-Json).body
}

# --- Rewrite into Keep a Changelog form ------------------------------------------
#
# GitHub produces:
#
#   ## What's Changed
#   ### Added
#   * Add TLS over Schannel by @someone in https://github.com/.../pull/4
#   ## New Contributors
#   * @someone made their first contribution in https://github.com/.../pull/4
#   **Full Changelog**: https://github.com/.../compare/v0.1.0...v0.2.0

$sections = [ordered]@{}
$current = $null
$compare = $null
$uncategorised = 0
$inChanges = $false

foreach ($line in ($body -split "`r?`n")) {
    if ($line -match '^##\s+What''s Changed') { $inChanges = $true; continue }
    if ($line -match '^##\s+(?!#)') { $inChanges = $false; $current = $null }
    if ($line -match '^\*\*Full Changelog\*\*:\s*(\S+)') { $compare = $Matches[1]; continue }
    if (-not $inChanges) { continue }

    if ($line -match '^###\s+(.+?)\s*$') {
        $current = $Matches[1]
        if ($current -eq 'Other Changes') { $current = 'Other' }
        if (-not $sections.Contains($current)) { $sections[$current] = [System.Collections.Generic.List[string]]::new() }
        continue
    }

    if ($line -match '^\*\s+(.+?)\s+by\s+@\S+\s+in\s+(https://\S+/pull/(\d+))\s*$') {
        if (-not $current) {
            $current = 'Other'
            if (-not $sections.Contains($current)) { $sections[$current] = [System.Collections.Generic.List[string]]::new() }
        }
        if ($current -eq 'Other') { $uncategorised++ }
        $sections[$current].Add("- $($Matches[1]) ([#$($Matches[3])]($($Matches[2])))")
    }
}

# --- Emit --------------------------------------------------------------------------

$out = [System.Text.StringBuilder]::new()
[void]$out.AppendLine("## [$version] - $($Date.ToString('yyyy-MM-dd'))")

if ($sections.Count -eq 0) {
    [void]$out.AppendLine()
    [void]$out.AppendLine('No user-facing changes.')
}
foreach ($name in $sections.Keys) {
    [void]$out.AppendLine()
    [void]$out.AppendLine("### $name")
    [void]$out.AppendLine()
    foreach ($entry in $sections[$name]) { [void]$out.AppendLine($entry) }
}

if ($compare) {
    [void]$out.AppendLine()
    [void]$out.AppendLine("[$version]: $compare")
}

$out.ToString().TrimEnd()

if ($uncategorised -gt 0) {
    Write-Warning "$uncategorised change(s) had no release-note category and were placed under 'Other'. pr-metadata.yml should have prevented that; categorise them before publishing."
}
