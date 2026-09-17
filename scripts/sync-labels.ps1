<#
.SYNOPSIS
    Synchronizes GitHub issue labels from .github/labels.yml.

.DESCRIPTION
    Labels are kept as data so they can be reviewed in a pull request rather
    than clicked into a settings page and forgotten. This script applies that
    file to a repository.

    Shows what it would do by default. Pass -Apply to actually change anything.

    The YAML parsing here is hand-rolled rather than using a module, because
    labels.yml has a fixed, trivial shape (a flat list of name/color/description)
    and Crimson does not take dependencies it does not need. It is not a general
    YAML parser and does not pretend to be.

.PARAMETER Repo
    owner/name. Defaults to CrimsonMail/crimson.

.PARAMETER Apply
    Actually create and update labels. Without it, nothing is changed.

.PARAMETER Prune
    Also delete labels present on the repository but absent from labels.yml.
    Off by default: GitHub creates a set of defaults on every new repository,
    and deleting a label silently removes it from every issue that carries it.

.EXAMPLE
    ./scripts/sync-labels.ps1
    Show what would change.

.EXAMPLE
    ./scripts/sync-labels.ps1 -Apply
    Create and update labels, leaving unknown ones alone.

.EXAMPLE
    ./scripts/sync-labels.ps1 -Apply -Prune
    Also remove labels that are not in labels.yml.
#>
[CmdletBinding()]
param(
    [string]$Repo = 'CrimsonMail/crimson',
    [switch]$Apply,
    [switch]$Prune
)

$ErrorActionPreference = 'Stop'

if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
    throw "The GitHub CLI is not installed. Install it with: winget install --id GitHub.cli"
}

$labelsPath = Join-Path $PSScriptRoot '..\.github\labels.yml'
if (-not (Test-Path $labelsPath)) {
    throw "Could not find $labelsPath"
}

# --- Parse labels.yml -------------------------------------------------------
# Expected shape, and nothing more:
#   - name: "area: networking"
#     color: "4A5568"
#     description: "TCP, DNS, sockets, byte streams"

$desired = [System.Collections.Generic.List[object]]::new()
$current = $null

foreach ($rawLine in Get-Content -LiteralPath $labelsPath) {
    $line = $rawLine.TrimEnd()
    if ($line -match '^\s*#' -or $line -match '^\s*$') { continue }

    if ($line -match '^\s*-\s+name:\s*(.+)$') {
        if ($null -ne $current) { $desired.Add($current) }
        $current = [pscustomobject]@{ name = $Matches[1].Trim('"', "'", ' '); color = ''; description = '' }
    }
    elseif ($line -match '^\s+color:\s*(.+)$' -and $null -ne $current) {
        $current.color = $Matches[1].Trim('"', "'", ' ')
    }
    elseif ($line -match '^\s+description:\s*(.+)$' -and $null -ne $current) {
        $current.description = $Matches[1].Trim('"', "'", ' ')
    }
}
if ($null -ne $current) { $desired.Add($current) }

if ($desired.Count -eq 0) { throw "No labels parsed from $labelsPath" }

foreach ($label in $desired) {
    if ($label.color -notmatch '^[0-9a-fA-F]{6}$') {
        throw "Label '$($label.name)' has an invalid colour: '$($label.color)' (expected six hex digits)"
    }
}

Write-Host "Parsed $($desired.Count) labels from .github/labels.yml" -ForegroundColor Cyan
Write-Host "Target repository: $Repo`n"

# --- Read what is already there --------------------------------------------
$existing = @{}
try {
    $json = gh label list --repo $Repo --limit 200 --json name,color,description 2>$null
    if ($LASTEXITCODE -eq 0 -and $json) {
        foreach ($item in ($json | ConvertFrom-Json)) { $existing[$item.name] = $item }
    }
}
catch {
    Write-Warning "Could not list existing labels. Does $Repo exist, and is gh authenticated?"
    throw
}

# --- Work out the changes ---------------------------------------------------
$toCreate = @()
$toUpdate = @()

foreach ($label in $desired) {
    if (-not $existing.ContainsKey($label.name)) {
        $toCreate += $label
    }
    elseif ($existing[$label.name].color -ne $label.color -or
            $existing[$label.name].description -ne $label.description) {
        $toUpdate += $label
    }
}

$desiredNames = $desired | ForEach-Object { $_.name }
$toDelete = $existing.Keys | Where-Object { $_ -notin $desiredNames }

foreach ($label in $toCreate) { Write-Host "  create  $($label.name)" -ForegroundColor Green }
foreach ($label in $toUpdate) { Write-Host "  update  $($label.name)" -ForegroundColor Yellow }
foreach ($name in $toDelete) {
    $verb = if ($Prune) { 'delete ' } else { 'leave  ' }
    $colour = if ($Prune) { 'Red' } else { 'DarkGray' }
    Write-Host "  $verb $name" -ForegroundColor $colour
}

if ($toCreate.Count -eq 0 -and $toUpdate.Count -eq 0 -and -not ($Prune -and $toDelete)) {
    Write-Host "`nAlready in sync." -ForegroundColor Cyan
    return
}

if (-not $Apply) {
    Write-Host "`nNothing changed. Re-run with -Apply to make these changes." -ForegroundColor Cyan
    return
}

# --- Apply ------------------------------------------------------------------
foreach ($label in ($toCreate + $toUpdate)) {
    # --force creates the label, or updates it if it already exists.
    gh label create $label.name --repo $Repo --color $label.color --description $label.description --force | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Failed to apply label '$($label.name)'" }
}

if ($Prune) {
    foreach ($name in $toDelete) {
        gh label delete $name --repo $Repo --yes | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Failed to delete label '$name'" }
    }
}

Write-Host "`nDone: $($toCreate.Count) created, $($toUpdate.Count) updated$(if ($Prune) { ", $($toDelete.Count) deleted" })." -ForegroundColor Green
