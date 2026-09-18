<#
.SYNOPSIS
    Checks that every PowerShell example in the documentation actually parses.

.DESCRIPTION
    Crimson is Windows-first and its documentation gives PowerShell commands,
    many of them copied straight into a terminal. A command that is really bash
    — a `<<'EOF'` heredoc, a trailing `\` line continuation, a `for ...; do`
    loop — fails at PowerShell's parser before anything runs, which is exactly
    what happened to an early version of docs/architecture/github-setup.md.

    So every ```powershell block in every Markdown file is handed to
    PowerShell's own parser, and any JSON body piped into a command, as a
    here-string or a single-quoted string, is validated too.

    Nothing is executed. This only proves the examples are well-formed.

.PARAMETER Path
    Markdown files or directories to check. Defaults to the whole repository.
#>
[CmdletBinding()]
param(
    [string[]]$Path = @((Join-Path $PSScriptRoot '..'))
)

$ErrorActionPreference = 'Stop'

$files = foreach ($item in $Path) {
    if (Test-Path -LiteralPath $item -PathType Container) {
        Get-ChildItem -LiteralPath $item -Recurse -Filter *.md -File |
            Where-Object { $_.FullName -notmatch '[\\/](\.git|x64|obj|node_modules)[\\/]' }
    }
    else {
        Get-Item -LiteralPath $item
    }
}

$blocksChecked = 0
$problems = [System.Collections.Generic.List[string]]::new()
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path

foreach ($file in $files) {
    $text = Get-Content -Raw -LiteralPath $file.FullName
    if (-not $text) { continue }
    $shown = $file.FullName.Replace($root, '').TrimStart('\', '/')

    foreach ($block in [regex]::Matches($text, '(?ms)^```powershell\r?\n(.*?)^```')) {
        $blocksChecked++
        $code = $block.Groups[1].Value
        $line = ($text.Substring(0, $block.Index) -split "`n").Count

        $tokens = $null
        $errors = $null
        [void][System.Management.Automation.Language.Parser]::ParseInput($code, [ref]$tokens, [ref]$errors)
        foreach ($parseError in $errors) {
            $problems.Add("${shown}:$($line + $parseError.Extent.StartLineNumber): $($parseError.Message)")
        }
        if ($errors.Count -gt 0) { continue }

        $json = $null
        $here = [regex]::Match($code, "(?ms)^@'\r?\n(.*?)\r?\n'@")
        if ($here.Success) {
            $json = $here.Groups[1].Value
        }
        else {
            $single = [regex]::Match($code, "^'(\{.*\})'\s*\|")
            if ($single.Success) { $json = $single.Groups[1].Value }
        }
        if ($json) {
            try { $null = $json | ConvertFrom-Json -ErrorAction Stop }
            catch { $problems.Add("${shown}:$($line + 1): JSON body does not parse: $($_.Exception.Message)") }
        }
    }
}

$problems | ForEach-Object { Write-Host $_ }

if ($problems.Count -gt 0) {
    Write-Host "`n$($problems.Count) problem(s) in $blocksChecked PowerShell example(s)."
    exit 1
}

Write-Host "$blocksChecked PowerShell example(s) in $(@($files).Count) Markdown file(s) parse cleanly."
exit 0
