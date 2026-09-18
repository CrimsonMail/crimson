<#
.SYNOPSIS
    Generates an SPDX 2.3 SBOM describing the binaries in a Crimson build.

.DESCRIPTION
    Crimson takes no third-party libraries, so its source tree has no
    dependency manifest to read an SBOM from. That does not mean the shipped
    binaries have no dependencies: the supply-chain model is explicit that the
    SBOM must describe "the actual shipped build, not just source manifests".

    So this reads the binaries themselves. For each executable it runs
    `dumpbin /dependents` and sorts the imported DLLs into:

      Visual C++ runtime  Crimson builds with /MD, so its binaries load
                          VCRUNTIME140.dll and friends at run time. Those come
                          from the Visual C++ Redistributable, which is a real
                          external component and is listed as one.
      Windows             kernel32, ws2_32, the api-ms-win-* API sets and the
                          Universal CRT: operating-system components, imported
                          but never redistributed.

    Anything else is an unexpected dependency and fails the script, as does a
    debug or AddressSanitizer runtime turning up in what is meant to be a
    release build.

    Needs dumpbin, which ships with the MSVC toolset. It is located through
    vswhere, so no developer prompt is required.

.PARAMETER BinaryDirectory
    Directory containing the built executables, e.g. x64\Release.

.PARAMETER Version
    The Crimson version being described, without a leading "v".

.PARAMETER Output
    Path of the SPDX JSON file to write.

.PARAMETER Exclude
    Executables to leave out. Defaults to the test runner, which is never shipped.

.EXAMPLE
    ./scripts/generate-sbom.ps1 -BinaryDirectory x64/Release -Version 0.1.0 -Output dist/crimson-0.1.0.spdx.json
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$BinaryDirectory,
    [Parameter(Mandatory)] [string]$Version,
    [Parameter(Mandatory)] [string]$Output,
    [string[]]$Exclude = @('Crimson.Tests.exe')
)

$ErrorActionPreference = 'Stop'

# --- Locate dumpbin -----------------------------------------------------------

$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
if (-not (Test-Path $vswhere)) { throw "vswhere.exe not found; is Visual Studio installed?" }

$vsPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $vsPath) { throw "No Visual Studio installation with the C++ toolset was found." }

$dumpbin = Get-ChildItem -Path (Join-Path $vsPath 'VC\Tools\MSVC') -Recurse -Filter dumpbin.exe |
    Where-Object { $_.FullName -match '\\bin\\Hostx64\\x64\\' } |
    Sort-Object FullName -Descending |
    Select-Object -First 1
if (-not $dumpbin) { throw "dumpbin.exe not found under $vsPath" }

# The toolset that built the binaries is the minimum runtime they need.
$toolset = ($dumpbin.FullName -split '\\MSVC\\')[1].Split('\')[0]

# --- Collect imports ------------------------------------------------------------

$binaries = Get-ChildItem -Path $BinaryDirectory -Filter *.exe |
    Where-Object { $_.Name -notin $Exclude } |
    Sort-Object Name
if (-not $binaries) { throw "No executables to describe in $BinaryDirectory" }

$runtimeDlls = [System.Collections.Generic.SortedSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$windowsDlls = [System.Collections.Generic.SortedSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$problems = @()

foreach ($binary in $binaries) {
    $lines = & $dumpbin.FullName /nologo /dependents $binary.FullName
    if ($LASTEXITCODE -ne 0) { throw "dumpbin failed on $($binary.Name)" }

    # The list sits between "has the following dependencies:" and the next
    # blank line after it. (A separate delay-load list would follow; Crimson
    # does not delay-load anything, and that list is not read.)
    $inList = $false
    $seen = $false
    foreach ($line in $lines) {
        $text = $line.Trim()
        if ($text -match 'has the following dependencies') { $inList = $true; continue }
        if (-not $inList) { continue }
        if ($text -eq '') { if ($seen) { break } else { continue } }
        $seen = $true
        if ($text -notmatch '\.dll$') { continue }

        switch -Regex ($text) {
            '^(VCRUNTIME140D|MSVCP140D|ucrtbased)'       { $problems += "$($binary.Name) imports the debug runtime $text"; break }
            '^clang_rt\.asan'                             { $problems += "$($binary.Name) imports the AddressSanitizer runtime $text"; break }
            '^(VCRUNTIME140|VCRUNTIME140_1|MSVCP140|MSVCP140_1|MSVCP140_2|MSVCP140_ATOMIC_WAIT|MSVCP140_CODECVT_IDS|CONCRT140|VCCORLIB140)\.dll$' { [void]$runtimeDlls.Add($text); break }
            '^(api-ms-win-|ext-ms-win-)'                  { [void]$windowsDlls.Add($text); break }
            default {
                if (Test-Path (Join-Path $env:SystemRoot "System32\$text")) {
                    [void]$windowsDlls.Add($text)
                }
                else {
                    $problems += "$($binary.Name) imports $text, which is neither a Windows component nor the Visual C++ runtime"
                }
            }
        }
    }
}

if ($problems) {
    $problems | ForEach-Object { Write-Error $_ -ErrorAction Continue }
    throw "The binaries have dependencies an SBOM for a release build should not contain."
}

# --- Build the SPDX document ------------------------------------------------------

$shipped = ($binaries | ForEach-Object Name) -join ', '
$created = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

$packages = @(
    [ordered]@{
        name             = 'Crimson'
        SPDXID           = 'SPDXRef-Package-Crimson'
        versionInfo      = $Version
        supplier         = 'Organization: CrimsonMail'
        downloadLocation = "https://github.com/CrimsonMail/crimson/releases/tag/v$Version"
        filesAnalyzed    = $false
        licenseConcluded = 'MPL-2.0'
        licenseDeclared  = 'MPL-2.0'
        copyrightText    = 'NOASSERTION'
        primaryPackagePurpose = 'APPLICATION'
        comment          = "Shipped executables: $shipped. Built with no third-party libraries (ADR 0004)."
        externalRefs     = @(
            [ordered]@{
                referenceCategory = 'PACKAGE-MANAGER'
                referenceType     = 'purl'
                referenceLocator  = "pkg:github/CrimsonMail/crimson@v$Version"
            }
        )
    }
)

$relationships = @(
    [ordered]@{ spdxElementId = 'SPDXRef-DOCUMENT'; relationshipType = 'DESCRIBES'; relatedSpdxElement = 'SPDXRef-Package-Crimson' }
)

if ($runtimeDlls.Count -gt 0) {
    $packages += [ordered]@{
        name             = 'Microsoft Visual C++ Redistributable'
        SPDXID           = 'SPDXRef-Package-VCRedist'
        versionInfo      = "$toolset or later"
        supplier         = 'Organization: Microsoft Corporation'
        downloadLocation = 'https://aka.ms/vs/17/release/vc_redist.x64.exe'
        filesAnalyzed    = $false
        licenseConcluded = 'NOASSERTION'
        licenseDeclared  = 'NOASSERTION'
        copyrightText    = 'NOASSERTION'
        primaryPackagePurpose = 'LIBRARY'
        comment          = "Loaded at run time because Crimson links the dynamic CRT (/MD): $($runtimeDlls -join ', '). Must be present on the target machine; not bundled."
    }
    $relationships += [ordered]@{ spdxElementId = 'SPDXRef-Package-Crimson'; relationshipType = 'DEPENDS_ON'; relatedSpdxElement = 'SPDXRef-Package-VCRedist' }
}

if ($windowsDlls.Count -gt 0) {
    $packages += [ordered]@{
        name             = 'Microsoft Windows'
        SPDXID           = 'SPDXRef-Package-Windows'
        versionInfo      = '10.0 or later'
        supplier         = 'Organization: Microsoft Corporation'
        downloadLocation = 'NOASSERTION'
        filesAnalyzed    = $false
        licenseConcluded = 'NOASSERTION'
        licenseDeclared  = 'NOASSERTION'
        copyrightText    = 'NOASSERTION'
        primaryPackagePurpose = 'OPERATING-SYSTEM'
        comment          = "Operating-system components imported, never redistributed: $($windowsDlls -join ', ')."
    }
    $relationships += [ordered]@{ spdxElementId = 'SPDXRef-Package-Crimson'; relationshipType = 'DEPENDS_ON'; relatedSpdxElement = 'SPDXRef-Package-Windows' }
}

$document = [ordered]@{
    spdxVersion       = 'SPDX-2.3'
    dataLicense       = 'CC0-1.0'
    SPDXID            = 'SPDXRef-DOCUMENT'
    name              = "crimson-$Version-windows-x64"
    documentNamespace = "https://github.com/CrimsonMail/crimson/spdx/crimson-$Version-$([guid]::NewGuid())"
    creationInfo      = [ordered]@{
        created  = $created
        creators = @('Organization: CrimsonMail', 'Tool: crimson-generate-sbom')
    }
    documentDescribes = @('SPDXRef-Package-Crimson')
    packages          = $packages
    relationships     = $relationships
}

$directory = Split-Path -Parent $Output
if ($directory -and -not (Test-Path $directory)) { New-Item -ItemType Directory -Path $directory | Out-Null }

$document | ConvertTo-Json -Depth 10 | Set-Content -Path $Output -Encoding utf8NoBOM

Write-Host "SBOM written to $Output"
Write-Host "  binaries:           $shipped"
Write-Host "  Visual C++ runtime: $(if ($runtimeDlls.Count) { $runtimeDlls -join ', ' } else { 'none' })"
Write-Host "  Windows components: $($windowsDlls.Count)"
