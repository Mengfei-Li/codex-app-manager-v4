[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Installer,
    [Parameter(Mandatory = $true)]
    [string]$Target,
    [Parameter(Mandatory = $true)]
    [string]$Commit,
    [Parameter(Mandatory = $true)]
    [string]$ReleaseTag,
    [Parameter(Mandatory = $true)]
    [string]$RunId,
    [Parameter(Mandatory = $true)]
    [string]$ExpectedSubject,
    [Parameter(Mandatory = $true)]
    [string]$SmokeEvidence,
    [Parameter(Mandatory = $true)]
    [string]$Output
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ($Commit -notmatch '^[0-9a-f]{40}$') { throw "invalid release commit" }
if ($ReleaseTag -notmatch '^v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$') {
    throw "invalid release tag"
}
if ($Target -notin @('x86_64-pc-windows-msvc', 'aarch64-pc-windows-msvc')) {
    throw "invalid Windows target"
}
$expectedNative = if ($Target.StartsWith('aarch64-')) { 'ARM64' } else { 'AMD64' }
if ($env:PROCESSOR_ARCHITECTURE -ne $expectedNative) {
    throw "G6 evidence requires native $expectedNative runner"
}

$item = Get-Item -LiteralPath $Installer -ErrorAction Stop
$artifactSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $item.FullName).Hash.ToLowerInvariant()
$smoke = Get-Content -LiteralPath $SmokeEvidence -Raw -Encoding UTF8 | ConvertFrom-Json
if ($smoke.schema_version -ne 1 -or $smoke.status -ne 'passed' -or $smoke.platform -ne 'windows') {
    throw "invalid G6 Windows lifecycle receipt"
}
if ($smoke.runner_architecture -ne $expectedNative -or $smoke.artifact_sha256 -ne $artifactSha256) {
    throw "G6 Windows lifecycle receipt is not bound to this native artifact"
}
$requiredLifecycle = @('install', 'launch', 'upgrade', 'uninstall', 'signature_reverified_after_install')
foreach ($name in $requiredLifecycle) {
    if ($smoke.lifecycle.$name -ne $true) { throw "G6 Windows lifecycle receipt missing $name" }
}
if ($smoke.production_side_effects -ne $false) { throw "G6 Windows lifecycle touched production" }
& "$PSScriptRoot\verify-windows-authenticode.ps1" `
    -Path @($item.FullName) `
    -Mode required `
    -ExpectedSubject $ExpectedSubject `
    -RequireTimestamp `
    -Stage 'g6-evidence'

$signature = Get-AuthenticodeSignature -LiteralPath $item.FullName
if ($signature.Status -ne 'Valid' -or -not $signature.SignerCertificate) {
    throw "G6 Authenticode evidence is not valid"
}
if (-not $signature.TimeStamperCertificate) {
    throw "G6 Authenticode evidence has no trusted timestamp"
}

$evidence = [ordered]@{
    schema_version = 1
    gate = 'G6'
    status = 'passed'
    platform = 'windows'
    target = $Target
    runner_architecture = $env:PROCESSOR_ARCHITECTURE
    native_runner = $true
    release_tag = $ReleaseTag
    release_commit = $Commit
    release_run_id = [string]$RunId
    artifact = [ordered]@{
        name = $item.Name
        size = [int64]$item.Length
        sha256 = $artifactSha256
    }
    authenticode = [ordered]@{
        status = [string]$signature.Status
        signer_subject = $signature.SignerCertificate.Subject
        signer_thumbprint = $signature.SignerCertificate.Thumbprint.ToLowerInvariant()
        signer_not_after_utc = $signature.SignerCertificate.NotAfter.ToUniversalTime().ToString('o')
        timestamp_subject = $signature.TimeStamperCertificate.Subject
        timestamp_thumbprint = $signature.TimeStamperCertificate.Thumbprint.ToLowerInvariant()
    }
    lifecycle = $smoke.lifecycle
    lifecycle_receipt_sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $SmokeEvidence).Hash.ToLowerInvariant()
    production_side_effects = $false
}

$outputPath = [IO.Path]::GetFullPath($Output)
$parent = Split-Path -Parent $outputPath
New-Item -ItemType Directory -Path $parent -Force | Out-Null
$json = $evidence | ConvertTo-Json -Depth 8
[IO.File]::WriteAllText($outputPath, $json + "`n", [Text.UTF8Encoding]::new($false))
Write-Host "G6 Windows evidence written: $outputPath"
