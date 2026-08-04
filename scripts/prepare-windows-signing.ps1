# Import the production Authenticode identity for a Tauri build and emit a
# one-run JSON merge config. The PFX stays in the current-user certificate
# store only for this CI job; cleanup-windows-signing.ps1 removes it.

[CmdletBinding()]
param(
    [string]$CertificateBase64 = $env:WINDOWS_CERTIFICATE,
    [string]$CertificatePassword = $env:WINDOWS_CERTIFICATE_PASSWORD,
    [string]$ExpectedPublisherSubject = $env:WINDOWS_EXPECTED_PUBLISHER_SUBJECT,
    [string]$TimestampUrl = $(if ($env:WINDOWS_TIMESTAMP_URL) { $env:WINDOWS_TIMESTAMP_URL } else { "https://timestamp.digicert.com" }),
    [string]$Stage = "sign-prepare"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Fail-Stage([string]$Message) {
    Write-Host "::error::[$Stage] $Message"
    throw "[$Stage] $Message"
}

if ([string]::IsNullOrWhiteSpace($CertificateBase64)) {
    Fail-Stage "WINDOWS_CERTIFICATE is required for a production V4 build"
}
if ([string]::IsNullOrWhiteSpace($ExpectedPublisherSubject)) {
    Fail-Stage "WINDOWS_EXPECTED_PUBLISHER_SUBJECT is required for a production V4 build"
}
$timestamp = $null
if (-not [Uri]::TryCreate($TimestampUrl, [UriKind]::Absolute, [ref]$timestamp)) {
    Fail-Stage "timestamp URL is invalid"
}
if ($timestamp.Scheme -ne "https" -or -not $timestamp.Host) {
    Fail-Stage "timestamp URL must be HTTPS"
}

$tempRoot = Join-Path $env:RUNNER_TEMP ("codex-v4-signing-" + [guid]::NewGuid().ToString("n"))
New-Item -ItemType Directory -Path $tempRoot | Out-Null
$pfxPath = Join-Path $tempRoot "identity.pfx"
$configPath = Join-Path $tempRoot "tauri.windows.signing.json"

try {
    [IO.File]::WriteAllBytes($pfxPath, [Convert]::FromBase64String($CertificateBase64.Trim()))
    $securePassword = if ([string]::IsNullOrEmpty($CertificatePassword)) {
        New-Object System.Security.SecureString
    }
    else {
        ConvertTo-SecureString -String $CertificatePassword -AsPlainText -Force
    }
    $imported = @(Import-PfxCertificate `
        -FilePath $pfxPath `
        -CertStoreLocation Cert:\CurrentUser\My `
        -Password $securePassword)
    $now = Get-Date
    $cert = $imported | Where-Object {
        $_.HasPrivateKey -and
        $_.NotBefore -le $now -and
        $_.NotAfter -gt $now -and
        ($_.EnhancedKeyUsageList.ObjectId.Value -contains "1.3.6.1.5.5.7.3.3")
    } | Sort-Object NotAfter -Descending | Select-Object -First 1
    if (-not $cert) {
        Fail-Stage "PFX contains no current private-key certificate with Code Signing EKU"
    }
    if ($cert.Subject -ne $ExpectedPublisherSubject) {
        Fail-Stage "certificate subject does not equal the approved Windows publisher subject"
    }

    $thumbprint = $cert.Thumbprint.Replace(" ", "").ToUpperInvariant()
    if ($thumbprint -notmatch "^[0-9A-F]{40,64}$") {
        Fail-Stage "certificate thumbprint is invalid"
    }
    $config = @{
        bundle = @{
            windows = @{
                certificateThumbprint = $thumbprint
                digestAlgorithm = "sha256"
                timestampUrl = $TimestampUrl
            }
        }
    } | ConvertTo-Json -Depth 6
    [IO.File]::WriteAllText($configPath, $config + "`n", [Text.UTF8Encoding]::new($false))

    $envLines = @(
        "TAURI_WINDOWS_SIGNING_CONFIG=$configPath",
        "WINDOWS_SIGNING_THUMBPRINT=$thumbprint",
        "WINDOWS_SIGNING_SUBJECT=$($cert.Subject)",
        "WINDOWS_SIGNING_TEMP_ROOT=$tempRoot"
    )
    if ($env:GITHUB_ENV) {
        $envLines | Add-Content -LiteralPath $env:GITHUB_ENV -Encoding UTF8
    }
    if ($env:GITHUB_OUTPUT) {
        @(
            "thumbprint=$thumbprint",
            "subject=$($cert.Subject)",
            "config_path=$configPath"
        ) | Add-Content -LiteralPath $env:GITHUB_OUTPUT -Encoding UTF8
    }
    Write-Host "[$Stage] production code-signing identity imported"
    Write-Host "[$Stage] subject=$($cert.Subject)"
    Write-Host "[$Stage] expires=$($cert.NotAfter.ToUniversalTime().ToString('O'))"
}
catch {
    if (Test-Path -LiteralPath $tempRoot) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
    throw
}
finally {
    if (Test-Path -LiteralPath $pfxPath) {
        [IO.File]::WriteAllBytes($pfxPath, [byte[]]::new(0))
        Remove-Item -LiteralPath $pfxPath -Force -ErrorAction SilentlyContinue
    }
}
