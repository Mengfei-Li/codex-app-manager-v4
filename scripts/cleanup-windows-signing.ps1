[CmdletBinding()]
param(
    [string]$Thumbprint = $env:WINDOWS_SIGNING_THUMBPRINT,
    [string]$TempRoot = $env:WINDOWS_SIGNING_TEMP_ROOT
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ($Thumbprint -match "^[0-9A-Fa-f]{40,64}$") {
    $certificatePath = "Cert:\CurrentUser\My\$($Thumbprint.ToUpperInvariant())"
    if (Test-Path -LiteralPath $certificatePath) {
        Remove-Item -LiteralPath $certificatePath -Force
    }
}
if ($TempRoot) {
    $resolvedRunnerTemp = [IO.Path]::GetFullPath($env:RUNNER_TEMP).TrimEnd('\')
    $resolvedTempRoot = [IO.Path]::GetFullPath($TempRoot).TrimEnd('\')
    if (-not $resolvedTempRoot.StartsWith($resolvedRunnerTemp + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw "refusing to remove signing temp root outside RUNNER_TEMP"
    }
    if (Test-Path -LiteralPath $resolvedTempRoot) {
        Remove-Item -LiteralPath $resolvedTempRoot -Recurse -Force
    }
}

