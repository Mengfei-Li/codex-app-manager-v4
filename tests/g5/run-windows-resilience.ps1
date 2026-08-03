param(
    [Parameter(Mandatory = $true)]
    [string]$OutputPath
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 3.0

$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\.."))
$manifest = Join-Path $repo "src-tauri\Cargo.toml"
$deliveryManifest = Join-Path $repo "crates\codex-delivery-engine\Cargo.toml"
$cases = @(
    "app::install_tx::tests",
    "app::oplock::tests",
    "app::reboot_continuation::tests",
    "app::win_update::tests",
    "delivery::tests",
    "delivery_runtime::tests",
    "v4_diagnostics::tests"
)

foreach ($case in $cases) {
    & cargo test --manifest-path $manifest $case --lib -- --test-threads=1
    if ($LASTEXITCODE -ne 0) {
        throw "resilience case failed: $case"
    }
}
& cargo test --manifest-path $deliveryManifest --all-targets -- --test-threads=1
if ($LASTEXITCODE -ne 0) {
    throw "delivery transaction matrix failed"
}

$evidence = [ordered]@{
    schema_version = 1
    status = "passed"
    platform = "windows"
    architecture = $env:PROCESSOR_ARCHITECTURE
    loopback_only = $true
    production_side_effects = $false
    skipped_required_tests = 0
    cases = $cases
    delivery_transaction_matrix = $true
    tested_at_utc = [DateTime]::UtcNow.ToString("o")
}
$parent = Split-Path -Parent $OutputPath
[void](New-Item -ItemType Directory -Path $parent -Force)
[IO.File]::WriteAllText(
    $OutputPath,
    (($evidence | ConvertTo-Json -Depth 5) + "`n"),
    [Text.UTF8Encoding]::new($false)
)
