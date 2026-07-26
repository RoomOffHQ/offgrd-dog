# verify.ps1 — runs every check across the whole project in one go,
# in the order most likely to surface problems fast: cheap/fast checks
# first (fmt, the OS-agnostic crates), expensive/risky ones last (the
# Windows-specific collectors, then the GUI, which has its own
# Cargo.toml/Cargo.lock).
#
# This exists specifically because a LOT of code has been written
# across many rounds without a single real compile pass yet (see
# WIP.md). Rather than you having to remember every command from the
# README, run this once and paste back whatever it prints — that's
# the single most useful thing you can hand back right now.
#
# Usage:
#   .\verify.ps1            # run everything
#   .\verify.ps1 -SkipGui    # skip the GUI (if Tauri CLI isn't installed yet)

param(
    [switch]$SkipGui
)

$ErrorActionPreference = "Continue"
$results = @()

function Run-Step {
    param(
        [string]$Name,
        [string]$WorkingDirectory,
        [scriptblock]$Command
    )

    Write-Host ""
    Write-Host "=== $Name ===" -ForegroundColor Cyan
    Push-Location $WorkingDirectory
    try {
        & $Command
        $exitCode = $LASTEXITCODE
    } finally {
        Pop-Location
    }

    $status = if ($exitCode -eq 0) { "PASS" } else { "FAIL (exit $exitCode)" }
    $color = if ($exitCode -eq 0) { "Green" } else { "Red" }
    Write-Host "--- $Name : $status ---" -ForegroundColor $color

    $script:results += [PSCustomObject]@{
        Step   = $Name
        Status = $status
    }
}

$root = $PSScriptRoot

Run-Step "cargo fmt --check (workspace)" $root {
    cargo fmt --all -- --check
}

Run-Step "cargo build --workspace" $root {
    cargo build --workspace
}

Run-Step "cargo test --workspace" $root {
    cargo test --workspace
}

Run-Step "cargo clippy --workspace" $root {
    cargo clippy --workspace --all-targets -- -D warnings
}

Run-Step "offgrd rules-check (lints bundled rules/)" $root {
    cargo run --quiet --bin offgrd -- rules-check
}

if (-not $SkipGui) {
    $guiDir = Join-Path $root "gui\offgrd-gui\src-tauri"
    if (Test-Path $guiDir) {
        Run-Step "cargo build (GUI backend only, not full Tauri bundle)" $guiDir {
            cargo build
        }
    } else {
        Write-Host "GUI directory not found at $guiDir, skipping." -ForegroundColor Yellow
    }
} else {
    Write-Host "Skipping GUI checks (-SkipGui)." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "==================== SUMMARY ====================" -ForegroundColor Cyan
$results | Format-Table -AutoSize

$failures = $results | Where-Object { $_.Status -like "FAIL*" }
if ($failures.Count -gt 0) {
    Write-Host ""
    Write-Host "$($failures.Count) step(s) failed. Paste the full console output above (not just this summary) back for fixes." -ForegroundColor Red
    exit 1
} else {
    Write-Host ""
    Write-Host "Everything passed." -ForegroundColor Green
    exit 0
}
