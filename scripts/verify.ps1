$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Push-Location (Split-Path -Parent $PSScriptRoot)
try {
    cargo fmt --all -- --check
    if ($LASTEXITCODE -ne 0) { throw 'Formatting check failed' }
    cargo test --offline
    if ($LASTEXITCODE -ne 0) { throw 'Tests failed' }
    cargo clippy --offline --all-targets -- -D warnings
    if ($LASTEXITCODE -ne 0) { throw 'Clippy failed' }
    cargo build --offline --release
    if ($LASTEXITCODE -ne 0) { throw 'Build failed' }
    New-Item -ItemType Directory -Path logs -Force | Out-Null
    & .\target\release\nat4-demo.exe lab --case all --seed 7 2>&1 | Tee-Object -FilePath logs\lab-seed7.txt
    if ($LASTEXITCODE -ne 0) { throw 'Lab outcomes differed from the seeded expectations' }
    Write-Host 'Verification complete. Lab log: logs/lab-seed7.txt'
}
finally {
    Pop-Location
}
