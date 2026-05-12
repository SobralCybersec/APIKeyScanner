param(
    [string]$Version = "1.0.0"
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$distDir = Join-Path $repoRoot "dist"
$stageDir = Join-Path $distDir "api-key-scanner-v$Version-windows-x64"
$zipPath = Join-Path $distDir "api-key-scanner-v$Version-windows-x64.zip"
$exePath = Join-Path $repoRoot "target\release\api-key-scanner.exe"
$isccPath = "C:\Program Files (x86)\Inno Setup 6\ISCC.exe"

New-Item -ItemType Directory -Force -Path $distDir | Out-Null

Write-Host "Building release binary..."
cargo build --release

if (-not (Test-Path $exePath)) {
    throw "Release binary not found at $exePath"
}

Write-Host "Preparing portable ZIP contents..."
if (Test-Path $stageDir) {
    Remove-Item -LiteralPath $stageDir -Recurse -Force
}

New-Item -ItemType Directory -Force -Path $stageDir | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $stageDir "data") | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $stageDir "private_keys") | Out-Null

Copy-Item -LiteralPath $exePath -Destination (Join-Path $stageDir "api-key-scanner.exe")
Copy-Item -LiteralPath (Join-Path $repoRoot "README.md") -Destination $stageDir
Copy-Item -LiteralPath (Join-Path $repoRoot "RELEASE_NOTES.md") -Destination $stageDir
Copy-Item -LiteralPath (Join-Path $repoRoot "install.bat") -Destination $stageDir
Copy-Item -LiteralPath (Join-Path $repoRoot "install.sh") -Destination $stageDir

if (Test-Path $zipPath) {
    Remove-Item -LiteralPath $zipPath -Force
}

Compress-Archive -Path (Join-Path $stageDir "*") -DestinationPath $zipPath -CompressionLevel Optimal

if (Test-Path $isccPath) {
    Write-Host "Compiling Inno Setup installer..."
    & $isccPath (Join-Path $repoRoot "installer.iss")
} else {
    Write-Warning "Inno Setup compiler not found. ZIP artifact was created, but the installer was not built."
}

Write-Host ""
Write-Host "Artifacts ready:"
Write-Host "  ZIP:      $zipPath"
Write-Host "  Stage:    $stageDir"
Write-Host "  Installer:$distDir\api-key-scanner-setup-v$Version.exe"
