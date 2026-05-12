@echo off
echo API Key Scanner - Installation
echo ==================================

where cargo >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo Rust not found. Install from https://rustup.rs
    exit /b 1
)

echo ✓ Rust found

echo Building release binary...
cargo build --release

if %ERRORLEVEL% NEQ 0 (
    echo Build failed
    exit /b 1
)

echo ✓ Build complete

if exist .git (
    echo Installing Git hook...
    if not exist .git\hooks mkdir .git\hooks
    (
        echo #!/bin/sh
        echo # Auto-installed by api-key-scanner
        echo echo "Running API key scanner..."
        echo cargo run --release -- --max-requests 5 --no-tui ^|^| exit 1
    ) > .git\hooks\pre-push
    echo ✓ Git hook installed
) else (
    echo Not a Git repo, skipping hook installation
)

if not exist data mkdir data
echo ✓ Data directory created

echo.
echo Installation complete!
echo.
echo Usage:
echo   set GITHUB_TOKEN=your_token
echo   .\target\release\api-key-scanner.exe
echo.
echo Or run via cargo:
echo   cargo run --release -- --token YOUR_TOKEN --no-tui
