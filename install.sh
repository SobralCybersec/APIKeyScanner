#!/bin/bash
set -e

echo "API Key Scanner - Installation"
echo "=================================="

# Check for Rust
if ! command -v cargo &> /dev/null; then
    echo "Rust not found. Install from https://rustup.rs"
    exit 1
fi

echo "✓ Rust found"

# Build release binary
echo "Building release binary..."
cargo build --release

echo "✓ Build complete"

# Install Git hook
if [ -d .git ]; then
    echo "Installing Git hook..."
    mkdir -p .git/hooks
    cat > .git/hooks/pre-push << 'EOF'
#!/bin/sh
# Auto-installed by api-key-scanner
echo "Running API key scanner..."
cargo run --release -- --max-requests 5 --no-tui || exit 1
EOF
    chmod +x .git/hooks/pre-push
    echo "✓ Git hook installed"
else
    echo "Not a Git repo, skipping hook installation"
fi

# Create data directory
mkdir -p data
echo "✓ Data directory created"

echo ""
echo "Installation complete!"
echo ""
echo "Usage:"
echo "  export GITHUB_TOKEN='your_token'"
echo "  ./target/release/api-key-scanner"
echo ""
echo "Or run via cargo:"
echo "  cargo run --release -- --token YOUR_TOKEN --no-tui"
