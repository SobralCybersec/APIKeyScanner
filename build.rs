use std::env;
use std::fs;
use std::path::Path;

fn main() {
    // Skip in CI
    if env::var("CI").is_ok() || env::var("NO_HOOKS").is_ok() {
        return;
    }

    let git_dir = Path::new(".git");
    if !git_dir.exists() {
        return;
    }

    let hooks_dir = git_dir.join("hooks");
    fs::create_dir_all(&hooks_dir).ok();

    // Install pre-push hook
    let hook_path = hooks_dir.join("pre-push");
    let hook_content = r#"#!/bin/sh
# Auto-installed by api-key-scanner
echo "🔍 Running API key scanner..."
cargo run --release -- --max-requests 5 || exit 1
"#;

    fs::write(&hook_path, hook_content).ok();
    
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&hook_path).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&hook_path, perms).ok();
    }

    println!("cargo:rerun-if-changed=build.rs");
}
