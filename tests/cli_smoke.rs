use std::process::Command;

fn scanner(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_api-key-scanner"))
        .args(args)
        .output()
        .expect("scanner binary should execute")
}

#[test]
fn help_command_is_local_and_successful() {
    let output = scanner(&["--help"]);
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("API key scanner"));
}

#[test]
fn show_dorks_command_is_local_and_successful() {
    let output = scanner(&["--show-dorks"]);
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Web-Search Dorks"));
}

#[test]
fn scan_without_token_fails_at_cli_boundary() {
    let output = scanner(&["--no-tui"]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("GitHub token required"));
}

#[test]
fn zero_concurrency_is_rejected_at_cli_boundary() {
    let output = scanner(&["--concurrency", "0", "--no-tui"]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("greater than zero"));
}
