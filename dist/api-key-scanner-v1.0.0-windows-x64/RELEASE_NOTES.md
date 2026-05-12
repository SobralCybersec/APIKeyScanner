# API Key Scanner Release Notes

## 1.0.0

- Added a polished Windows installer and a portable ZIP packaging flow for `api-key-scanner.exe`.
- Fixed the Git `pre-push` hook so pushes run the scanner in non-interactive mode instead of opening the canceled quick-start menu.
- Updated CLI argument detection so scripted runs with flags like `--max-requests 5` stay in CLI mode and never fall back to the launcher.
- Packaged the Windows app for per-user installation under Local AppData to avoid permission issues when the scanner writes `data/` and `private_keys/`.
- Included `README.md`, release notes, and install helper scripts in release artifacts for easier first-run setup.
