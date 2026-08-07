#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
version=$(sed -n 's/^version = "\([^"]*\)"$/\1/p' "$root/Cargo.toml")

[ -n "$version" ]
grep -Fq "Version = \"$version\"" "$root/build-release.ps1"
grep -Fq "MyAppVersion \"$version\"" "$root/installer.iss"
grep -Fq "## $version" "$root/RELEASE_NOTES.md"

printf 'version=%s consistent\n' "$version"
