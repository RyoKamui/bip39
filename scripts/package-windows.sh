#!/usr/bin/env bash
set -euo pipefail

binary_path="${1:-target/release/bip39.exe}"
package_dir="${2:-target/release/BIP39 Tool Windows}"
age_bundle_dir="${3:-}"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"
icon_path="$repo_root/assets/BIP39Tool.ico"

if [[ ! -f "$binary_path" ]]; then
  echo "Binary not found: $binary_path" >&2
  exit 1
fi
if [[ ! -f "$icon_path" ]]; then
  echo "Windows application icon not found: $icon_path" >&2
  exit 1
fi
if [[ -z "$package_dir" || "$package_dir" == "/" || "$package_dir" == "." || "$package_dir" == ".." ]]; then
  echo "Refusing unsafe Windows package path: $package_dir" >&2
  exit 1
fi

if [[ -z "$age_bundle_dir" ]]; then
  age_bundle_dir="$("$script_dir/fetch-age.sh" windows x86_64)"
fi
if [[ ! -x "$age_bundle_dir/age.exe" || ! -x "$age_bundle_dir/age-keygen.exe" || ! -f "$age_bundle_dir/LICENSE" ]]; then
  echo "Complete bundled age files not found: $age_bundle_dir" >&2
  exit 1
fi

rm -rf "$package_dir"
mkdir -p "$package_dir"
cp "$binary_path" "$package_dir/BIP39 Tool.exe"
cp "$age_bundle_dir/age.exe" "$package_dir/age.exe"
cp "$age_bundle_dir/age-keygen.exe" "$package_dir/age-keygen.exe"
cp "$age_bundle_dir/LICENSE" "$package_dir/age-LICENSE.txt"
cp "$icon_path" "$package_dir/BIP39Tool.ico"
cp "$repo_root/assets/Noto-CJK-LICENSE.txt" "$package_dir/Noto-CJK-LICENSE.txt"

"$package_dir/age.exe" --version >/dev/null
"$package_dir/age-keygen.exe" --version >/dev/null
echo "Created Windows package: $package_dir"
