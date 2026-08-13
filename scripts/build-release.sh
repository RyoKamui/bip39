#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"
cd "$repo_root"

bin_name="bip39"
app_name="BIP39 Tool"
mac_app_path="target/release/$app_name.app"
mac_current_zip="target/release/bip39-tool-macos.zip"
linux_appdir_path="target/release/$app_name.AppDir"
linux_appdir_tarball="target/release/bip39-tool-linux.tar.gz"
windows_package_path="target/release/$app_name Windows"
windows_package_zip="target/release/bip39-tool-windows.zip"

host_os() {
  case "$(uname -s)" in
    Darwin) echo "macos" ;;
    Linux) echo "linux" ;;
    MINGW* | MSYS* | CYGWIN*) echo "windows" ;;
    *) echo "unknown" ;;
  esac
}

host_arch() {
  case "$(uname -m)" in
    arm64 | aarch64) echo "aarch64" ;;
    x86_64 | amd64) echo "x86_64" ;;
    *) uname -m ;;
  esac
}

run() {
  printf '+'
  printf ' %q' "$@"
  printf '\n'
  "$@"
}

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

cargo_sanitized() {
  run "$script_dir/cargo-sanitized.sh" "$@"
}

zip_macos_app() {
  local app_path="$1"
  local zip_path="$2"

  require_command ditto
  rm -f "$zip_path"
  run ditto -c -k --sequesterRsrc --keepParent "$app_path" "$zip_path"
}

build_macos_current() {
  if [[ "$(host_os)" != "macos" ]]; then
    echo "macOS app bundles must be built on macOS. Use GitHub Actions or run this on a Mac." >&2
    exit 1
  fi

  require_command cargo
  cargo_sanitized build --release --locked
  run "$script_dir/package-macos.sh" "target/release/$bin_name" "$mac_app_path"
  zip_macos_app "$mac_app_path" "$mac_current_zip"
  run "$script_dir/check-binary-paths.sh" \
    "target/release/$bin_name" \
    "$mac_app_path/Contents/MacOS/$bin_name" \
    "$mac_app_path/Contents/MacOS/age"

  echo
  echo "Built macOS app:"
  echo "  $mac_app_path"
  echo "  $mac_current_zip"
}

build_linux_appdir() {
  if [[ "$(host_os)" != "linux" ]]; then
    echo "Linux AppDir should be built on Linux. Use GitHub Actions, a Linux VM, or a Linux machine." >&2
    exit 1
  fi

  require_command cargo
  require_command tar

  cargo_sanitized build --release --locked
  run "$script_dir/package-linux.sh" "target/release/$bin_name" "$linux_appdir_path"
  rm -f "$linux_appdir_tarball"
  run tar -C target/release -czf "$linux_appdir_tarball" "$app_name.AppDir"
  run "$script_dir/check-binary-paths.sh" \
    "target/release/$bin_name" \
    "$linux_appdir_path/usr/bin/$bin_name" \
    "$linux_appdir_path/usr/bin/age"

  echo
  echo "Built Linux AppDir:"
  echo "  $linux_appdir_path"
  echo "  $linux_appdir_tarball"
}

build_windows_package() {
  if [[ "$(host_os)" != "windows" ]]; then
    echo "Windows GUI executables should be built on Windows. Use GitHub Actions or run this script from Git Bash/MSYS on Windows." >&2
    exit 1
  fi

  require_command cargo
  require_command powershell.exe
  cargo_sanitized build --release --locked
  run "$script_dir/package-windows.sh" "target/release/$bin_name.exe" "$windows_package_path"
  rm -f "$windows_package_zip"
  run powershell.exe -NoProfile -Command \
    "Compress-Archive -LiteralPath '$windows_package_path' -DestinationPath '$windows_package_zip' -Force"
  run "$script_dir/check-binary-paths.sh" \
    "target/release/$bin_name.exe" \
    "$windows_package_path/$app_name.exe" \
    "$windows_package_path/age.exe"

  echo
  echo "Built Windows package:"
  echo "  $windows_package_path"
  echo "  $windows_package_zip"
}

build_current_platform() {
  case "$(host_os)" in
    macos) build_macos_current ;;
    linux) build_linux_appdir ;;
    windows) build_windows_package ;;
    *)
      echo "Unsupported OS: $(uname -s)" >&2
      exit 1
      ;;
  esac
}

run_checks() {
  require_command cargo
  cargo_sanitized fmt --check
  cargo_sanitized clippy --locked --all-targets -- -D warnings
  cargo_sanitized test --locked
}

usage() {
  cat <<USAGE
Usage: scripts/build-release.sh [command]

Commands:
  current  Build and package for this machine's OS.
  macos    Build a macOS .app and zip. Must be run on macOS.
  linux    Build a Linux AppDir and tarball. Must be run on Linux.
  windows  Build a Windows GUI package and zip. Must be run on Windows.
  check    Run fmt, clippy, and tests.
  help     Show this help.

Without a command, this script asks what to build.

Host detected: $(host_os) $(host_arch)
USAGE
}

prompt_command() {
  echo "What do you want to build?" >&2
  case "$(host_os)" in
    macos) echo "  1) macOS app" >&2 ;;
    linux) echo "  1) Linux AppDir" >&2 ;;
    windows) echo "  1) Windows GUI package" >&2 ;;
    *) echo "  1) Current OS app/package" >&2 ;;
  esac
  echo "  2) Checks" >&2
  echo "  q) Quit" >&2
  printf "Select: " >&2

  local choice
  read -r choice

  case "$choice" in
    1) echo "current" ;;
    2) echo "check" ;;
    q | Q) echo "quit" ;;
    *)
      echo "Unknown selection: $choice" >&2
      exit 1
      ;;
  esac
}

command_name="${1:-}"
if [[ -z "$command_name" ]]; then
  usage
  echo
  command_name="$(prompt_command)"
fi

case "$command_name" in
  current) build_current_platform ;;
  macos) build_macos_current ;;
  linux) build_linux_appdir ;;
  windows) build_windows_package ;;
  check) run_checks ;;
  help | --help | -h) usage ;;
  quit) exit 0 ;;
  *)
    echo "Unknown command: $command_name" >&2
    echo >&2
    usage >&2
    exit 1
    ;;
esac
