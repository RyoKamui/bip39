#!/usr/bin/env bash
set -euo pipefail

binary_path="${1:-target/release/bip39}"
app_path="${2:-target/release/BIP39 Tool.app}"
age_bundle_dir="${3:-}"
bundle_name="${BIP39_BUNDLE_NAME:-BIP39 Tool}"
bundle_id="${BIP39_BUNDLE_ID:-dev.local.bip39-tool}"
version="${BIP39_BUNDLE_VERSION:-0.1.0}"
executable_name="bip39"

if [[ ! -f "$binary_path" ]]; then
  echo "Binary not found: $binary_path" >&2
  exit 1
fi

if [[ -z "$age_bundle_dir" ]]; then
  binary_description="$(file -b "$binary_path")"
  case "$binary_description" in
    *arm64*) age_arch="arm64" ;;
    *x86_64*) age_arch="x86_64" ;;
    *)
      echo "Cannot determine macOS binary architecture: $binary_description" >&2
      exit 1
      ;;
  esac
  script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  age_bundle_dir="$("$script_dir/fetch-age-macos.sh" "$age_arch")"
fi

if [[ ! -x "$age_bundle_dir/age" ]]; then
  echo "Bundled age executable not found: $age_bundle_dir/age" >&2
  exit 1
fi
if [[ ! -f "$age_bundle_dir/LICENSE" ]]; then
  echo "Bundled age license not found: $age_bundle_dir/LICENSE" >&2
  exit 1
fi

rm -rf "$app_path"
mkdir -p "$app_path/Contents/MacOS" "$app_path/Contents/Resources"

cp "$binary_path" "$app_path/Contents/MacOS/$executable_name"
chmod 755 "$app_path/Contents/MacOS/$executable_name"
cp "$age_bundle_dir/age" "$app_path/Contents/MacOS/age"
chmod 755 "$app_path/Contents/MacOS/age"
cp "$age_bundle_dir/LICENSE" "$app_path/Contents/Resources/age-LICENSE.txt"

cat > "$app_path/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleDevelopmentRegion</key>
  <string>en</string>
  <key>CFBundleExecutable</key>
  <string>${executable_name}</string>
  <key>CFBundleIdentifier</key>
  <string>${bundle_id}</string>
  <key>CFBundleInfoDictionaryVersion</key>
  <string>6.0</string>
  <key>CFBundleName</key>
  <string>${bundle_name}</string>
  <key>CFBundleDisplayName</key>
  <string>${bundle_name}</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>CFBundleShortVersionString</key>
  <string>${version}</string>
  <key>CFBundleVersion</key>
  <string>${version}</string>
  <key>LSMinimumSystemVersion</key>
  <string>12.0</string>
  <key>NSHighResolutionCapable</key>
  <true/>
  <key>NSSupportsAutomaticGraphicsSwitching</key>
  <true/>
</dict>
</plist>
PLIST

if command -v plutil >/dev/null 2>&1; then
  plutil -lint "$app_path/Contents/Info.plist" >/dev/null
fi

if command -v codesign >/dev/null 2>&1; then
  codesign --force --sign - "$app_path/Contents/MacOS/age" >/dev/null
  codesign --force --deep --sign - "$app_path" >/dev/null
fi

"$app_path/Contents/MacOS/age" --version >/dev/null

echo "Created $app_path"
