#!/usr/bin/env bash
set -euo pipefail

binary_path="${1:-target/release/bip39}"
app_dir="${2:-target/release/BIP39 Tool.AppDir}"
app_name="${BIP39_APP_NAME:-BIP39 Tool}"
desktop_id="${BIP39_DESKTOP_ID:-dev.local.bip39-tool}"
executable_name="${BIP39_EXECUTABLE_NAME:-bip39}"
age_bundle_dir="${3:-}"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"
icon_svg="$repo_root/assets/bip39-tool-icon.svg"
icon_png="$repo_root/assets/bip39-tool-icon-256.png"

if [[ ! -f "$binary_path" ]]; then
  echo "Binary not found: $binary_path" >&2
  exit 1
fi
if [[ ! -f "$icon_svg" || ! -f "$icon_png" ]]; then
  echo "Linux application icons are missing from assets/." >&2
  exit 1
fi

if [[ -z "$age_bundle_dir" ]]; then
  binary_description="$(file -b "$binary_path")"
  case "$binary_description" in
    *aarch64* | *ARM\ aarch64*) age_arch="aarch64" ;;
    *x86-64* | *x86_64*) age_arch="x86_64" ;;
    *)
      echo "Cannot determine Linux binary architecture: $binary_description" >&2
      exit 1
      ;;
  esac
  age_bundle_dir="$("$script_dir/fetch-age.sh" linux "$age_arch")"
fi

if [[ ! -x "$age_bundle_dir/age" || ! -x "$age_bundle_dir/age-keygen" || ! -f "$age_bundle_dir/LICENSE" ]]; then
  echo "Complete bundled age files not found: $age_bundle_dir" >&2
  exit 1
fi

if [[ -z "$app_dir" || "$app_dir" == "/" || "$app_dir" == "." || "$app_dir" == ".." ]]; then
  echo "Refusing unsafe AppDir path: $app_dir" >&2
  exit 1
fi

rm -rf "$app_dir"
mkdir -p \
  "$app_dir/usr/bin" \
  "$app_dir/usr/share/applications" \
  "$app_dir/usr/share/icons/hicolor/scalable/apps" \
  "$app_dir/usr/share/icons/hicolor/256x256/apps" \
  "$app_dir/usr/share/licenses/bip39-tool"

cp "$binary_path" "$app_dir/usr/bin/$executable_name"
chmod 755 "$app_dir/usr/bin/$executable_name"
cp "$age_bundle_dir/age" "$app_dir/usr/bin/age"
chmod 755 "$app_dir/usr/bin/age"
cp "$age_bundle_dir/age-keygen" "$app_dir/usr/bin/age-keygen"
chmod 755 "$app_dir/usr/bin/age-keygen"
cp "$age_bundle_dir/LICENSE" "$app_dir/usr/share/licenses/bip39-tool/age-LICENSE.txt"
cp "$repo_root/assets/Noto-CJK-LICENSE.txt" "$app_dir/usr/share/licenses/bip39-tool/Noto-CJK-LICENSE.txt"
cp "$icon_svg" "$app_dir/usr/share/icons/hicolor/scalable/apps/$desktop_id.svg"
cp "$icon_png" "$app_dir/usr/share/icons/hicolor/256x256/apps/$desktop_id.png"
cp "$icon_png" "$app_dir/.DirIcon"

cat > "$app_dir/AppRun" <<APPRUN
#!/usr/bin/env bash
set -euo pipefail

APPDIR="\$(cd "\$(dirname "\${BASH_SOURCE[0]}")" && pwd)"
exec "\$APPDIR/usr/bin/$executable_name" "\$@"
APPRUN
chmod 755 "$app_dir/AppRun"

cat > "$app_dir/$desktop_id.desktop" <<DESKTOP
[Desktop Entry]
Type=Application
Name=$app_name
Comment=Generate and recover BIP-39 backups
Exec=AppRun
Terminal=false
Categories=Utility;Finance;
StartupNotify=true
Icon=$desktop_id
DESKTOP

cp "$app_dir/$desktop_id.desktop" "$app_dir/usr/share/applications/$desktop_id.desktop"

cat > "$app_dir/install-desktop-entry.sh" <<INSTALLER
#!/usr/bin/env bash
set -euo pipefail

APPDIR="\$(cd "\$(dirname "\${BASH_SOURCE[0]}")" && pwd)"
desktop_dir="\${XDG_DATA_HOME:-\$HOME/.local/share}/applications"
desktop_file="\$desktop_dir/$desktop_id.desktop"

mkdir -p "\$desktop_dir"
cat > "\$desktop_file" <<DESKTOP
[Desktop Entry]
Type=Application
Name=$app_name
Comment=Generate and recover BIP-39 backups
Exec="\$APPDIR/AppRun"
Terminal=false
Categories=Utility;Finance;
StartupNotify=true
Icon=\$APPDIR/usr/share/icons/hicolor/256x256/apps/$desktop_id.png
DESKTOP

chmod 644 "\$desktop_file"

if command -v update-desktop-database >/dev/null 2>&1; then
  update-desktop-database "\$desktop_dir" >/dev/null 2>&1 || true
fi

echo "Installed desktop launcher: \$desktop_file"
INSTALLER
chmod 755 "$app_dir/install-desktop-entry.sh"

echo "Created Linux AppDir: $app_dir"
