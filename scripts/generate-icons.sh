#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"
asset_dir="$repo_root/assets"
source_svg="$asset_dir/bip39-tool-icon.svg"
source_png="$asset_dir/bip39-tool-icon-1024.png"
iconset_dir="$asset_dir/BIP39Tool.iconset"

if [[ ! -f "$source_svg" ]]; then
  echo "Icon source not found: $source_svg" >&2
  exit 1
fi
if ! command -v qlmanage >/dev/null 2>&1 \
  || ! command -v sips >/dev/null 2>&1 \
  || ! command -v iconutil >/dev/null 2>&1 \
  || ! command -v ffmpeg >/dev/null 2>&1; then
  echo "Generating release icons requires macOS qlmanage, sips, iconutil, and ffmpeg." >&2
  exit 1
fi

render_dir="$(mktemp -d)"
trap 'rm -rf "$render_dir"' EXIT
qlmanage -t -s 1024 -o "$render_dir" "$source_svg" >/dev/null
flat_png="$render_dir/$(basename "$source_svg").png"
transparent_png="$render_dir/bip39-tool-transparent.png"
# Quick Look flattens SVG transparency onto opaque white. Restore the exact
# rounded-square alpha mask before this PNG is embedded into eframe or ICNS;
# otherwise macOS shows a white Dock halo around the icon.
ffmpeg -v error -y -i "$flat_png" \
  -vf "format=rgba,geq=r='r(X,Y)':g='g(X,Y)':b='b(X,Y)':a='if(gt(between(X,264,760)*between(Y,46,978)+between(Y,264,760)*between(X,46,978)+lte((X-264)*(X-264)+(Y-264)*(Y-264),218*218)+lte((X-760)*(X-760)+(Y-264)*(Y-264),218*218)+lte((X-264)*(X-264)+(Y-760)*(Y-760),218*218)+lte((X-760)*(X-760)+(Y-760)*(Y-760),218*218),0),255,0)'" \
  -frames:v 1 "$transparent_png"
cp "$transparent_png" "$source_png"
rm -rf "$render_dir"
trap - EXIT
rm -rf "$iconset_dir"
mkdir -p "$iconset_dir"

resize_icon() {
  local pixels="$1"
  local output="$2"
  sips -z "$pixels" "$pixels" "$source_png" --out "$output" >/dev/null
}

resize_icon 16 "$iconset_dir/icon_16x16.png"
resize_icon 32 "$iconset_dir/icon_16x16@2x.png"
resize_icon 32 "$iconset_dir/icon_32x32.png"
resize_icon 64 "$iconset_dir/icon_32x32@2x.png"
resize_icon 128 "$iconset_dir/icon_128x128.png"
resize_icon 256 "$iconset_dir/icon_128x128@2x.png"
resize_icon 256 "$iconset_dir/icon_256x256.png"
resize_icon 512 "$iconset_dir/icon_256x256@2x.png"
resize_icon 512 "$iconset_dir/icon_512x512.png"
cp "$source_png" "$iconset_dir/icon_512x512@2x.png"

iconutil -c icns "$iconset_dir" -o "$asset_dir/BIP39Tool.icns"
resize_icon 256 "$asset_dir/bip39-tool-icon-256.png"
sips -s format ico "$asset_dir/bip39-tool-icon-256.png" \
  --out "$asset_dir/BIP39Tool.ico" >/dev/null
rm -rf "$iconset_dir"

echo "Generated app icons in $asset_dir"
