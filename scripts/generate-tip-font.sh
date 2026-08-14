#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"
font_url="https://raw.githubusercontent.com/notofonts/noto-cjk/main/Sans/OTF/Japanese/NotoSansCJKjp-Regular.otf"
license_url="https://raw.githubusercontent.com/notofonts/noto-cjk/main/Sans/LICENSE"
bip39_wordlist_base="https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039"

if ! command -v hb-subset >/dev/null 2>&1; then
  echo "hb-subset is required to regenerate the embedded CJK font subset." >&2
  exit 1
fi

work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT
curl --fail --location --retry 3 --output "$work_dir/NotoSansCJK-Regular.otf" "$font_url"
curl --fail --location --retry 3 --output "$work_dir/LICENSE" "$license_url"
for wordlist in chinese_simplified chinese_traditional japanese korean; do
  curl --fail --location --retry 3 \
    --output "$work_dir/$wordlist.txt" \
    "$bip39_wordlist_base/$wordlist.txt"
done
perl -CSDA -ne 'while (/([^\x00-\x7F])/g) { print $1 }' \
  "$repo_root/src/main.rs" \
  "$work_dir/chinese_simplified.txt" \
  "$work_dir/chinese_traditional.txt" \
  "$work_dir/japanese.txt" \
  "$work_dir/korean.txt" > "$work_dir/glyphs.txt"
hb-subset "$work_dir/NotoSansCJK-Regular.otf" \
  --text-file="$work_dir/glyphs.txt" \
  --name-IDs='*' \
  --layout-features='*' \
  --output-file="$repo_root/assets/NotoSansCJK-Tips.otf"
cp "$work_dir/LICENSE" "$repo_root/assets/Noto-CJK-LICENSE.txt"

echo "Regenerated assets/NotoSansCJK-Tips.otf"
