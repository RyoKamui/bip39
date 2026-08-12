#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"
age_version="1.3.1"
requested_arch="${1:-$(uname -m)}"

case "$requested_arch" in
  arm64 | aarch64)
    archive_arch="arm64"
    expected_sha256="01120ea2cbf0463d4c6bd767f99f3271bbed1cdc8a9aa718a76ba1fe4f01998b"
    ;;
  x86_64 | amd64)
    archive_arch="amd64"
    expected_sha256="2b233301ad21ab7b1eabd9ae1198a164005fa4928fcdd745d47c39f8593209d7"
    ;;
  *)
    echo "Unsupported macOS age architecture: $requested_arch" >&2
    exit 1
    ;;
esac

cache_dir="$repo_root/target/vendor/age/v$age_version/darwin-$archive_arch"
archive_name="age-v$age_version-darwin-$archive_arch.tar.gz"
archive_path="$cache_dir/$archive_name"
bundle_dir="$cache_dir/age"
download_url="https://github.com/FiloSottile/age/releases/download/v$age_version/$archive_name"

sha256_file() {
  shasum -a 256 "$1" | awk '{print $1}'
}

mkdir -p "$cache_dir"

if [[ ! -f "$archive_path" ]] || [[ "$(sha256_file "$archive_path")" != "$expected_sha256" ]]; then
  temp_archive="$(mktemp "$cache_dir/$archive_name.download.XXXXXX")"
  trap 'rm -f "$temp_archive"' EXIT
  curl --fail --location --retry 3 --output "$temp_archive" "$download_url"
  actual_sha256="$(sha256_file "$temp_archive")"
  if [[ "$actual_sha256" != "$expected_sha256" ]]; then
    echo "age archive checksum mismatch: expected $expected_sha256, got $actual_sha256" >&2
    exit 1
  fi
  mv "$temp_archive" "$archive_path"
  trap - EXIT
fi

if [[ ! -x "$bundle_dir/age" ]] || [[ ! -f "$bundle_dir/LICENSE" ]]; then
  temp_extract="$(mktemp -d "$cache_dir/extract.XXXXXX")"
  trap 'rm -rf "$temp_extract"' EXIT
  tar -xzf "$archive_path" -C "$temp_extract" age/age age/LICENSE
  rm -rf "$bundle_dir"
  mv "$temp_extract/age" "$bundle_dir"
  trap - EXIT
  rmdir "$temp_extract"
fi

"$bundle_dir/age" --version >&2
printf '%s\n' "$bundle_dir"
