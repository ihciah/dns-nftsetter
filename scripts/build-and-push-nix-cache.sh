#!/usr/bin/env bash

set -euo pipefail

# Build dns-nftsetter and publish its closure to the Nix HTTP binary cache.
# Cache credentials are read from the environment and are never written to
# the repository or printed by this script.

cache_url="${NIX_CACHE_URL:-https://nix-cache.ihc.im}"
flake_ref="${NIX_FLAKE_REF:-.#default}"
cache_password="${NIX_CACHE_PASSWORD:-}"
secret_key_file="${NIX_CACHE_SECRET_KEY_FILE:-$HOME/.config/nix/cache-signing-key.sec}"
package_name="${NIX_CACHE_PACKAGE_NAME:-dns-nftsetter}"
version_name="${NIX_CACHE_VERSION:-}"
registration_tags_json="${NIX_CACHE_TAGS_JSON:-}"
upload_command="${NIX_CACHE_UPLOAD_COMMAND:-nix-cache-upload}"
if ! command -v nix >/dev/null 2>&1; then
  echo "nix is required" >&2
  exit 1
fi

if ! command -v "$upload_command" >/dev/null 2>&1; then
  echo "Nix cache upload client not found: $upload_command" >&2
  exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required" >&2
  exit 1
fi

if [[ -z "$cache_password" ]]; then
  echo "set NIX_CACHE_PASSWORD" >&2
  exit 1
fi

echo "Building $flake_ref"
out_path="$(nix build --no-link --print-out-paths "$flake_ref")"
echo "Built $out_path"

if [[ -z "$registration_tags_json" ]]; then
  nix_system="$(nix eval --raw --impure --expr 'builtins.currentSystem')"
  registration_tags_json="$(printf '{"channel":"dev","system":"%s"}' "$nix_system")"
fi

if [[ -z "$version_name" ]]; then
  output_name="$(basename "$out_path")"
  output_hash="${output_name%%-*}"
  version_name="${output_hash:0:12}"
fi

if [[ -s "$secret_key_file" ]]; then
  # Dependencies substituted from cache.nixos.org already carry a valid public
  # cache signature. Sign only this package output so the cache receives one
  # signature for the newly built artifact instead of rewriting every shared
  # dependency's narinfo.
  nix store sign --key-file "$secret_key_file" "$out_path"
else
  echo "warning: signing key not found at $secret_key_file; published narinfo files will be unsigned" >&2
fi

echo "Publishing the closure to $cache_url"
cache_tag_args=()
while IFS= read -r tag; do
  [[ -n "$tag" ]] && cache_tag_args+=(--tag "$tag")
done < <(jq --raw-output 'to_entries[] | "\(.key)=\(.value)"' <<<"$registration_tags_json")

echo "Publishing and registering $package_name/$version_name"
NIX_CACHE_WRITE_TOKEN="$cache_password" \
  "$upload_command" \
    --to "$cache_url" \
    --package "$package_name" \
    --version "$version_name" \
    "${cache_tag_args[@]}" \
    "$out_path"
