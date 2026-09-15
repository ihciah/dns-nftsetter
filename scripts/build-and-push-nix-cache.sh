#!/usr/bin/env bash

set -euo pipefail

# Build dns-nftsetter and publish its closure to the Nix HTTP binary cache.
# Cache credentials are read from the environment and are never written to
# the repository or printed by this script.

cache_url="${NIX_CACHE_URL:-https://nix-cache.ihc.im}"
flake_ref="${NIX_FLAKE_REF:-.#default}"
cache_host="${cache_url#https://}"
cache_host="${cache_host#http://}"
cache_host="${cache_host%%/*}"
cache_user="${NIX_CACHE_USER:-nix}"
cache_password="${NIX_CACHE_PASSWORD:-}"
secret_key_file="${NIX_CACHE_SECRET_KEY_FILE:-$HOME/.config/nix/cache-signing-key.sec}"
package_name="${NIX_CACHE_PACKAGE_NAME:-dns-nftsetter}"
version_name="${NIX_CACHE_VERSION:-}"
registration_tags_json="${NIX_CACHE_TAGS_JSON:-}"
if ! command -v nix >/dev/null 2>&1; then
  echo "nix is required" >&2
  exit 1
fi

if ! command -v curl >/dev/null 2>&1; then
  echo "curl is required" >&2
  exit 1
fi

if [[ -z "$cache_password" && -z "${NIX_NETRC_FILE:-}" ]]; then
  echo "set NIX_CACHE_PASSWORD or NIX_NETRC_FILE" >&2
  exit 1
fi

netrc_file="${NIX_NETRC_FILE:-}"
temporary_netrc=0
registration_file=""
if [[ -z "$netrc_file" ]]; then
  netrc_file="$(mktemp)"
  temporary_netrc=1
  chmod 600 "$netrc_file"
  printf 'machine %s login %s password %s\n' \
    "$cache_host" "$cache_user" "$cache_password" >"$netrc_file"
fi

cleanup() {
  if [[ "$temporary_netrc" == 1 ]]; then
    rm -f "$netrc_file"
  fi
  if [[ -n "$registration_file" ]]; then
    rm -f "$registration_file"
  fi
}
trap cleanup EXIT

echo "Building $flake_ref"
out_path="$(nix build --no-link --print-out-paths "$flake_ref")"
echo "Built $out_path"

if [[ -z "$registration_tags_json" ]]; then
  nix_system="$(nix eval --raw --impure --expr 'builtins.currentSystem')"
  registration_tags_json="$(printf '{"channel":"dev","system":"%s"}' "$nix_system")"
fi

mapfile -t closure_paths < <(nix-store --query --requisites "$out_path")
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
nix copy --to "$cache_url" --option netrc-file "$netrc_file" \
  "${closure_paths[@]}"
echo "Uploaded $out_path"

registration_file="$(mktemp)"
chmod 600 "$registration_file"
{
  printf '{"tags":%s,"narinfoKeys":[' "$registration_tags_json"
  first=1
  for closure_path in "${closure_paths[@]}"; do
    narinfo_key="$(basename "$closure_path" | sed -E 's/^([^-]+)-.*/\1.narinfo/')"
    if [[ "$first" == 0 ]]; then
      printf ','
    fi
    printf '%s' "\"$narinfo_key\""
    first=0
  done
  printf '],"retentionDays":null}'
} >"$registration_file"

registration_url="$cache_url/api/packages/$package_name/versions/$version_name"
echo "Registering $package_name/$version_name"
curl --fail-with-body --silent --show-error \
  --request PUT \
  --header "Authorization: Bearer $cache_password" \
  --header 'Content-Type: application/json' \
  --data-binary "@$registration_file" \
  "$registration_url" \
  >/dev/null

echo "Published and registered $package_name/$version_name"
