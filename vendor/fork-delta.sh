#!/usr/bin/env bash
# Regenerate the delta between a vendored fork and its pristine crates.io source.
#
# A hand-maintained fork-delta list has been wrong twice (dig_ecosystem#2228): both vendor READMEs
# understated their fork. Derive it instead. Requires the upstream crate to be present in the local
# cargo registry, which it is after any `cargo build` of this workspace.
#
# Usage:  vendor/fork-delta.sh <crate-name> [--summary]
#   vendor/fork-delta.sh chia-sdk-client            # full unified diff
#   vendor/fork-delta.sh chia-sdk-client --summary  # one line per changed file
set -euo pipefail

crate="${1:?usage: vendor/fork-delta.sh <crate-name> [--summary]}"
mode="${2:-}"

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fork="$here/$crate/src"
[[ -d "$fork" ]] || { echo "no vendored tree at $fork" >&2; exit 1; }

version="$(sed -n 's/^version = "\(.*\)"/\1/p' "$here/$crate/Cargo.toml" | head -1)"
[[ -n "$version" ]] || { echo "cannot read version from $here/$crate/Cargo.toml" >&2; exit 1; }

# The vendored trees are unpacked crates.io tarballs, so the pristine source of the SAME version is
# the correct baseline — anything the diff reports is DIG's, by construction.
upstream="$(find "${CARGO_HOME:-$HOME/.cargo}/registry/src" -maxdepth 2 -type d \
    -name "$crate-$version" -print -quit)"
[[ -n "$upstream" ]] || {
    echo "pristine $crate-$version not in the registry; run 'cargo fetch' first" >&2
    exit 1
}

echo "# $crate $version — vendored fork vs $upstream"
if [[ "$mode" == "--summary" ]]; then
    # `diff -q` per file: the file list IS the delta of record.
    diff -rq --strip-trailing-cr "$upstream/src" "$fork" || true
else
    diff -ru --strip-trailing-cr "$upstream/src" "$fork" || true
fi
