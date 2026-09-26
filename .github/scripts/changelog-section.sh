#!/usr/bin/env bash
# Prints the body of the "## [VERSION]" section of CHANGELOG.md (used as the
# GitHub Release notes). Fails if the section is missing or empty.
#
# Usage: .github/scripts/changelog-section.sh VERSION [CHANGELOG]
set -euo pipefail

version="${1:?usage: $0 VERSION [CHANGELOG]}"
changelog="${2:-CHANGELOG.md}"

notes="$(awk -v v="$version" '
  index($0, "## [" v "]") == 1 { found = 1; next }
  found && /^## \[/            { exit }
  found                        { print }
' "$changelog" | sed -e '/./,$!d')"

if [[ -z "${notes//[[:space:]]/}" ]]; then
  echo "No CHANGELOG section for version ${version} in ${changelog}" >&2
  exit 1
fi
printf '%s\n' "$notes"
