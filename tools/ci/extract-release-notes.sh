#!/usr/bin/env bash
# PROD-49: print one release's notes, the "### <tag>" section of docs/UPGRADE.md, for the GitHub release body. The app's
# update check shows that body to administrators, so the in-app notes are the upgrade notes. Fails when the section is
# missing or empty: a release is only tagged once its notes are written.
#
# Usage: tools/ci/extract-release-notes.sh v1.6.0 [docs/UPGRADE.md]
set -euo pipefail

tag="${1:?usage: extract-release-notes.sh <tag> [UPGRADE.md]}"
file="${2:-docs/UPGRADE.md}"

notes="$(awk -v head="### ${tag}" '
  $0 == head { on = 1; next }
  on && (/^### / || /^## / || /^---[[:space:]]*$/) { exit }
  on { print }
' "$file" | sed -e '/./,$!d' | sed -e ':a' -e '/^\n*$/{$d;N;ba' -e '}')"

if [[ -z "${notes//[[:space:]]/}" ]]; then
  echo "No '### ${tag}' section (or an empty one) in ${file}. Write the release's notes before tagging." >&2
  exit 1
fi
printf '%s\n' "$notes"
