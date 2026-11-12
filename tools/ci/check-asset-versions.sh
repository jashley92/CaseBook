#!/usr/bin/env bash
# Every script and stylesheet that changed ships. App.razor loads each self-hosted file with ?v=, and browsers cache
# the file by that address, so a file changed without a new ?v= is served from the old copy. A page that then calls a
# function only the new copy has throws into its error boundary.
#
# This fails when:
#   - a file under wwwroot that App.razor loads with ?v= changed since the base, but its ?v= didn't;
#   - a component stylesheet (*.razor.css) changed, but the ?v= on the bundle they build into
#     (IncidentManager.Web.styles.css) didn't;
#   - App.razor loaded a file at the base, the file is still there, and App.razor no longer loads it (most likely a
#     line dropped by a merge).
# A file that's new since the base has no old copy to be served, so it needs nothing.
#
# Usage: tools/ci/check-asset-versions.sh [base]   base: the ref to compare with (default origin/main)
set -euo pipefail

base="${1:-origin/main}"
web=src/IncidentManager.Web
root=$web/wwwroot
app=$web/Components/App.razor
bundle=IncidentManager.Web.styles.css

# A push that starts a branch has no "before" (all zeros): nothing to compare with.
if ! git rev-parse --verify -q "$base^{commit}" >/dev/null; then echo "No base to compare the assets with ($base); skipped."; exit 0; fi

# The address App.razor loads a file with, ?v= and all, from its text on stdin ("" when it doesn't load it with ?v=).
loaded() { grep -oE "\"${1//./[.]}[?]v=[^\"]*\"" | head -1 || true; }

before_app="$(git show "$base:$app" 2>/dev/null || true)"
bad=0

# $1: the path App.razor loads; $2: what changed (for the message).
must_bump() {
  local now was
  now="$(loaded "$1" < "$app")"
  [[ -z "$now" ]] && return 0                      # not loaded with ?v= by App.razor (a page loads it, or nothing does)
  was="$(loaded "$1" <<<"$before_app")"
  if [[ -n "$was" && "$was" == "$now" ]]; then
    echo "::error file=$app::$2 changed since $base, but App.razor still loads it as ${now//\"/}: bump its ?v="
    bad=1
  fi
}

# Changed since the base, committed or not (a local run checks work in progress too).
while IFS= read -r file; do
  [[ -z "$file" ]] && continue
  must_bump "${file#"$root"/}" "${file#"$root"/}"
done < <(git diff --name-only "$base" -- "$root/*.js" "$root/*.css")

scoped="$(git diff --name-only "$base" -- "$web/*.razor.css" | head -1)"
if [[ -n "$scoped" ]]; then must_bump "$bundle" "$scoped (built into $bundle)"; fi

while IFS= read -r ref; do
  [[ -z "$ref" ]] && continue
  path="${ref%%\?*}"
  [[ -f "$root/$path" || ( "$path" == "$bundle" && -n "$(git ls-files "$web/*.razor.css")" ) ]] || continue
  if [[ -z "$(loaded "$path" < "$app")" ]]; then
    echo "::error file=$app::App.razor loaded $path at $base but no longer does: was its line dropped by a merge?"
    bad=1
  fi
done < <(grep -oE '(href|src)="[^"]+[?]v=[^"]*"' <<<"$before_app" | sed -E 's/^(href|src)="//; s/"$//')

if [[ $bad -eq 0 ]]; then echo "Every changed script and stylesheet has a new ?v= in App.razor."; fi
exit $bad
