#!/usr/bin/env bash
# Released migrations are immutable: a migration that has shipped in any release tag (v*) must still exist,
# byte-for-byte, under the same name. Deleting, renaming, regenerating, or squashing one changes the migration
# lineage, and every database created by that release then fails to upgrade — the new build no longer sees
# its baseline as applied, re-runs InitialCreate, and dies with "There is already an object named ...".
# (That is exactly what happened when the pre-public history was squashed in 2026-09.)
#
# Adding NEW migrations is always fine; so is changing AppDbContextModelSnapshot.cs.
#
# Usage: tools/ci/check-migrations-immutable.sh   (needs tags: actions/checkout with fetch-depth: 0)
set -euo pipefail

dirs=(
  src/IncidentManager.Migrations.SqlServer/Migrations   # production (SQL Server)
  src/IncidentManager.Infrastructure/Persistence/Migrations  # development (SQLite)
)

head="$(git rev-parse HEAD)"
tags="$(git tag --list 'v[0-9]*' --merged HEAD)"
if [ -z "$tags" ]; then echo "No release tags reachable from HEAD; nothing to check."; exit 0; fi

bad=0
for tag in $tags; do
  [ "$(git rev-parse "$tag^{commit}")" = "$head" ] && continue   # the release being built right now
  # D = deleted, M = modified, R = renamed. A = added is the normal, safe case.
  changes="$(git diff --name-status --no-renames --diff-filter=DM "$tag" HEAD -- "${dirs[@]}" \
             | grep -v 'ModelSnapshot\.cs$' || true)"
  if [ -n "$changes" ]; then
    bad=1
    echo "::error::Migrations shipped in $tag were changed or removed:"
    echo "$changes" | sed 's/^/    /'
  fi
done

if [ "$bad" -ne 0 ]; then
  cat <<'EOF'

A released migration must never be edited, deleted, renamed, regenerated, or squashed: databases
installed from that release would no longer upgrade (see docs/UPGRADE.md). To change the schema, ADD a new
migration (dotnet ef migrations add ...) that alters what the old one created.
EOF
  exit 1
fi
echo "OK: every migration from $(echo "$tags" | wc -l | tr -d ' ') release tag(s) is intact."
