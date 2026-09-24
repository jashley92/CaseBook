#!/usr/bin/env bash
# Upgrade-path test: prove a database created by an OLDER CaseBook release upgrades in place to a newer
# build on real SQL Server — no wipe. This is the test that would have caught the 2026-09 lineage break
# (migrations regenerated between versions -> "There is already an object named 'AdGroupRoleMappings'").
#
#   1. Check out <from-ref> into a temporary worktree, build it, and start it against a fresh SQL Server
#      database (Development mode, so it migrates AND seeds demo cases + a populated audit chain).
#   2. Stop it, then start the <to> build against the SAME database. Its startup applies the pending
#      migrations and runs every startup seeder against existing data — exactly what an IIS upgrade does.
#   3. Assert: the new build came up (live + ready), every one of its migrations is recorded, and the
#      case / audit rows written by the old release are still there.
#
# Usage:  tools/upgrade-test/upgrade-path.sh <from-ref> [<to-ref>]
#   <from-ref>  a release tag (e.g. v1.0.0) or any commit
#   <to-ref>    optional; defaults to the current working tree (including uncommitted changes)
#
# Environment:
#   CASEBOOK_TEST_SQL  ADO.NET connection string to the SQL Server, WITHOUT Database=, e.g.
#                      "Server=localhost,14333;User Id=sa;Password=...;TrustServerCertificate=True;Encrypt=False"
#   SQLCMD             command that runs sqlcmd against that server (default: "sqlcmd"), e.g.
#                      "docker exec casebook-sql /opt/mssql-tools18/bin/sqlcmd -C -S localhost -U sa -P ..."
#   UPGRADE_TEST_PORT  local port for the app under test (default 5199)
set -euo pipefail

from_ref="${1:?usage: upgrade-path.sh <from-ref> [<to-ref>]}"
to_ref="${2:-}"
: "${CASEBOOK_TEST_SQL:?set CASEBOOK_TEST_SQL (SQL Server connection string without Database=)}"
SQLCMD="${SQLCMD:-sqlcmd}"
port="${UPGRADE_TEST_PORT:-5199}"

repo="$(git rev-parse --show-toplevel)"
work="$(mktemp -d)"
db="CaseBookUpg_$(printf %s "$from_ref" | tr -c 'A-Za-z0-9' '_')_$$"
conn="${CASEBOOK_TEST_SQL%;};Database=$db"
# A data root shared by both builds, as the installer's DataRoot is in production (it persists across
# upgrades). Pre-created so the /health evidence-store check sees it, even on a fresh CI checkout.
evidence="$work/data/evidence-store"
mkdir -p "$evidence"
app_pid=""

log()  { printf '==> %s\n' "$*"; }
fail() { printf '::error::%s\n' "$*" >&2; exit 1; }

# MSYS_NO_PATHCONV stops Git Bash on Windows rewriting a "docker exec ... /opt/..." path; a no-op elsewhere.
sql() { MSYS_NO_PATHCONV=1 $SQLCMD -b -h -1 -W -Q "SET NOCOUNT ON; $1" | tr -d '\r' | sed '/^$/d'; }

cleanup() {
  [ -n "$app_pid" ] && kill "$app_pid" 2>/dev/null || true
  sql "IF DB_ID('$db') IS NOT NULL BEGIN ALTER DATABASE [$db] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [$db]; END" >/dev/null 2>&1 || true
  for wt in "$work"/*/; do [ -d "$wt" ] && git -C "$repo" worktree remove --force "$wt" >/dev/null 2>&1 || true; done
  rm -rf "$work"
}
trap cleanup EXIT

# Build a source tree and return nothing; the app is then run from its build output.
build() {
  log "Building $2"
  dotnet build "$1/src/IncidentManager.Web" -c Release --nologo -v q >"$work/build-$2.log" 2>&1 \
    || { tail -30 "$work/build-$2.log"; fail "build of $2 failed"; }
}

# Start the app from a built source tree and wait until it answers HTTP (startup migrates + seeds BEFORE
# Kestrel listens, so answering means the schema work finished). Fails fast if the process dies.
start_app() {
  local dir="$1" label="$2" applog="$work/app-$2.log"
  local dll; dll="$(ls "$dir"/src/IncidentManager.Web/bin/Release/net*/IncidentManager.Web.dll | head -1)"
  log "Starting $label against [$db]"
  ( cd "$dir/src/IncidentManager.Web" && \
    ASPNETCORE_ENVIRONMENT=Development Database__Provider=SqlServer ConnectionStrings__Default="$conn" \
    EvidenceStore__RootPath="$evidence" \
    exec dotnet "$dll" --urls "http://127.0.0.1:$port" ) >"$applog" 2>&1 &
  app_pid=$!
  for _ in $(seq 1 120); do
    # Any HTTP answer means Kestrel is listening (older builds predate /health/live and 404 it).
    [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$port/health/live" || true)" != "000" ] && return 0
    if ! kill -0 "$app_pid" 2>/dev/null; then
      tail -40 "$applog"; app_pid=""; fail "$label exited during startup (see log above)"
    fi
    sleep 2
  done
  tail -40 "$applog"; fail "$label did not become live within 240s"
}

stop_app() {
  [ -n "$app_pid" ] || return 0
  kill "$app_pid" 2>/dev/null || true
  for _ in $(seq 1 20); do kill -0 "$app_pid" 2>/dev/null || break; sleep 1; done
  kill -9 "$app_pid" 2>/dev/null || true
  app_pid=""
}

# Migration IDs a source tree ships for SQL Server (the same derivation the release manifest uses).
migrations_in() {
  ls "$1/src/IncidentManager.Migrations.SqlServer/Migrations" \
    | grep -E '^[0-9]+_.*\.cs$' | grep -v '\.Designer\.cs$' | sed 's/\.cs$//' | sort
}

# --- 1. Old release creates + seeds the database -------------------------------------------------
sql "CREATE DATABASE [$db]" >/dev/null || fail "cannot create a database via SQLCMD ($SQLCMD)"
git -C "$repo" worktree add --detach "$work/from" "$from_ref" >/dev/null 2>&1 \
  || fail "cannot check out '$from_ref'"
build "$work/from" "from-$from_ref"
start_app "$work/from" "from-$from_ref"
stop_app

cases_before="$(sql "SELECT COUNT(*) FROM [$db].dbo.Cases")"
audit_before="$(sql "SELECT COUNT(*) FROM [$db].dbo.AuditLog")"
mig_before="$(sql "SELECT COUNT(*) FROM [$db].dbo.__EFMigrationsHistory")"
log "$from_ref installed: $mig_before migrations, $cases_before cases, $audit_before audit rows"
[ "$cases_before" -gt 0 ] || fail "$from_ref seeded no cases; the upgrade would not be exercised against data"

# --- 2. Newer build upgrades the same database in place ------------------------------------------
if [ -n "$to_ref" ]; then
  git -C "$repo" worktree add --detach "$work/to" "$to_ref" >/dev/null 2>&1 || fail "cannot check out '$to_ref'"
  to_dir="$work/to"; to_label="to-$to_ref"
else
  to_dir="$repo"; to_label="to-worktree"
fi
build "$to_dir" "$to_label"
start_app "$to_dir" "$to_label"
ready="$(curl -sS "http://127.0.0.1:$port/health" || true)"
stop_app
[ "$ready" = "Healthy" ] || { grep -iE "health|unhealthy|fail" "$work/app-$to_label.log" | tail -20; \
  fail "$to_label started but /health reported '$ready'"; }

# --- 3. Assertions -------------------------------------------------------------------------------
expected="$(migrations_in "$to_dir")"
applied="$(sql "SELECT MigrationId FROM [$db].dbo.__EFMigrationsHistory ORDER BY MigrationId")"
missing="$(comm -23 <(echo "$expected") <(echo "$applied"))"
[ -z "$missing" ] || fail "migrations not applied after upgrade: $(echo $missing)"

cases_after="$(sql "SELECT COUNT(*) FROM [$db].dbo.Cases")"
audit_after="$(sql "SELECT COUNT(*) FROM [$db].dbo.AuditLog")"
[ "$cases_after" -eq "$cases_before" ] || fail "case count changed across the upgrade ($cases_before -> $cases_after)"
[ "$audit_after" -ge "$audit_before" ] || fail "audit rows lost across the upgrade ($audit_before -> $audit_after)"

log "PASS $from_ref -> ${to_ref:-working tree}: $(echo "$expected" | wc -l | tr -d ' ') migrations applied, $cases_after cases and $audit_after audit rows preserved"
