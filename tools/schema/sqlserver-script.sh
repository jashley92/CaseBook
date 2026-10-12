#!/usr/bin/env bash
# Generates deploy/sql/casebook-schema-sqlserver.sql, the idempotent SQL Server schema script a DBA applies in
# DbaApplies mode, from the EF Core migrations, then makes it safe to run on any database state (BUG-133).
#
#   bash tools/schema/sqlserver-script.sh            # regenerate the checked-in script
#   bash tools/schema/sqlserver-script.sh <path>     # write it elsewhere (CI compares that to the checked-in one)
#
# Why the post-processing: EF puts a migration's custom SQL (migrationBuilder.Sql) in the same batch as the ALTERs
# around it, guarded by IF NOT EXISTS. SQL Server binds column names on existing tables when it compiles the batch,
# whether or not the guard would run that statement, so a statement that names a column added earlier in the same
# migration (or one a later migration dropped) fails the whole batch. Running each data statement through EXEC
# defers its compilation until it actually runs.
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
out="${1:-$repo/deploy/sql/casebook-schema-sqlserver.sql}"
raw="$(mktemp)"
trap 'rm -f "$raw"' EXIT

IM_MIGRATIONS_PROVIDER=SqlServer dotnet ef migrations script --idempotent ${CASEBOOK_EF_ARGS:-} \
  --project "$repo/src/IncidentManager.Migrations.SqlServer" \
  --startup-project "$repo/src/IncidentManager.Web" --context AppDbContext \
  --output "$raw" >/dev/null

py="$(command -v python3 || command -v python)"
"$py" "$repo/tools/schema/defer_data_statements.py" "$raw" "$out"
