# 0009. Two migration sets; shipped migrations are immutable

- **Status:** Accepted
- **Recorded:** 2026-10-02

## Context

Developers need a database that installs nothing; production runs SQL Server. Separately, the SQL Server
migrations were squashed once before the repository went public, which left every earlier database unable to
upgrade.

## Decision

- **SQLite** migrations (development) live in `IncidentManager.Infrastructure/Persistence/Migrations`.
  **SQL Server** migrations (production) live in the `IncidentManager.Migrations.SqlServer` assembly. Every
  model change adds a migration to both.
- **A migration that shipped in a `v*` tag is never edited, renamed, deleted or squashed.** CI enforces this
  (`tools/ci/check-migrations-immutable.sh`). It also checks both providers for model changes that have no
  migration, and upgrades real SQL Server databases created by older releases, including v1.0.0, to the
  current build.

## Consequences

- Schema changes are always additive migrations. To undo something, add a migration that reverses it.
- Data fixes that existing installs need, such as adding a gate requirement, ship as data migrations, so
  upgraded and fresh installs end up the same.
- Sites with the ledger enabled accept only new **nullable** columns on the ledger tables. A test enforces it.
