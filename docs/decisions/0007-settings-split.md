# 0007. Operational settings in the database; security settings in server files

- **Status:** Accepted
- **Recorded:** 2026-10-02

## Context

Operators need to change things like SLA targets, reminder timing and email wording without a deployment.
But if the database could override any setting, anyone with write access to it could redirect the SIEM
stream, swap the signing-key path or switch authentication off.

## Decision

- `SettingsCatalog` is a **whitelist** of operational settings. Only these can be edited in-app. Each change is
  an audited, hash-chained `AppSetting` row, and configuration reloads without a restart.
- The database configuration provider applies the **same whitelist when loading**. A row with any other key
  could only have been written out of band. It is ignored, logged as Critical and emitted as SIEM event 5002.
- Everything else lives in `appsettings.Production.json` or environment variables: connection strings,
  `Auth:Mode`, key paths, `RoleMapping`, `Siem:*`, `Secrets:*`. Administration shows these read-only, and
  shows only whether a secret is present.

## Consequences

- To add an operational setting, add it to `SettingsCatalog`. To add a sensitive one, keep it out.
- A setting can come from three places: file, environment or database. Administration → Settings shows the
  effective value and where it came from.
