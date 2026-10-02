# 0008. Evidence and report files on disk; hashes in the database

- **Status:** Accepted
- **Recorded:** 2026-10-02

## Context

Evidence files (exports, screenshots, packet captures) and generated reports can be large. Storing them in SQL
Server grows the database, slows backups and puts the files out of reach of host EDR scanning.

## Decision

Files are written to stores on a data volume outside the web root: `EvidenceStore:RootPath`,
`ReportOutput:RootPath`, plus the branding and Word-template stores. The database keeps the metadata and each
file's SHA-256, and the hash is part of the row's hashed content. Evidence files are never rewritten. An
optional job re-hashes stored evidence and raises event 5003 on drift.

## Consequences

- Back up the database **and** the file stores together. Otherwise references dangle and restored evidence
  fails verification ([OPERATIONS.md §1](../OPERATIONS.md#1-backup--disaster-recovery-h-03)).
- The web root can be read-only. Any store path left unset falls back to `App_Data` under the web root and
  fails with "Access denied" on a locked-down server. The upgrade script adds missing store settings.
