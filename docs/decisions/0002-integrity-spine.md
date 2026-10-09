# 0002. Tamper evidence: row hashes, a hash-chained audit log and signed seals

- **Status:** Accepted. Keying the chain (HMAC) and copying seals outside CaseBook were added by [0016](0016-key-custody-and-seal-copies.md) (v1.4.0); the chain key is optional and off by default.
- **Recorded:** 2026-10-02

## Context

The record has to stand up to an examiner: what was known, when, and who changed it. A database administrator,
or an attacker with database access, can edit any row. An audit table that can itself be edited proves nothing.

## Decision

Three layers, all automatic:

1. **Row hash.** Business entities implement `IHashableEntity`. A SHA-256 over their canonical fields is stored
   in `RowHash` on every save.
2. **Hash-chained audit log.** `AuditChainInterceptor` (an EF Core `SaveChangesInterceptor`) writes one
   `AuditLogEntry` per changed entity, in the same transaction as the change. Each entry's hash covers the
   previous entry's hash, so inserting, deleting, reordering or editing history breaks the chain.
3. **Signed seals.** A background job periodically signs the chain head with an RSA key. It writes the seal
   to the database *and* to an out-of-band folder. A seal proves the history up to that point is unchanged.

Optionally, SQL Server ledger tables make the audit log, seals and custody events append-only in the engine
itself ([OPERATIONS.md §7](../OPERATIONS.md#7-sql-server-ledger-e-10)).

## Alternatives considered

- **An audit table without chaining:** editable without a trace.
- **A keyed chain (HMAC) instead of seals:** the key would sit on the same server. A seal exported elsewhere
  is a stronger anchor. HMAC keying is still a candidate hardening step.

## Consequences

- **Nobody edits the database directly.** An out-of-band change looks exactly like tampering and raises a
  Critical alarm (event 5001). Corrections go through the app.
- The chain alone is unkeyed. A competent attacker who recomputes every hash produces a chain that verifies.
  The seal check catches that, which is why the monitor verifies the latest seal as well as the chain.
- Changing an entity's `BuildCanonicalContent()` changes how existing rows hash. A new field must only extend
  the canonical content when it has a value, so existing rows still hash the same. Otherwise every existing
  row appears tampered.
- Some high-volume or cosmetic tables are deliberately outside the chain: access telemetry, graph layout, the
  user mirror. See [architecture/integrity.md](../architecture/integrity.md).
