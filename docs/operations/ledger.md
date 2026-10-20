# SQL Server ledger

Section 7 of the [operations guide](../OPERATIONS.md), which keeps the deploy-time checklist and the host controls. Section numbers are kept, so "OPERATIONS.md section 7" in the app and the scripts means this page.

## 7. SQL Server Ledger (E-10)

An optional, engine-level control under CaseBook's own tamper evidence. CaseBook already hash-chains the audit
log and signs seals over it (§2), so an edit to history is **detectable**. The ledger makes the three
evidentiary tables **append-only inside SQL Server**, so the engine itself refuses the edit, and gives you
digests that prove later nothing was changed:

| Table | Holds |
|---|---|
| `AuditLog` | The hash-chained audit trail |
| `IntegritySeals` | Signed seals over the chain head |
| `ChainOfCustodyEvents` | Evidence custody history |

Once on, `UPDATE`, `DELETE` and `TRUNCATE` on these tables fail for **every** principal, including `db_owner`
and `sysadmin`. A change made below SQL (editing the data files, restoring a doctored copy) fails
verification against a digest taken earlier. Both were tested against SQL Server 2022 CU27: the refusal on
`sa`, and a single byte changed on a raw data page with `DBCC WRITEPAGE`, reported by verification as a hash
mismatch on `AuditLog`.

CaseBook needs no change to run on ledger tables: it only ever inserts into them. **Administration → Server
configuration** and **Integrity & audit** show whether the ledger is on.

### 7.1 Turn it on (one-way)

A ledger table can't be turned back into an ordinary table. Take a full backup first (the script checks for one
from the last 24 hours and refuses otherwise).

1. Stop the CaseBook app pool.
2. As sysadmin or `db_owner`, after the schema exists (after the app's first start):
   ```powershell
   .\Enable-Ledger.ps1 -ConfigFile .\casebook.config.psd1     # SqlInstance, DbName, LedgerDigestPath
   ```
   It runs `deploy/sql/02-Enable-Ledger.sql`: each table is renamed, rebuilt as an append-only ledger table with
   the same columns, keys and indexes, every row copied and counted, and the old table dropped, one transaction
   per table. It also turns on `ALLOW_SNAPSHOT_ISOLATION`, which verification needs (it doesn't change how
   CaseBook reads). Re-running is safe; converted tables are skipped.
3. Start the app pool. Server configuration shows **SQL Server ledger: On**.

No SqlServer module or `sqlcmd.exe` is needed: the ledger scripts use the SqlClient built into Windows
PowerShell 5.1, with Windows integrated authentication (`-SqlCredential` only where that isn't possible).

One schema difference: EF declares a cascade delete from `Evidence` to `ChainOfCustodyEvents`. The ledger
table's foreign key has no cascade, because an append-only table can never delete. CaseBook never hard-deletes
evidence (it's soft-deleted), so nothing changes in practice.

### 7.2 Digests: schedule them, store them where the DBA can't

A digest is a hash over every ledger transaction so far. It's only proof if it lives outside the database
administrator's reach: an immutable (WORM / object-lock) share, or a server owned by security rather than the
DBAs. Set `LedgerDigestPath` in the answers file, then schedule a daily export, from the release's `deploy` folder:

```powershell
.\Export-LedgerDigest.ps1 -ConfigFile .\casebook.config.psd1 -Register -TaskAccount 'CONTOSO\svc-casebook-ops$' -At 02:00
```

That creates the task **CaseBook ledger digest**, with the server, database and folder written into it (the answers
file stays with the release), running the copy of the script kept beside the site (`-SitePath`, default
`C:\inetpub\casebook`), which upgrades keep current. A group managed service account (`DOMAIN\name$`) needs no
password; another account is asked for one.

The account needs `GENERATE LEDGER DIGEST` on the database (`db_owner` has it) and write access to the share.
The script exits 1 on failure so the scheduler can alert. Also take a digest before and after anything
notable (an upgrade, a restore, an examination).

### 7.3 Verify

```powershell
.\Verify-LedgerDigests.ps1 -ConfigFile .\casebook.config.psd1       # all saved digests
.\Verify-LedgerDigests.ps1 -ConfigFile .\casebook.config.psd1 -Latest 30
```

SQL Server recomputes every ledger row and transaction hash and checks them against the digests. **OK** means no
ledger row changed since the digests were taken. **FAIL** (exit 1) names the table and transaction: treat it as
a possible tampering incident, preserve the database, backups and digests, and compare against the app's own
chain check and seals (§2). **Couldn't verify** (exit 2) means the check didn't finish (SQL Server unreachable,
sign-in or permission refused, a timeout): it isn't a tamper finding; fix the cause and run it again. Run it monthly,
before an examination, and whenever the in-app chain check fails, and keep the output with your NYDFS Part 500
evidence. To run it every fourth Sunday, add `-Register -TaskAccount 'CONTOSO\svc-casebook-ops$'` (`-At`, default
04:00) to the first line: the task **CaseBook ledger verify** records the exit code as its last run result, so alert on
anything but 0.

### 7.4 Upgrades and schema changes

SQL Server allows only some schema changes on a ledger table. Tested on SQL Server 2022:

| Change | Allowed |
|---|---|
| Add a **nullable** column with no default | Yes |
| Add a `NOT NULL` column (with a default) | **No** |
| Widen a column, make it `NOT NULL`, rename or drop a column | Yes |
| Create / drop an index, rename the table | Yes |

CaseBook's build enforces the rule: `LedgerScriptModelTests` fails if a column is added to one of these tables
that isn't nullable, or if the model and `02-Enable-Ledger.sql` disagree. So a release can't ship a migration
that breaks on ledger-enabled sites. Use the `02-Enable-Ledger.sql` shipped with your release; its column guard
refuses to run against a table shape it doesn't expect.

A dropped ledger table isn't deleted: SQL Server keeps it, renamed `MSSQL_DroppedLedgerTable_...`. Nothing in
CaseBook drops these tables.
