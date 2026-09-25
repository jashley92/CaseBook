/*
  CaseBook - SQL Server 2022 ledger for the evidentiary tables (E-10)
  ------------------------------------------------------------------------------
  Rebuilds the three insert-only tables as APPEND-ONLY LEDGER tables:

      AuditLog              the hash-chained audit trail
      IntegritySeals        signed seals over the audit chain head
      ChainOfCustodyEvents  evidence custody history

  CaseBook already makes these tamper-evident in the application (hash chain +
  signed seals). The ledger adds an engine-level control underneath: SQL Server
  rejects UPDATE and DELETE on these tables for every principal, including
  db_owner and sysadmin, and keeps a cryptographic digest of every insert. A
  digest exported off the server (Export-LedgerDigest.ps1) later proves the
  tables were not altered, even by someone with full database rights.

  Run ONCE, after the schema exists (i.e. after the app's first start in
  AppMigrates mode, or after casebook-schema-sqlserver.sql in DbaApplies mode),
  as a sysadmin or db_owner, in the CaseBook database:

      sqlcmd -S SQLHOST\INSTANCE -E -b -C -d CaseBook -i 02-Enable-Ledger.sql

  Or use deploy/Enable-Ledger.ps1, which wraps this file.

  Idempotent: a table that is already a ledger table is left alone. Each table is
  converted in its own transaction: rename the old table, create the ledger table
  with the same columns, keys and indexes, copy every row, check the counts, drop
  the old table. Existing rows are preserved exactly.

  IMPORTANT - this is one-way. A ledger table cannot be turned back into an
  ordinary table, and a dropped ledger table is kept (renamed) by SQL Server.
  Take a full backup first. See docs/OPERATIONS.md, "SQL Server ledger".

  The column guard below refuses to run if a table's columns differ from what
  this script expects (for example after a newer CaseBook release changed the
  table). Use the copy of this script that shipped with your release.
*/

:on error exit
SET NOCOUNT ON;
SET XACT_ABORT ON;
GO

IF CAST(SERVERPROPERTY('ProductMajorVersion') AS int) < 16
    THROW 50000, 'Ledger tables need SQL Server 2022 or later.', 1;
IF OBJECT_ID(N'dbo.AuditLog', N'U') IS NULL
    THROW 50001, 'The CaseBook schema is not in this database yet. Start the app once (or apply casebook-schema-sqlserver.sql), then run this script.', 1;
GO

-- sp_verify_database_ledger (Verify-LedgerDigests.ps1) needs snapshot isolation allowed on the database.
-- This only permits SNAPSHOT transactions; it doesn't change how CaseBook reads (that's RCSI, already on).
IF NOT EXISTS (SELECT 1 FROM sys.databases WHERE database_id = DB_ID() AND snapshot_isolation_state = 1)
    ALTER DATABASE CURRENT SET ALLOW_SNAPSHOT_ISOLATION ON;
GO

-- Column guard: fails loudly if a table's shape differs from what this script rebuilds.
CREATE OR ALTER PROCEDURE #AssertColumns @Table sysname, @Expected nvarchar(max)
AS
BEGIN
    DECLARE @Actual nvarchar(max) =
        (SELECT STRING_AGG(CONVERT(nvarchar(max), c.name), N',') WITHIN GROUP (ORDER BY c.name)
         FROM sys.columns c
         WHERE c.object_id = OBJECT_ID(N'dbo.' + @Table) AND c.is_hidden = 0);
    DECLARE @Want nvarchar(max) =
        (SELECT STRING_AGG(CONVERT(nvarchar(max), LTRIM(RTRIM(value))), N',') WITHIN GROUP (ORDER BY LTRIM(RTRIM(value)))
         FROM STRING_SPLIT(@Expected, N','));
    IF @Actual <> @Want
    BEGIN
        DECLARE @Msg nvarchar(2048) = CONCAT(N'Table ', @Table, N' has columns [', @Actual,
            N'] but this script expects [', @Want, N']. Use the 02-Enable-Ledger.sql shipped with your CaseBook release.');
        THROW 50002, @Msg, 1;
    END
END;
GO

------------------------------------------------------------------------------------------
-- AuditLog
------------------------------------------------------------------------------------------
IF EXISTS (SELECT 1 FROM sys.tables WHERE object_id = OBJECT_ID(N'dbo.AuditLog') AND ledger_type = 0)
BEGIN
    EXEC #AssertColumns N'AuditLog',
        N'Id,Sequence,AtUtc,Actor,Action,EntityType,EntityId,EntityLabel,CaseNumber,Summary,BeforeJson,AfterJson,Reason,PrevHash,EntryHash';

    BEGIN TRANSACTION;
    EXEC sp_rename N'dbo.AuditLog', N'AuditLog_PreLedger';
    EXEC sp_rename N'dbo.PK_AuditLog', N'PK_AuditLog_PreLedger', N'OBJECT';

    CREATE TABLE dbo.AuditLog (
        [Id] uniqueidentifier NOT NULL,
        [Sequence] bigint NOT NULL,
        [AtUtc] datetimeoffset NOT NULL,
        [Actor] nvarchar(200) NOT NULL,
        [Action] int NOT NULL,
        [EntityType] nvarchar(100) NOT NULL,
        [EntityId] nvarchar(100) NULL,
        [CaseNumber] nvarchar(200) NULL,
        [Summary] nvarchar(2000) NULL,
        [BeforeJson] nvarchar(max) NULL,
        [AfterJson] nvarchar(max) NULL,
        [Reason] nvarchar(2000) NULL,
        [PrevHash] nvarchar(64) NOT NULL,
        [EntryHash] nvarchar(64) NOT NULL,
        [EntityLabel] nvarchar(300) NULL,
        CONSTRAINT [PK_AuditLog] PRIMARY KEY ([Id])
    ) WITH (LEDGER = ON (APPEND_ONLY = ON));

    INSERT INTO dbo.AuditLog ([Id],[Sequence],[AtUtc],[Actor],[Action],[EntityType],[EntityId],[CaseNumber],
                              [Summary],[BeforeJson],[AfterJson],[Reason],[PrevHash],[EntryHash],[EntityLabel])
    SELECT [Id],[Sequence],[AtUtc],[Actor],[Action],[EntityType],[EntityId],[CaseNumber],
           [Summary],[BeforeJson],[AfterJson],[Reason],[PrevHash],[EntryHash],[EntityLabel]
    FROM dbo.AuditLog_PreLedger
    ORDER BY [Sequence];

    IF (SELECT COUNT_BIG(*) FROM dbo.AuditLog) <> (SELECT COUNT_BIG(*) FROM dbo.AuditLog_PreLedger)
        THROW 50003, 'AuditLog row count mismatch after copy; rolled back.', 1;

    CREATE INDEX [IX_AuditLog_AtUtc] ON dbo.AuditLog ([AtUtc]);
    CREATE INDEX [IX_AuditLog_CaseNumber] ON dbo.AuditLog ([CaseNumber]);
    CREATE UNIQUE INDEX [IX_AuditLog_Sequence] ON dbo.AuditLog ([Sequence]);

    DROP TABLE dbo.AuditLog_PreLedger;
    COMMIT TRANSACTION;
    PRINT 'AuditLog is now an append-only ledger table.';
END
ELSE PRINT 'AuditLog is already a ledger table; left unchanged.';
GO

------------------------------------------------------------------------------------------
-- IntegritySeals
------------------------------------------------------------------------------------------
IF EXISTS (SELECT 1 FROM sys.tables WHERE object_id = OBJECT_ID(N'dbo.IntegritySeals') AND ledger_type = 0)
BEGIN
    EXEC #AssertColumns N'IntegritySeals',
        N'Id,SealedAtUtc,UpToSequence,ChainHeadHash,Signature,Algorithm,KeyId,SealedBy';

    BEGIN TRANSACTION;
    EXEC sp_rename N'dbo.IntegritySeals', N'IntegritySeals_PreLedger';
    EXEC sp_rename N'dbo.PK_IntegritySeals', N'PK_IntegritySeals_PreLedger', N'OBJECT';

    CREATE TABLE dbo.IntegritySeals (
        [Id] uniqueidentifier NOT NULL,
        [SealedAtUtc] datetimeoffset NOT NULL,
        [UpToSequence] bigint NOT NULL,
        [ChainHeadHash] nvarchar(64) NOT NULL,
        [Signature] nvarchar(1024) NOT NULL,
        [Algorithm] nvarchar(50) NOT NULL,
        [KeyId] nvarchar(100) NOT NULL,
        [SealedBy] nvarchar(200) NOT NULL,
        CONSTRAINT [PK_IntegritySeals] PRIMARY KEY ([Id])
    ) WITH (LEDGER = ON (APPEND_ONLY = ON));

    INSERT INTO dbo.IntegritySeals ([Id],[SealedAtUtc],[UpToSequence],[ChainHeadHash],[Signature],[Algorithm],[KeyId],[SealedBy])
    SELECT [Id],[SealedAtUtc],[UpToSequence],[ChainHeadHash],[Signature],[Algorithm],[KeyId],[SealedBy]
    FROM dbo.IntegritySeals_PreLedger
    ORDER BY [SealedAtUtc];

    IF (SELECT COUNT_BIG(*) FROM dbo.IntegritySeals) <> (SELECT COUNT_BIG(*) FROM dbo.IntegritySeals_PreLedger)
        THROW 50003, 'IntegritySeals row count mismatch after copy; rolled back.', 1;

    CREATE INDEX [IX_IntegritySeals_SealedAtUtc] ON dbo.IntegritySeals ([SealedAtUtc]);

    DROP TABLE dbo.IntegritySeals_PreLedger;
    COMMIT TRANSACTION;
    PRINT 'IntegritySeals is now an append-only ledger table.';
END
ELSE PRINT 'IntegritySeals is already a ledger table; left unchanged.';
GO

------------------------------------------------------------------------------------------
-- ChainOfCustodyEvents
-- The foreign key to Evidence is recreated WITHOUT the cascade delete EF declares: an
-- append-only table can never delete rows, and CaseBook never hard-deletes evidence, so
-- the cascade could only ever fail. Evidence rows keep being soft-deleted.
------------------------------------------------------------------------------------------
IF EXISTS (SELECT 1 FROM sys.tables WHERE object_id = OBJECT_ID(N'dbo.ChainOfCustodyEvents') AND ledger_type = 0)
BEGIN
    EXEC #AssertColumns N'ChainOfCustodyEvents', N'Id,EvidenceId,AtUtc,Actor,Action,Details';

    BEGIN TRANSACTION;
    ALTER TABLE dbo.ChainOfCustodyEvents DROP CONSTRAINT [FK_ChainOfCustodyEvents_Evidence_EvidenceId];
    EXEC sp_rename N'dbo.ChainOfCustodyEvents', N'ChainOfCustodyEvents_PreLedger';
    EXEC sp_rename N'dbo.PK_ChainOfCustodyEvents', N'PK_ChainOfCustodyEvents_PreLedger', N'OBJECT';

    CREATE TABLE dbo.ChainOfCustodyEvents (
        [Id] uniqueidentifier NOT NULL,
        [EvidenceId] uniqueidentifier NOT NULL,
        [AtUtc] datetimeoffset NOT NULL,
        [Actor] nvarchar(200) NOT NULL,
        [Action] nvarchar(100) NOT NULL,
        [Details] nvarchar(2000) NULL,
        CONSTRAINT [PK_ChainOfCustodyEvents] PRIMARY KEY ([Id]),
        CONSTRAINT [FK_ChainOfCustodyEvents_Evidence_EvidenceId] FOREIGN KEY ([EvidenceId]) REFERENCES dbo.[Evidence] ([Id])
    ) WITH (LEDGER = ON (APPEND_ONLY = ON));

    INSERT INTO dbo.ChainOfCustodyEvents ([Id],[EvidenceId],[AtUtc],[Actor],[Action],[Details])
    SELECT [Id],[EvidenceId],[AtUtc],[Actor],[Action],[Details]
    FROM dbo.ChainOfCustodyEvents_PreLedger
    ORDER BY [AtUtc];

    IF (SELECT COUNT_BIG(*) FROM dbo.ChainOfCustodyEvents) <> (SELECT COUNT_BIG(*) FROM dbo.ChainOfCustodyEvents_PreLedger)
        THROW 50003, 'ChainOfCustodyEvents row count mismatch after copy; rolled back.', 1;

    CREATE INDEX [IX_ChainOfCustodyEvents_EvidenceId] ON dbo.ChainOfCustodyEvents ([EvidenceId]);

    DROP TABLE dbo.ChainOfCustodyEvents_PreLedger;
    COMMIT TRANSACTION;
    PRINT 'ChainOfCustodyEvents is now an append-only ledger table.';
END
ELSE PRINT 'ChainOfCustodyEvents is already a ledger table; left unchanged.';
GO

-- Summary
SELECT t.name AS [Table], t.ledger_type_desc AS [Ledger]
FROM sys.tables t
WHERE t.name IN (N'AuditLog', N'IntegritySeals', N'ChainOfCustodyEvents')
ORDER BY t.name;
GO
