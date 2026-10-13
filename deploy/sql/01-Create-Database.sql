/*
  CaseBook - SQL Server 2022 database provisioning
  ------------------------------------------------------------------------------
  Creates the CaseBook database and the least-privilege login/user for the IIS
  application-pool identity, using WINDOWS (integrated) authentication only - no
  SQL logins, no passwords in configuration (see docs/OPERATIONS.md section 3).

  Run as a sysadmin ONCE against the target instance. Idempotent: re-running is
  safe. Invoke with sqlcmd variables, e.g.:

      sqlcmd -S SQLHOST\INSTANCE -E -b -i 01-Create-Database.sql ^
             -v DbName="CaseBook" AppAccount="CONTOSO\svc-casebook$" ^
                DataPath="" LogPath=""

  Variables:
    DbName      Database name (default CaseBook).
    AppAccount  Windows account the IIS app pool runs as. A gMSA is written with a
                trailing '$' (e.g. CONTOSO\svc-casebook$). Must already exist in AD.
    DataPath    Optional folder for the .mdf (blank = instance default).
    LogPath     Optional folder for the .ldf (blank = instance default).
    SchemaMode  'AppMigrates' (default) grants the app account db_owner so the app
                applies EF migrations on startup. 'DbaApplies' grants only
                data reader/writer + EXECUTE; a DBA then runs
                deploy/sql/casebook-schema-sqlserver.sql to create the schema.
*/

:on error exit

-- No :setvar defaults here: a :setvar in the script overrides the value passed on the command line, so the
-- defaults used to win over -v DbName/DataPath/LogPath/SchemaMode. Pass all five; use "(default)" for an
-- instance-default DataPath/LogPath (sqlcmd won't take an empty -v value). Install-Database.ps1 does this.

SET NOCOUNT ON;
GO

IF N'$(AppAccount)' = N'' OR N'$(AppAccount)' = N'$' + N'(AppAccount)'
BEGIN
    RAISERROR('AppAccount variable is required (e.g. -v AppAccount="CONTOSO\svc-casebook$").', 16, 1);
    SET NOEXEC ON;
END
GO

-- 1) Create the database (FULL recovery for point-in-time restore; see OPERATIONS section 1.1)
IF DB_ID(N'$(DbName)') IS NULL
BEGIN
    DECLARE @sql nvarchar(max) = N'CREATE DATABASE ' + QUOTENAME(N'$(DbName)');
    -- REV-74: either path on its own is honoured. CREATE DATABASE takes LOG ON only with ON PRIMARY, so the one not
    -- given is the instance default (SQL Server 2012+), rather than both being ignored unless both are set.
    DECLARE @data nvarchar(4000) = CASE WHEN N'$(DataPath)' IN (N'', N'(default)')
        THEN CAST(SERVERPROPERTY('InstanceDefaultDataPath') AS nvarchar(4000)) ELSE N'$(DataPath)' END;
    DECLARE @log nvarchar(4000) = CASE WHEN N'$(LogPath)' IN (N'', N'(default)')
        THEN CAST(SERVERPROPERTY('InstanceDefaultLogPath') AS nvarchar(4000)) ELSE N'$(LogPath)' END;
    IF RIGHT(@data, 1) = N'\' SET @data = LEFT(@data, LEN(@data) - 1);
    IF RIGHT(@log, 1) = N'\' SET @log = LEFT(@log, LEN(@log) - 1);
    IF N'$(DataPath)' NOT IN (N'', N'(default)') OR N'$(LogPath)' NOT IN (N'', N'(default)')
        SET @sql = N'CREATE DATABASE ' + QUOTENAME(N'$(DbName)') + N'
             ON PRIMARY (NAME = ' + QUOTENAME(N'$(DbName)' + N'_data', '''') + N',
                         FILENAME = ' + QUOTENAME(@data + N'\$(DbName).mdf', '''') + N')
             LOG ON     (NAME = ' + QUOTENAME(N'$(DbName)' + N'_log', '''') + N',
                         FILENAME = ' + QUOTENAME(@log + N'\$(DbName)_log.ldf', '''') + N')';
    -- EXEC's errors don't end the batch on their own, so catch and re-raise: the "Created" line only prints on
    -- success, and the re-raised error stops the script (sqlcmd :on error exit; Invoke-Sqlcmd -AbortOnError).
    BEGIN TRY
        EXEC (@sql);
        PRINT 'Created database [$(DbName)].';
    END TRY
    BEGIN CATCH
        THROW;
    END CATCH
END
ELSE
    PRINT 'Database [$(DbName)] already exists - leaving as-is.';
GO

IF (SELECT recovery_model_desc FROM sys.databases WHERE name = N'$(DbName)') <> N'FULL'
    ALTER DATABASE [$(DbName)] SET RECOVERY FULL;
-- Snapshot isolation eases the read-heavy dashboards without blocking writers. Switching it on needs the database to
-- itself, so ROLLBACK IMMEDIATE ends open transactions: only done when it is off, so a re-run against a live
-- database leaves running work alone.
IF (SELECT is_read_committed_snapshot_on FROM sys.databases WHERE name = N'$(DbName)') = 0
    ALTER DATABASE [$(DbName)] SET READ_COMMITTED_SNAPSHOT ON WITH ROLLBACK IMMEDIATE;
GO

-- 2) Server login for the app-pool identity (Windows auth) ----------------------
IF SUSER_ID(N'$(AppAccount)') IS NULL
BEGIN
    CREATE LOGIN [$(AppAccount)] FROM WINDOWS;
    PRINT 'Created login [$(AppAccount)].';
END
ELSE
    PRINT 'Login [$(AppAccount)] already exists.';
GO

-- 3) Database user + role membership -------------------------------------------
USE [$(DbName)];
GO

IF USER_ID(N'$(AppAccount)') IS NULL
BEGIN
    CREATE USER [$(AppAccount)] FOR LOGIN [$(AppAccount)];
    PRINT 'Created database user [$(AppAccount)] in [$(DbName)].';
END
GO

IF N'$(SchemaMode)' = N'AppMigrates'
BEGIN
    -- The app runs EF Core migrations at startup, which needs DDL rights.
    ALTER ROLE db_owner ADD MEMBER [$(AppAccount)];
    PRINT 'Granted db_owner to [$(AppAccount)] (app applies migrations at startup).';
END
ELSE
BEGIN
    -- A DBA runs the generated schema script; the app only reads/writes data.
    ALTER ROLE db_datareader ADD MEMBER [$(AppAccount)];
    ALTER ROLE db_datawriter ADD MEMBER [$(AppAccount)];
    GRANT EXECUTE TO [$(AppAccount)];
    PRINT 'Granted datareader/datawriter/EXECUTE to [$(AppAccount)] (DBA applies schema).';
    PRINT 'NEXT: run deploy/sql/casebook-schema-sqlserver.sql against [$(DbName)] as a privileged account.';
END
GO

PRINT 'CaseBook database provisioning complete for [$(DbName)].';
GO
