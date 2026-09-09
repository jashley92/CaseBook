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

-- Defaults for variables not supplied on the command line -----------------------
:setvar DbName "CaseBook"
:setvar DataPath ""
:setvar LogPath ""
:setvar SchemaMode "AppMigrates"
-- AppAccount has no safe default; it must be provided.

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
    IF N'$(DataPath)' <> N'' AND N'$(LogPath)' <> N''
        SET @sql = N'CREATE DATABASE ' + QUOTENAME(N'$(DbName)') + N'
             ON PRIMARY (NAME = ' + QUOTENAME(N'$(DbName)' + N'_data', '''') + N',
                         FILENAME = ' + QUOTENAME(N'$(DataPath)\$(DbName).mdf', '''') + N')
             LOG ON     (NAME = ' + QUOTENAME(N'$(DbName)' + N'_log', '''') + N',
                         FILENAME = ' + QUOTENAME(N'$(LogPath)\$(DbName)_log.ldf', '''') + N')';
    EXEC (@sql);
    PRINT 'Created database [$(DbName)].';
END
ELSE
    PRINT 'Database [$(DbName)] already exists - leaving as-is.';
GO

ALTER DATABASE [$(DbName)] SET RECOVERY FULL;
-- Snapshot isolation eases the read-heavy dashboards without blocking writers.
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
