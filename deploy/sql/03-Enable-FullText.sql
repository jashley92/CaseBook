/*
  CaseBook - full-text search on SQL Server (CAP-22)
  ------------------------------------------------------------------------------
  Creates CaseBook's full-text catalog (CaseBookText) and the full-text indexes on
  the free-text columns Find and the case-list search read: case titles and
  summaries, briefs, record entries, working notes, tasks, task comments and
  evidence descriptions. With them, a search word matches words that start with
  it, from the index, instead of a substring scan of every row. Evidence file
  names stay a substring match (the word breaker keeps lsass_dump.dmp whole).

  Optional. Without Full-Text Search installed on the instance, CaseBook searches
  by substring, as it always has; this script then does nothing.

  CaseBook's migration creates these when the feature is already installed. Run
  this when it was added afterwards and the app account can't create them itself
  (DbaApplies mode), as db_owner (or db_ddladmin) in the CaseBook database:

      sqlcmd -S SQLHOST\INSTANCE -E -b -C -I -d CaseBook -i 03-Enable-FullText.sql

  In AppMigrates mode, Administration > Diagnostics > "Create full-text indexes"
  does the same. Idempotent: it creates only what is missing. SQL Server fills
  the indexes in the background; Diagnostics shows when search uses them. Not
  inside a transaction (full-text DDL can't be).

  The statements below are the app's own (FullTextSchema.Script); a test keeps
  this file the same as them. Use the copy that shipped with your release.
*/
-- CAP-22: CaseBook's full-text catalog and indexes. Creates only what's missing, and nothing when the server
-- doesn't have Full-Text Search, so it can be run again at any time. Not inside a transaction.
IF CAST(ISNULL(SERVERPROPERTY('IsFullTextInstalled'), 0) AS int) = 1
BEGIN
    IF NOT EXISTS (SELECT 1 FROM sys.fulltext_catalogs WHERE name = N'CaseBookText')
        EXEC(N'CREATE FULLTEXT CATALOG [CaseBookText]');
    IF OBJECT_ID(N'[Cases]') IS NOT NULL AND NOT EXISTS (SELECT 1 FROM sys.fulltext_indexes WHERE object_id = OBJECT_ID(N'[Cases]'))
        EXEC(N'CREATE FULLTEXT INDEX ON [Cases] ([Title] LANGUAGE 1033, [Summary] LANGUAGE 1033) KEY INDEX [PK_Cases] ON [CaseBookText] WITH (CHANGE_TRACKING = AUTO, STOPLIST = OFF)');
    IF EXISTS (SELECT 1 FROM sys.fulltext_indexes WHERE object_id = OBJECT_ID(N'[Cases]'))
       AND NOT EXISTS (SELECT 1 FROM sys.fulltext_index_columns WHERE object_id = OBJECT_ID(N'[Cases]') AND column_id = COLUMNPROPERTY(OBJECT_ID(N'[Cases]'), N'Title', 'ColumnId'))
        EXEC(N'ALTER FULLTEXT INDEX ON [Cases] ADD ([Title] LANGUAGE 1033)');
    IF EXISTS (SELECT 1 FROM sys.fulltext_indexes WHERE object_id = OBJECT_ID(N'[Cases]'))
       AND NOT EXISTS (SELECT 1 FROM sys.fulltext_index_columns WHERE object_id = OBJECT_ID(N'[Cases]') AND column_id = COLUMNPROPERTY(OBJECT_ID(N'[Cases]'), N'Summary', 'ColumnId'))
        EXEC(N'ALTER FULLTEXT INDEX ON [Cases] ADD ([Summary] LANGUAGE 1033)');
    IF OBJECT_ID(N'[CaseBriefs]') IS NOT NULL AND NOT EXISTS (SELECT 1 FROM sys.fulltext_indexes WHERE object_id = OBJECT_ID(N'[CaseBriefs]'))
        EXEC(N'CREATE FULLTEXT INDEX ON [CaseBriefs] ([Summary] LANGUAGE 1033, [WorkingAssessment] LANGUAGE 1033, [Known] LANGUAGE 1033, [OpenQuestions] LANGUAGE 1033) KEY INDEX [PK_CaseBriefs] ON [CaseBookText] WITH (CHANGE_TRACKING = AUTO, STOPLIST = OFF)');
    IF EXISTS (SELECT 1 FROM sys.fulltext_indexes WHERE object_id = OBJECT_ID(N'[CaseBriefs]'))
       AND NOT EXISTS (SELECT 1 FROM sys.fulltext_index_columns WHERE object_id = OBJECT_ID(N'[CaseBriefs]') AND column_id = COLUMNPROPERTY(OBJECT_ID(N'[CaseBriefs]'), N'Summary', 'ColumnId'))
        EXEC(N'ALTER FULLTEXT INDEX ON [CaseBriefs] ADD ([Summary] LANGUAGE 1033)');
    IF EXISTS (SELECT 1 FROM sys.fulltext_indexes WHERE object_id = OBJECT_ID(N'[CaseBriefs]'))
       AND NOT EXISTS (SELECT 1 FROM sys.fulltext_index_columns WHERE object_id = OBJECT_ID(N'[CaseBriefs]') AND column_id = COLUMNPROPERTY(OBJECT_ID(N'[CaseBriefs]'), N'WorkingAssessment', 'ColumnId'))
        EXEC(N'ALTER FULLTEXT INDEX ON [CaseBriefs] ADD ([WorkingAssessment] LANGUAGE 1033)');
    IF EXISTS (SELECT 1 FROM sys.fulltext_indexes WHERE object_id = OBJECT_ID(N'[CaseBriefs]'))
       AND NOT EXISTS (SELECT 1 FROM sys.fulltext_index_columns WHERE object_id = OBJECT_ID(N'[CaseBriefs]') AND column_id = COLUMNPROPERTY(OBJECT_ID(N'[CaseBriefs]'), N'Known', 'ColumnId'))
        EXEC(N'ALTER FULLTEXT INDEX ON [CaseBriefs] ADD ([Known] LANGUAGE 1033)');
    IF EXISTS (SELECT 1 FROM sys.fulltext_indexes WHERE object_id = OBJECT_ID(N'[CaseBriefs]'))
       AND NOT EXISTS (SELECT 1 FROM sys.fulltext_index_columns WHERE object_id = OBJECT_ID(N'[CaseBriefs]') AND column_id = COLUMNPROPERTY(OBJECT_ID(N'[CaseBriefs]'), N'OpenQuestions', 'ColumnId'))
        EXEC(N'ALTER FULLTEXT INDEX ON [CaseBriefs] ADD ([OpenQuestions] LANGUAGE 1033)');
    IF OBJECT_ID(N'[TimelineEntries]') IS NOT NULL AND NOT EXISTS (SELECT 1 FROM sys.fulltext_indexes WHERE object_id = OBJECT_ID(N'[TimelineEntries]'))
        EXEC(N'CREATE FULLTEXT INDEX ON [TimelineEntries] ([Description] LANGUAGE 1033, [Rationale] LANGUAGE 1033) KEY INDEX [PK_TimelineEntries] ON [CaseBookText] WITH (CHANGE_TRACKING = AUTO, STOPLIST = OFF)');
    IF EXISTS (SELECT 1 FROM sys.fulltext_indexes WHERE object_id = OBJECT_ID(N'[TimelineEntries]'))
       AND NOT EXISTS (SELECT 1 FROM sys.fulltext_index_columns WHERE object_id = OBJECT_ID(N'[TimelineEntries]') AND column_id = COLUMNPROPERTY(OBJECT_ID(N'[TimelineEntries]'), N'Description', 'ColumnId'))
        EXEC(N'ALTER FULLTEXT INDEX ON [TimelineEntries] ADD ([Description] LANGUAGE 1033)');
    IF EXISTS (SELECT 1 FROM sys.fulltext_indexes WHERE object_id = OBJECT_ID(N'[TimelineEntries]'))
       AND NOT EXISTS (SELECT 1 FROM sys.fulltext_index_columns WHERE object_id = OBJECT_ID(N'[TimelineEntries]') AND column_id = COLUMNPROPERTY(OBJECT_ID(N'[TimelineEntries]'), N'Rationale', 'ColumnId'))
        EXEC(N'ALTER FULLTEXT INDEX ON [TimelineEntries] ADD ([Rationale] LANGUAGE 1033)');
    IF OBJECT_ID(N'[AnalystNotes]') IS NOT NULL AND NOT EXISTS (SELECT 1 FROM sys.fulltext_indexes WHERE object_id = OBJECT_ID(N'[AnalystNotes]'))
        EXEC(N'CREATE FULLTEXT INDEX ON [AnalystNotes] ([Body] LANGUAGE 1033) KEY INDEX [PK_AnalystNotes] ON [CaseBookText] WITH (CHANGE_TRACKING = AUTO, STOPLIST = OFF)');
    IF EXISTS (SELECT 1 FROM sys.fulltext_indexes WHERE object_id = OBJECT_ID(N'[AnalystNotes]'))
       AND NOT EXISTS (SELECT 1 FROM sys.fulltext_index_columns WHERE object_id = OBJECT_ID(N'[AnalystNotes]') AND column_id = COLUMNPROPERTY(OBJECT_ID(N'[AnalystNotes]'), N'Body', 'ColumnId'))
        EXEC(N'ALTER FULLTEXT INDEX ON [AnalystNotes] ADD ([Body] LANGUAGE 1033)');
    IF OBJECT_ID(N'[ActionItems]') IS NOT NULL AND NOT EXISTS (SELECT 1 FROM sys.fulltext_indexes WHERE object_id = OBJECT_ID(N'[ActionItems]'))
        EXEC(N'CREATE FULLTEXT INDEX ON [ActionItems] ([Title] LANGUAGE 1033, [Description] LANGUAGE 1033) KEY INDEX [PK_ActionItems] ON [CaseBookText] WITH (CHANGE_TRACKING = AUTO, STOPLIST = OFF)');
    IF EXISTS (SELECT 1 FROM sys.fulltext_indexes WHERE object_id = OBJECT_ID(N'[ActionItems]'))
       AND NOT EXISTS (SELECT 1 FROM sys.fulltext_index_columns WHERE object_id = OBJECT_ID(N'[ActionItems]') AND column_id = COLUMNPROPERTY(OBJECT_ID(N'[ActionItems]'), N'Title', 'ColumnId'))
        EXEC(N'ALTER FULLTEXT INDEX ON [ActionItems] ADD ([Title] LANGUAGE 1033)');
    IF EXISTS (SELECT 1 FROM sys.fulltext_indexes WHERE object_id = OBJECT_ID(N'[ActionItems]'))
       AND NOT EXISTS (SELECT 1 FROM sys.fulltext_index_columns WHERE object_id = OBJECT_ID(N'[ActionItems]') AND column_id = COLUMNPROPERTY(OBJECT_ID(N'[ActionItems]'), N'Description', 'ColumnId'))
        EXEC(N'ALTER FULLTEXT INDEX ON [ActionItems] ADD ([Description] LANGUAGE 1033)');
    IF OBJECT_ID(N'[ActionItemComments]') IS NOT NULL AND NOT EXISTS (SELECT 1 FROM sys.fulltext_indexes WHERE object_id = OBJECT_ID(N'[ActionItemComments]'))
        EXEC(N'CREATE FULLTEXT INDEX ON [ActionItemComments] ([Body] LANGUAGE 1033) KEY INDEX [PK_ActionItemComments] ON [CaseBookText] WITH (CHANGE_TRACKING = AUTO, STOPLIST = OFF)');
    IF EXISTS (SELECT 1 FROM sys.fulltext_indexes WHERE object_id = OBJECT_ID(N'[ActionItemComments]'))
       AND NOT EXISTS (SELECT 1 FROM sys.fulltext_index_columns WHERE object_id = OBJECT_ID(N'[ActionItemComments]') AND column_id = COLUMNPROPERTY(OBJECT_ID(N'[ActionItemComments]'), N'Body', 'ColumnId'))
        EXEC(N'ALTER FULLTEXT INDEX ON [ActionItemComments] ADD ([Body] LANGUAGE 1033)');
    IF OBJECT_ID(N'[Evidence]') IS NOT NULL AND NOT EXISTS (SELECT 1 FROM sys.fulltext_indexes WHERE object_id = OBJECT_ID(N'[Evidence]'))
        EXEC(N'CREATE FULLTEXT INDEX ON [Evidence] ([Description] LANGUAGE 1033) KEY INDEX [PK_Evidence] ON [CaseBookText] WITH (CHANGE_TRACKING = AUTO, STOPLIST = OFF)');
    IF EXISTS (SELECT 1 FROM sys.fulltext_indexes WHERE object_id = OBJECT_ID(N'[Evidence]'))
       AND NOT EXISTS (SELECT 1 FROM sys.fulltext_index_columns WHERE object_id = OBJECT_ID(N'[Evidence]') AND column_id = COLUMNPROPERTY(OBJECT_ID(N'[Evidence]'), N'Description', 'ColumnId'))
        EXEC(N'ALTER FULLTEXT INDEX ON [Evidence] ADD ([Description] LANGUAGE 1033)');
END;
