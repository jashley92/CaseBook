using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace IncidentManager.Migrations.SqlServer.Migrations
{
    /// <summary>
    /// CAP-22: CaseBook's full-text catalog and indexes on the free-text columns Find and the case-list search read, created
    /// only when the server has Full-Text Search (SERVERPROPERTY('IsFullTextInstalled') = 1), so a server without the
    /// feature migrates cleanly and keeps searching by substring. Full-text DDL can't run inside a transaction, hence
    /// suppressTransaction. The SQL is FullTextSchema.Script as it stood when this shipped, copied here so the migration
    /// never changes (ADR 0009); a server that gets the feature later creates them from Diagnostics, or a DBA runs
    /// deploy/sql/03-Enable-FullText.sql.
    /// </summary>
    public partial class FullTextSearch : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql(@"
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
        EXEC(N'CREATE FULLTEXT INDEX ON [Evidence] ([OriginalFileName] LANGUAGE 1033, [Description] LANGUAGE 1033) KEY INDEX [PK_Evidence] ON [CaseBookText] WITH (CHANGE_TRACKING = AUTO, STOPLIST = OFF)');
    IF EXISTS (SELECT 1 FROM sys.fulltext_indexes WHERE object_id = OBJECT_ID(N'[Evidence]'))
       AND NOT EXISTS (SELECT 1 FROM sys.fulltext_index_columns WHERE object_id = OBJECT_ID(N'[Evidence]') AND column_id = COLUMNPROPERTY(OBJECT_ID(N'[Evidence]'), N'OriginalFileName', 'ColumnId'))
        EXEC(N'ALTER FULLTEXT INDEX ON [Evidence] ADD ([OriginalFileName] LANGUAGE 1033)');
    IF EXISTS (SELECT 1 FROM sys.fulltext_indexes WHERE object_id = OBJECT_ID(N'[Evidence]'))
       AND NOT EXISTS (SELECT 1 FROM sys.fulltext_index_columns WHERE object_id = OBJECT_ID(N'[Evidence]') AND column_id = COLUMNPROPERTY(OBJECT_ID(N'[Evidence]'), N'Description', 'ColumnId'))
        EXEC(N'ALTER FULLTEXT INDEX ON [Evidence] ADD ([Description] LANGUAGE 1033)');
END;
", suppressTransaction: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql(@"
IF EXISTS (SELECT 1 FROM sys.fulltext_indexes WHERE object_id = OBJECT_ID(N'[Cases]'))
    EXEC(N'DROP FULLTEXT INDEX ON [Cases]');
IF EXISTS (SELECT 1 FROM sys.fulltext_indexes WHERE object_id = OBJECT_ID(N'[CaseBriefs]'))
    EXEC(N'DROP FULLTEXT INDEX ON [CaseBriefs]');
IF EXISTS (SELECT 1 FROM sys.fulltext_indexes WHERE object_id = OBJECT_ID(N'[TimelineEntries]'))
    EXEC(N'DROP FULLTEXT INDEX ON [TimelineEntries]');
IF EXISTS (SELECT 1 FROM sys.fulltext_indexes WHERE object_id = OBJECT_ID(N'[AnalystNotes]'))
    EXEC(N'DROP FULLTEXT INDEX ON [AnalystNotes]');
IF EXISTS (SELECT 1 FROM sys.fulltext_indexes WHERE object_id = OBJECT_ID(N'[ActionItems]'))
    EXEC(N'DROP FULLTEXT INDEX ON [ActionItems]');
IF EXISTS (SELECT 1 FROM sys.fulltext_indexes WHERE object_id = OBJECT_ID(N'[ActionItemComments]'))
    EXEC(N'DROP FULLTEXT INDEX ON [ActionItemComments]');
IF EXISTS (SELECT 1 FROM sys.fulltext_indexes WHERE object_id = OBJECT_ID(N'[Evidence]'))
    EXEC(N'DROP FULLTEXT INDEX ON [Evidence]');
IF EXISTS (SELECT 1 FROM sys.fulltext_catalogs WHERE name = N'CaseBookText')
    EXEC(N'DROP FULLTEXT CATALOG [CaseBookText]');
", suppressTransaction: true);
        }
    }
}
