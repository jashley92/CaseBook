using FluentAssertions;
using IncidentManager.Application.Access;
using IncidentManager.Application.Integrity;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>
/// E-24 / C-05: the audit-trail and access-log CSVs an examiner receives. Pins the scope line, the column order,
/// UTC times, RFC-4180 quoting and the formula-injection guard, since a reviewer reads these files outside CaseBook.
/// </summary>
public class ExportCsvTests
{
    private static readonly DateTimeOffset Generated = new(2026, 10, 9, 14, 30, 5, TimeSpan.Zero);

    private static string[] Lines(string csv) => csv.Split("\r\n", StringSplitOptions.RemoveEmptyEntries);

    private static AuditLogEntry Entry(long seq, string? summary = null, string? before = null, string? after = null,
        AuditAction action = AuditAction.Update) => new()
    {
        Sequence = seq,
        // A non-UTC offset: the export must still print UTC.
        AtUtc = new DateTimeOffset(2026, 10, 9, 9, 15, 0, TimeSpan.FromHours(-4)),
        Actor = "analyst1",
        Action = action,
        EntityType = "Case",
        EntityLabel = "2026-0042",
        EntityId = "3fb9669b-0000-0000-0000-000000000001",
        CaseNumber = "2026-0042",
        Summary = summary,
        BeforeJson = before,
        AfterJson = after,
        Reason = "Examiner request",
        EntryHash = "ab12cd34",
    };

    [Fact]
    public void Audit_csv_states_its_scope_and_generation_time_in_utc()
    {
        Lines(AuditCsv.Build([], Generated, "2026-0042"))[0]
            .Should().Be("# CaseBook audit trail: case 2026-0042, generated 2026-10-09 14:30:05 UTC");
        Lines(AuditCsv.Build([], Generated))[0]
            .Should().Be("# CaseBook audit trail: all visible cases, generated 2026-10-09 14:30:05 UTC");
    }

    [Theory(DisplayName = "BUG-516: a case number can't open a cell or a row in the scope line")]
    [InlineData("2026-0042,=HYPERLINK(\"http://x\")", "# CaseBook audit trail: case 2026-0042 =HYPERLINK( http://x ), generated 2026-10-09 14:30:05 UTC")]
    [InlineData("=1+1", "# CaseBook audit trail: case =1+1, generated 2026-10-09 14:30:05 UTC")]
    [InlineData("2026-0042\r\n=cmd,x", "# CaseBook audit trail: case 2026-0042  =cmd x, generated 2026-10-09 14:30:05 UTC")]
    [InlineData("2026-0042;=cmd\t@x\u2028+y", "# CaseBook audit trail: case 2026-0042 =cmd @x +y, generated 2026-10-09 14:30:05 UTC")]
    public void Audit_csv_scope_line_keeps_a_hostile_case_number_inside_the_comment(string caseNumber, string expected)
    {
        var lines = Lines(AuditCsv.Build([], Generated, caseNumber));

        lines.Should().HaveCount(2, "the scope line and the header, with no forged row between them");
        lines[0].Should().Be(expected);
        // The only separator left is the fixed one before "generated", so no cell starts with the case number.
        lines[0].Split(',').Skip(1).Should().ContainSingle().Which.Should().StartWith(" generated");
        lines[1].Should().StartWith("sequence,");
    }

    [Fact]
    public void Audit_csv_has_a_fixed_header_and_one_row_per_entry_in_utc()
    {
        var lines = Lines(AuditCsv.Build([Entry(7, "Closed the case"), Entry(8, "Reopened")], Generated));

        lines[1].Should().Be("sequence,at_utc,actor,action,entity_type,entity_label,entity_id,case_number,summary,changes,reason,entry_hash");
        lines.Should().HaveCount(4);
        lines[2].Should().Be(
            "7,2026-10-09 13:15:00,analyst1,Update,Case,2026-0042,3fb9669b-0000-0000-0000-000000000001,2026-0042,Closed the case,,Examiner request,ab12cd34");
    }

    [Fact]
    public void Audit_csv_quotes_delimiters_and_neutralises_formulas()
    {
        var csv = AuditCsv.Build([Entry(1, "Renamed \"Wave 2\", then merged"), Entry(2, "=HYPERLINK(\"http://x\")")], Generated);

        csv.Should().Contain(",\"Renamed \"\"Wave 2\"\", then merged\",");
        // The leading '=' is defused with an apostrophe so a spreadsheet shows text instead of running a formula.
        csv.Should().Contain(",\"'=HYPERLINK(\"\"http://x\"\")\",");
    }

    [Fact]
    public void Audit_csv_renders_the_before_after_diff_as_a_readable_change_line()
    {
        var row = Lines(AuditCsv.Build([Entry(3, "Legal hold changed", "{\"LegalHold\":false}", "{\"LegalHold\":true}")], Generated))[2];

        row.Should().Contain(",Legal hold: No → Yes,");
    }

    [Fact]
    public void Audit_csv_leaves_the_change_column_empty_for_non_updates()
    {
        var row = Lines(AuditCsv.Build([Entry(4, "Opened", "{\"LegalHold\":false}", "{\"LegalHold\":true}", AuditAction.Create)], Generated))[2];

        row.Should().Contain(",Opened,,Examiner request,");
    }

    [Fact]
    public void Access_log_csv_has_a_header_and_one_row_per_session_in_utc()
    {
        var rows = new List<CaseAccessEvent>
        {
            new()
            {
                ActorUserId = "analyst1", AccessType = AccessType.CaseOpen, CaseNumber = "2026-0042",
                TargetLabel = "Case workspace, timeline", WasRestricted = true, Count = 3,
                FirstSeenUtc = new DateTimeOffset(2026, 10, 9, 9, 0, 0, TimeSpan.FromHours(-4)),
                LastSeenUtc = new DateTimeOffset(2026, 10, 9, 13, 20, 0, TimeSpan.Zero),
            },
            new()
            {
                ActorUserId = "=cmd", AccessType = AccessType.EvidenceDownload, CaseNumber = null, TargetLabel = null,
                WasRestricted = false, Count = 1,
                FirstSeenUtc = Generated, LastSeenUtc = Generated,
            },
        };

        var lines = Lines(AccessLogCsv.Build(rows, Generated));

        lines[0].Should().Be("# CaseBook access log (read and access telemetry, kept outside the tamper-evident chain), generated 2026-10-09 14:30:05 UTC");
        lines[1].Should().Be("actor,access_type,case_number,target,restricted,count,first_seen_utc,last_seen_utc");
        lines[2].Should().Be("analyst1,CaseOpen,2026-0042,\"Case workspace, timeline\",yes,3,2026-10-09 13:00:00,2026-10-09 13:20:00");
        // Missing case and target stay empty; a formula-looking actor is defused.
        lines[3].Should().Be("'=cmd,EvidenceDownload,,,no,1,2026-10-09 14:30:05,2026-10-09 14:30:05");
    }

    [Fact]
    public void An_export_cut_at_its_limit_says_so(/* REV-65 */)
    {
        Lines(AuditCsv.Build([], Generated, "2026-0042", truncatedAt: 100_000))[1]
            .Should().Be("# Truncated: only the newest 100000 rows are here. Narrow the date range to export the rest.");
        Lines(AccessLogCsv.Build([], Generated, truncatedAt: 100_000))[1].Should().StartWith("# Truncated: only the newest 100000");
        Lines(AccessLogCsv.Build([], Generated))[1].Should().StartWith("actor,", "an export that wasn't cut has no such line");
        // BUG-543: a comma in the line would split it into cells and read as "the newest 100".
        Lines(AuditCsv.Build([], Generated, truncatedAt: 100_000))[1].Should().NotContain(",");
        Lines(AccessLogCsv.Build([], Generated, truncatedAt: 100_000))[1].Should().NotContain(",");
    }

    [Fact]
    public void An_audit_export_cut_at_its_limit_says_so_at_the_end_too(/* CAP-03, CAP-32 */)
    {
        var cut = Lines(AuditCsv.Build([Entry(9, "Newest"), Entry(8, "Older")], Generated, truncatedAt: 2));
        cut[^1].Should().Be("# Truncated at 2 rows: narrow the range to export the rest.");
        cut[^1].Should().NotContainAny([",", ";"], "the line stays one cell in any spreadsheet locale (BUG-516, BUG-543)");
        cut.Should().HaveCount(6, "the two comment lines, the header and the two rows");

        Lines(AuditCsv.Build([Entry(9, "Newest")], Generated))[^1].Should().StartWith("9,", "an export that wasn't cut ends on its last row");
    }

    [Fact]
    public void Access_log_csv_with_no_rows_is_just_the_preamble_and_header()
    {
        Lines(AccessLogCsv.Build([], Generated)).Should().HaveCount(2);
    }
}
