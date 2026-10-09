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
    public void Access_log_csv_with_no_rows_is_just_the_preamble_and_header()
    {
        Lines(AccessLogCsv.Build([], Generated)).Should().HaveCount(2);
    }
}
