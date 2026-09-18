using FluentAssertions;
using IncidentManager.Application.Integrity;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using Xunit;

namespace IncidentManager.UnitTests;

public class AuditChangeDetailTests
{
    // --- ComposeSummary: names the meaningful fields that moved -----------------------------------------

    [Fact]
    public void Update_summary_names_the_changed_field()
    {
        var summary = AuditChangeDetail.ComposeSummary(
            AuditAction.Update, "Case", ["LegalHold", "ModifiedAtUtc", "RowHash"]);

        // Housekeeping (ModifiedAtUtc / RowHash) is dropped; the real field is named with a friendly label.
        summary.Should().Be("Update Case — Legal hold");
    }

    [Fact]
    public void Update_summary_falls_back_when_only_bookkeeping_changed()
    {
        var summary = AuditChangeDetail.ComposeSummary(
            AuditAction.Update, "Case", ["ModifiedAtUtc", "ModifiedBy", "RowHash"]);

        summary.Should().Be("Update Case");
    }

    [Fact]
    public void Create_and_delete_keep_the_plain_form()
    {
        AuditChangeDetail.ComposeSummary(AuditAction.Create, "Case", ["Title", "Summary"])
            .Should().Be("Create Case");
        AuditChangeDetail.ComposeSummary(AuditAction.SoftDelete, "CaseEntity", [])
            .Should().Be("SoftDelete CaseEntity");
    }

    // --- Changes: the readable before/after diff from the captured JSON ---------------------------------

    [Fact]
    public void Changes_reads_a_bool_flip_as_yes_no()
    {
        var entry = new AuditLogEntry
        {
            Action = AuditAction.Update,
            BeforeJson = """{"LegalHold":false}""",
            AfterJson = """{"LegalHold":true}""",
        };

        var changes = AuditChangeDetail.Changes(entry);
        changes.Should().ContainSingle();
        changes[0].Should().Be(new AuditChangeDetail.FieldChange("Legal hold", "No", "Yes"));
    }

    [Fact]
    public void Changes_omits_suppressed_and_unchanged_fields()
    {
        var entry = new AuditLogEntry
        {
            Action = AuditAction.Update,
            // Summary moved; RowHash is bookkeeping; IsRestricted is present but unchanged.
            BeforeJson = """{"Summary":"old","RowHash":"aaa","IsRestricted":false}""",
            AfterJson = """{"Summary":"new","RowHash":"bbb","IsRestricted":false}""",
        };

        var changes = AuditChangeDetail.Changes(entry);
        changes.Should().ContainSingle();
        changes[0].Label.Should().Be("Case summary");
        changes[0].Before.Should().Be("old");
        changes[0].After.Should().Be("new");
    }

    [Fact]
    public void Changes_formats_a_cleared_string_as_a_dash()
    {
        var entry = new AuditLogEntry
        {
            Action = AuditAction.Update,
            BeforeJson = """{"IncidentCommander":"user-1"}""",
            AfterJson = """{"IncidentCommander":null}""",
        };

        AuditChangeDetail.Changes(entry).Single()
            .Should().Be(new AuditChangeDetail.FieldChange("Incident commander", "user-1", "—"));
    }

    [Theory]
    [InlineData(AuditAction.Create)]
    [InlineData(AuditAction.SoftDelete)]
    public void Changes_is_empty_for_non_updates(AuditAction action)
    {
        var entry = new AuditLogEntry { Action = action, AfterJson = """{"LegalHold":true}""" };
        AuditChangeDetail.Changes(entry).Should().BeEmpty();
    }

    [Fact]
    public void Changes_never_throws_on_malformed_json()
    {
        var entry = new AuditLogEntry { Action = AuditAction.Update, BeforeJson = "{ not json", AfterJson = "{}" };
        AuditChangeDetail.Changes(entry).Should().BeEmpty();
    }

    [Fact]
    public void ToLine_renders_a_compact_one_liner_for_the_csv()
    {
        var entry = new AuditLogEntry
        {
            Action = AuditAction.Update,
            BeforeJson = """{"LegalHold":false,"IsRestricted":false}""",
            AfterJson = """{"LegalHold":true,"IsRestricted":true}""",
        };

        AuditChangeDetail.ToLine(AuditChangeDetail.Changes(entry))
            .Should().Be("Legal hold: No → Yes; Restricted: No → Yes");
    }
}
