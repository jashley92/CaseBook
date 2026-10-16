using System.Text.RegularExpressions;
using FluentAssertions;
using IncidentManager.Application.Import;
using IncidentManager.Application.Views;
using IncidentManager.Domain.Entities;
using IncidentManager.Infrastructure.Access;
using IncidentManager.Infrastructure.Notifications;
using IncidentManager.Infrastructure.Persistence;
using IncidentManager.Infrastructure.Security;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// C12: text the app builds or caps itself (a label, a recipient list, a mirrored name, a reviewer's note) fits the
/// column it's stored in. SQLite ignores column lengths and SQL Server refuses the whole row, and these writers swallow
/// the failure (the access-log row, the queued alert, the directory refresh were lost) or end the circuit.
/// The per-writer behaviour is tested beside each service and checked here with <see cref="AssertFits"/>.
/// </summary>
public sealed partial class GeneratedTextFitsColumnTests
{
    /// <summary>Fails when any string of <paramref name="row"/> is longer than its column in the model.</summary>
    internal static void AssertFits(AppDbContext db, object row)
    {
        var entity = db.Model.FindEntityType(row.GetType()) ?? throw new InvalidOperationException($"{row.GetType().Name} isn't mapped.");
        foreach (var p in entity.GetProperties().Where(p => p.ClrType == typeof(string) && p.GetMaxLength() is not null))
        {
            var value = (string?)p.PropertyInfo?.GetValue(row);
            (value?.Length ?? 0).Should().BeLessThanOrEqualTo(p.GetMaxLength()!.Value, $"{entity.ClrType.Name}.{p.Name} is {p.GetMaxLength()} long");
        }
    }

    [Fact]
    public void The_caps_the_writers_use_are_the_columns_lengths()
    {
        using var database = TestDatabase.Open(TestDatabase.Sqlite);
        using var db = database.NewContext();
        int Max<T>(string property) => db.Model.FindEntityType(typeof(T))!.FindProperty(property)!.GetMaxLength()!.Value;

        AccessLogService.MaxTargetLabelLength.Should().Be(Max<CaseAccessEvent>(nameof(CaseAccessEvent.TargetLabel)));
        CriticalAlertOutbox.MaxRecipientsLength.Should().Be(Max<AlertDelivery>(nameof(AlertDelivery.Recipients)));
        CriticalAlertOutbox.MaxSubjectLength.Should().Be(Max<AlertDelivery>(nameof(AlertDelivery.Subject)));
        UserDirectory.MaxDisplayNameLength.Should().Be(Max<AppUser>(nameof(AppUser.DisplayName)));
        UserDirectory.MaxUpnLength.Should().Be(Max<AppUser>(nameof(AppUser.UserPrincipalName)));
        UserDirectory.MaxEmailLength.Should().Be(Max<AppUser>(nameof(AppUser.Email)));
        SavedViewService.MaxQueryLength.Should().Be(Max<SavedView>(nameof(SavedView.Query)));
        CaseImportService.MaxDecisionNoteLength.Should().Be(Max<PendingImport>(nameof(PendingImport.DecisionNote)));
        CaseImportService.MaxQueueSummaryLength.Should().Be(Max<PendingImport>(nameof(PendingImport.Summary)));
    }

    // ── Structural: no new hand-rolled cap ─────────────────────────────────────────────────────────────────────

    // `s.Length > n ? s[..n] : s`, `if (s.Length > n) s = s[..n]`, `s[..(n - 1)] + "…"`, `Substring(0, n)` cuts.
    [GeneratedRegex(@"\.Length\s*(<=|>=|<|>)\s*[\w.()+\- ]+.*\[\.\.[^\]]*\]|\[\.\.\(?[\w.]+\s*(-\s*\d+)?\)?\]\s*(\.TrimEnd\(\))?\s*\+\s*""…""|\.Substring\(0,\s*[\w.]+\)", RegexOptions.None, 1000)]
    private static partial Regex HandRolledCap();

    /// <summary>
    /// Hand-rolled caps in files other owners hold, kept until those owners move them to TextFit.Cap (REPORTED), and the
    /// wave-2 .razor ones. File name plus a distinctive piece of the line; stale entries don't fail.
    /// </summary>
    private static readonly (string File, string Code)[] Elsewhere =
    [
        ("AccessLogCsv.cs", "label[..499]"),
        ("AccountDirectoryService.cs", "s[..max]"),
        ("CaseOutcomeService.cs", "baseKey[..60]"),
        ("DataElementService.cs", "baseKey[..(MaxKeyLength - 6)]"),
        ("CaseMilestones.cs", "text[..599]"),
        ("CaseService.cs", "text[..(max - 1)]"),
        ("CaseService.cs", "source[..200]"),
        ("CaseService.cs", "reason[..500]"),
        ("CaseService.cs", "source[..199]"),
        ("ClosingBriefPrompt.cs", "body[..CaseBrief.MaxPartLength]"),
        ("ClosingBriefPrompt.cs", "text[..(MaxEntryLength - 1)]"),
        ("TaskResults.cs", "line[..(max - 1)]"),
        ("ReleaseFeed.cs", "notes[..MaxNotesChars]"),
        ("SecurityEvents.cs", "reason[..200]"),
        ("AppVersionInfo.cs", "sha[..7]"),
        ("FindQuery.cs", "terms[..MaxTerms]"),
        ("Case.cs", "name[..400]"),
        ("Case.cs", "t[..(ActionItem.MaxTitleLength - 1)]"),
        ("Case.cs", "steps[..CaseBrief.MaxPartLength]"),
        ("CaseNotifications.cs", "plain[..280]"),
        ("DbNotificationMarks.cs", "key[..NotificationMark.MaxKeyLength]"),
        ("AuditChainInterceptor.cs", "s[..(max - 1)]"),
        ("AuditChainInterceptor.cs", "firstLine[..(max - 1)]"),
        ("AuditWriter.cs", "summary[..1999]"),
        ("FileReportStore.cs", "stem[..MaxStemLength]"),
        ("EvidenceIntegrityVerifier.cs", "hex[..12]"),
        ("EventLogTransport.cs", "detail[..keep]"),
        ("SkiaReportDiagrams.cs", "s[..^1]"),
        // Web (wave 2 for the .razor files; Program.cs and the code-behind belong to the UI owners)
        ("AdminConfigBundle.razor", "s[..12]"),
        ("CaseAuditTab.razor", "value[..(max - 1)]"),
        ("CaseOverviewTab.razor", "text[..157]"),
        ("CaseTimelineTab.razor", "text[..(ActionItem.MaxTitleLength - 1)]"),
        ("CaseTimelineTab.razor", "t[..87]"),
        ("CreateCase.razor", "s[..42]"),
        ("Integrity.razor", "h[..12]"),
        ("StoredReportTable.razor", "h[..16]"),
        ("DateFieldBase.cs", "text[..Format.Length]"),
        ("ApiKeyAuthenticationHandler.cs", "token[..12]"),
    ];

    [Fact]
    public void Text_is_capped_with_TextFit_not_by_hand()
    {
        var root = Path.Combine(RepoRoot(), "src");
        var hits = Directory.EnumerateFiles(root, "*.*", SearchOption.AllDirectories)
            .Where(f => f.EndsWith(".cs", StringComparison.Ordinal) || f.EndsWith(".razor", StringComparison.Ordinal))
            .Where(f => !f.Contains($"{Path.DirectorySeparatorChar}Migrations{Path.DirectorySeparatorChar}")
                        && !f.EndsWith("DevDataSeeder.cs", StringComparison.Ordinal)
                        && !f.EndsWith("TextFit.cs", StringComparison.Ordinal))
            .SelectMany(f => File.ReadLines(f).Select((line, i) => (File: f, Line: i + 1, Text: line)))
            .Where(l => !l.Text.TrimStart().StartsWith("//", StringComparison.Ordinal) && HandRolledCap().IsMatch(l.Text))
            .Where(l => !Elsewhere.Any(e => Path.GetFileName(l.File) == e.File && l.Text.Contains(e.Code, StringComparison.Ordinal)))
            .Select(l => $"{Path.GetRelativePath(root, l.File)}:{l.Line}: {l.Text.Trim()}")
            .ToList();

        hits.Should().BeEmpty("cap text with TextFit.Cap: it keeps the ellipsis inside the limit and never splits a surrogate pair");
    }

    private static string RepoRoot()
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
            if (File.Exists(Path.Combine(dir.FullName, "IncidentManager.sln"))) return dir.FullName;
        throw new InvalidOperationException("Couldn't find the repo root (IncidentManager.sln).");
    }
}
