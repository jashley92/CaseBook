using IncidentManager.Domain.Common;
using IncidentManager.Domain.Entities;

namespace IncidentManager.Application.Integrity;

/// <summary>
/// C18: every released migration whose SQL writes rows of an audited table. A migration runs outside CaseBook's
/// interceptor, so the rows it inserts have no trail and no hash, and those it rewrites no longer match their trail. The
/// start-up upgrade (RowHashUpgrade) records the hash of such a row only when it still holds what its migration wrote
/// (<see cref="Write.Seeded"/>); one changed since stays unrecorded and the record check flags it. A write that changes
/// nothing a row hash covers names why instead. AuditedWriterBypassTests fails while a migration writing an audited
/// table isn't listed here, so a new one has to say how its rows are told apart from rows planted in the database.
/// </summary>
public static class MigrationSeededRows
{
    /// <summary>What the matchers can look up: another record's trail, and each stage gate's trigger.</summary>
    public sealed record Lookup(Func<string, Guid, Task<TrailSnapshot?>> TrailOf, IReadOnlyDictionary<Guid, int> GateTriggers);

    /// <summary>
    /// One migration's write to one table. <paramref name="Seeded"/>, when given, says whether a row of the table holds
    /// what the migration wrote (given the row's own trail, null for a row it inserted); null when the write changes
    /// nothing a row hash covers.
    /// </summary>
    public sealed record Write(string Migration, string Table, string Why,
        Func<IHashableEntity, TrailSnapshot?, Lookup, Task<bool>>? Seeded = null);

    // ClosureGateNotificationsRecorded / ClosureGateHonestChecks: the close gate (trigger 3) is the only one they wrote to.
    private const int CloseGate = 3;

    private static bool OnCloseGate(StageGateRequirement r, Lookup l) => l.GateTriggers.TryGetValue(r.GateId, out var t) && t == CloseGate;

    // An inserted requirement holds exactly what its INSERT wrote (its order was the gate's next; any is accepted).
    private static Func<IHashableEntity, TrailSnapshot?, Lookup, Task<bool>> Inserted(string checkKey, string label, bool blocking) =>
        (row, trail, l) => Task.FromResult(trail is null && row is StageGateRequirement r && OnCloseGate(r, l)
            && (int)r.Kind == 0 && r.CheckKey == checkKey && r.CheckParam is null && r.Label == label && r.IsBlocking == blocking);

    /// <summary>Every released migration's write to an audited table.</summary>
    public static IReadOnlyList<Write> Writes { get; } =
    [
        new("AddReportTemplateLibrary", "ReportTemplates",
            "each report profile's Word template became a library template (same id as the profile, size 0)",
            async (row, trail, l) =>
            {
                if (trail is not null || row is not ReportTemplate t) return false;
                // As the INSERT wrote it from the profile, as the profile's own trail last recorded its template.
                if (await l.TrailOf(nameof(ReportProfile), t.Id) is not { } profile) return false;
                var file = profile.Text("TemplateFileName");
                return file is not null && t.FileName == file && t.Sha256 == (profile.Text("TemplateSha256") ?? "")
                       && t.Name == (file.EndsWith(".docx", StringComparison.OrdinalIgnoreCase) ? file[..^5] : file)
                       && t.SizeBytes == 0 && t.IsActive && !t.IsLessonsDefault;
            }),
        new("AddReportTemplateLibrary", "ReportProfiles", "set each profile's TemplateId, which isn't in a profile's row hash"),
        new("ClosureGateNotificationsRecorded", "StageGateRequirements",
            "the close gate's blocking 'notifications recorded' check",
            Inserted("NotificationsRecorded", "Required regulatory notifications recorded", blocking: true)),
        new("ClosureGateHonestChecks", "StageGateRequirements",
            "the close gate's advisory 'entities assessed' check, and its 'review complete' attestation rewritten as the 'lessons captured' check (hash cleared)",
            (row, trail, l) =>
            {
                if (row is not StageGateRequirement r || !OnCloseGate(r, l)) return Task.FromResult(false);
                if (trail is null)
                    return Inserted("EntitiesAssessed", "Every entity / IOC has a verdict (none left Unknown)", blocking: false)(row, trail, l);
                // BUG-621: the rewritten row: its trail still has the attestation, and the rest is as the trail has it.
                bool Same(string field, string now) => trail.TryGetRaw(field, out var was) && was == now;
                return Task.FromResult(trail.Text(nameof(StageGateRequirement.Label)) == "Post-incident review complete"
                    && Same(nameof(StageGateRequirement.Kind), "1")
                    && (int)r.Kind == 0 && r.CheckKey == "LessonsCaptured" && r.CheckParam is null
                    && r.Label == "Post-incident review recorded (Incidents & Breaches)"
                    && Same(nameof(StageGateRequirement.GateId), System.Text.Json.JsonSerializer.Serialize(r.GateId))
                    && Same(nameof(StageGateRequirement.Order), System.Text.Json.JsonSerializer.Serialize(r.Order))
                    && Same(nameof(StageGateRequirement.IsBlocking), r.IsBlocking ? "true" : "false"));
            }),
        new("CaseEditVersion", "CaseBriefs", "left one brief current per case; which version is current isn't in a brief's row hash (the lineage check reads it)"),
        new("CaseBriefLatestCurrent", "CaseBriefs", "made each case's latest brief the current one; IsCurrent isn't in a brief's row hash (the lineage check reads it)"),
    ];

    /// <summary>The entity types whose rows a listed migration inserted or rewrote, for the upgrade to look at.</summary>
    public static IReadOnlySet<string> SeededTypes { get; } = new HashSet<string>(StringComparer.Ordinal)
        { nameof(ReportTemplate), nameof(StageGateRequirement) };

    /// <summary>Whether a row holds what one of the listed migrations wrote to its table.</summary>
    public static async Task<bool> HoldsWhatAMigrationWroteAsync(string table, IHashableEntity row, TrailSnapshot? trail, Lookup lookup)
    {
        foreach (var w in Writes.Where(w => w.Seeded is not null && w.Table == table))
            if (await w.Seeded!(row, trail, lookup)) return true;
        return false;
    }
}
