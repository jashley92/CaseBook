using System.Text.Json;
using IncidentManager.Application.Abstractions;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using Microsoft.EntityFrameworkCore;

namespace IncidentManager.Application.Sla;

/// <summary>The SLA targets as settings name them (<c>Sla:{Clock}:{Severity}</c>, <c>Sla:Breach:…</c>, the at-risk percent).</summary>
public static class SlaTargetSettings
{
    // Informational carries no SLA; only the four actionable severities have targets.
    private static readonly Severity[] Severities = { Severity.Low, Severity.Medium, Severity.High, Severity.Critical };
    private static readonly SlaClock[] Clocks = { SlaClock.Containment, SlaClock.Resolution, SlaClock.Detection };
    // PROD-08: clocks a Breach-classified case may override (detection happens before classification).
    private static readonly SlaClock[] BreachClocks = { SlaClock.Containment, SlaClock.Resolution };

    /// <summary>The prefix every SLA setting key has.</summary>
    public const string Prefix = "Sla:";

    /// <summary>The targets <paramref name="value"/> gives each key (hours; blank, 0 or over a year = no target).</summary>
    public static SlaTargets From(Func<string, string?> value)
    {
        var hours = new Dictionary<(SlaClock, Severity), int>();
        foreach (var clock in Clocks)
        foreach (var severity in Severities)
            if (int.TryParse(value($"Sla:{clock}:{severity}"), out var h) && h is > 0 and <= SlaPolicy.MaxTargetHours)
                hours[(clock, severity)] = h;

        var pct = int.TryParse(value("Sla:AtRiskThresholdPercent"), out var p) ? p : SlaPolicy.DefaultAtRiskThresholdPercent;
        if (pct is <= 0 or > 100) pct = SlaPolicy.DefaultAtRiskThresholdPercent;

        var breach = new Dictionary<(SlaClock, Severity), int>();
        foreach (var clock in BreachClocks)
        foreach (var severity in Severities)
            if (int.TryParse(value($"Sla:Breach:{clock}:{severity}"), out var h) && h is > 0 and <= SlaPolicy.MaxTargetHours)
                breach[(clock, severity)] = h;

        return new SlaTargets(hours, pct, breach);
    }
}

/// <summary>
/// BUG-322 (owner's decision): the SLA targets as they stood at any moment, so a past quarter's met/missed is judged
/// against the target in force when the milestone was reached, not today's: tightening a target no longer changes a board
/// pack already sent. Rebuilt from the audit trail of the in-app SLA settings (each change is an audited AppSetting row);
/// a target the app never overrode is the server's own value (its settings file). A setting saved before the audit trail
/// recorded it is taken as having held its earliest known value throughout.
/// </summary>
public sealed class SlaTargetHistory
{
    private readonly Func<string, string?> _server;
    // Per key, the in-app value from each change on (null value with Present false: no override, so the server's).
    private readonly Dictionary<string, List<(DateTimeOffset At, bool Present, string? Value)>> _changes;
    private readonly List<DateTimeOffset> _epochs;
    private readonly Dictionary<int, SlaTargets> _byEpoch = new();

    private SlaTargetHistory(Func<string, string?> server, Dictionary<string, List<(DateTimeOffset, bool, string?)>> changes)
    {
        _server = server;
        _changes = changes;
        _epochs = changes.Values.SelectMany(c => c.Select(x => x.Item1)).Where(t => t != DateTimeOffset.MinValue)
            .Distinct().OrderBy(t => t).ToList();
    }

    /// <param name="serverValue">The server's own value for a key (appsettings, environment), without the in-app changes.</param>
    public static async Task<SlaTargetHistory> LoadAsync(IAppDbContext db, Func<string, string?> serverValue, CancellationToken ct = default)
    {
        var rows = await db.AppSettings.AsNoTracking().Where(s => s.Key.StartsWith(SlaTargetSettings.Prefix))
            .Select(s => new { s.Id, s.Key, s.Value }).ToListAsync(ct);
        var keyOf = rows.ToDictionary(r => r.Id.ToString(), r => r.Key, StringComparer.OrdinalIgnoreCase);
        var entries = await db.AuditLog.AsNoTracking().Where(a => a.EntityType == nameof(AppSetting) && a.EntityId != null)
            .OrderBy(a => a.Sequence)
            .Select(a => new { a.EntityId, a.Action, a.AtUtc, a.BeforeJson, a.AfterJson }).ToListAsync(ct);
        // BUG-560: an update names only the fields it changed, so a row from before the trail that is gone now (reset) is
        // known by its key only from a later entry (the delete's before-image). Collect every entry's key first.
        foreach (var e in entries)
            if ((Field(e.BeforeJson, nameof(AppSetting.Key)) ?? Field(e.AfterJson, nameof(AppSetting.Key))) is { } k)
                keyOf.TryAdd(e.EntityId!, k);

        var changes = new Dictionary<string, List<(DateTimeOffset, bool, string?)>>(StringComparer.OrdinalIgnoreCase);
        foreach (var e in entries)
        {
            var key = Field(e.Action == AuditAction.Delete ? e.BeforeJson : e.AfterJson, nameof(AppSetting.Key))
                      ?? keyOf.GetValueOrDefault(e.EntityId!);
            if (key is null || !key.StartsWith(SlaTargetSettings.Prefix, StringComparison.OrdinalIgnoreCase)) continue;
            keyOf[e.EntityId!] = key;
            if (!changes.TryGetValue(key, out var list)) changes[key] = list = [];
            switch (e.Action)
            {
                case AuditAction.Create:
                    list.Add((e.AtUtc, true, Field(e.AfterJson, nameof(AppSetting.Value))));
                    break;
                case AuditAction.Delete:
                    if (list.Count == 0) list.Add((DateTimeOffset.MinValue, true, Field(e.BeforeJson, nameof(AppSetting.Value))));
                    list.Add((e.AtUtc, false, null));
                    break;
                default:
                    if (Has(e.AfterJson, nameof(AppSetting.Value)))
                    {
                        // An update with no create before it: the row predates the trail, so it held the before-value until now.
                        if (list.Count == 0) list.Add((DateTimeOffset.MinValue, true, Field(e.BeforeJson, nameof(AppSetting.Value))));
                        list.Add((e.AtUtc, true, Field(e.AfterJson, nameof(AppSetting.Value))));
                    }
                    break;
            }
        }
        // A row the trail never mentions has held its value throughout.
        foreach (var r in rows.Where(r => !changes.ContainsKey(r.Key)))
            changes[r.Key] = [(DateTimeOffset.MinValue, true, r.Value)];
        return new SlaTargetHistory(serverValue, changes);
    }

    /// <summary>The targets in force at <paramref name="atUtc"/>.</summary>
    public SlaTargets At(DateTimeOffset atUtc)
    {
        var epoch = _epochs.FindLastIndex(t => t <= atUtc);   // -1: before every recorded change
        if (_byEpoch.TryGetValue(epoch, out var cached)) return cached;
        var targets = SlaTargetSettings.From(key => ValueAt(key, atUtc));
        _byEpoch[epoch] = targets;
        return targets;
    }

    private string? ValueAt(string key, DateTimeOffset atUtc)
    {
        if (_changes.TryGetValue(key, out var list) && list.LastOrDefault(c => c.At <= atUtc) is { At: var at } last && at != default)
            return last.Present ? last.Value : _server(key);
        // Before its first recorded change: no override (it was created then), or the value it held (a row from before the trail).
        return list is { Count: > 0 } && list[0].At == DateTimeOffset.MinValue && list[0].Present ? list[0].Value : _server(key);
    }

    private static string? Field(string? json, string name)
    {
        if (json is null) return null;
        try
        {
            using var doc = JsonDocument.Parse(json);
            return doc.RootElement.ValueKind == JsonValueKind.Object && doc.RootElement.TryGetProperty(name, out var v)
                ? v.ValueKind == JsonValueKind.String ? v.GetString() : v.ValueKind == JsonValueKind.Null ? null : v.ToString()
                : null;
        }
        catch (JsonException) { return null; }
    }

    private static bool Has(string? json, string name)
    {
        if (json is null) return false;
        try
        {
            using var doc = JsonDocument.Parse(json);
            return doc.RootElement.ValueKind == JsonValueKind.Object && doc.RootElement.TryGetProperty(name, out _);
        }
        catch (JsonException) { return false; }
    }
}
