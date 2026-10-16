using System.Collections;
using System.Reflection;
using FluentAssertions;
using IncidentManager.Domain.Common;
using IncidentManager.Domain.Entities;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>
/// C18: every stored value of a hashable record is in its row hash, unless it's listed here with the reason it's left
/// out. Each property of each record is changed in turn, in every fixture shape, and the current format's canonical must
/// change with it. A listed property that the canonical has since come to cover fails too, so the list only holds what's
/// really left out. A new property is covered or listed before the build passes.
/// </summary>
public class CanonicalCoverageTests
{
    /// <summary>Left out of every record, and why.</summary>
    private static readonly Dictionary<string, string> LeftOutEverywhere = new(StringComparer.Ordinal)
    {
        [nameof(Entity.Id)] = "the key the audit trail records each row under: the record check compares a row with its own entries",
        [nameof(AuditableEntity.ModifiedAtUtc)] = "a freshness stamp: an update that only moves it isn't audited (IsTouchOnly)",
        [nameof(AuditableEntity.ModifiedBy)] = "a freshness stamp, as ModifiedAtUtc",
    };

    /// <summary>What's deliberately outside the row hash, and why. Keyed "Type.Property" ("Case.LegalReferral.X" for a
    /// value object's property, "Case.Notes" for a collection), or "Type.Property@Shape" for one fixture shape.</summary>
    private static readonly Dictionary<string, string> LeftOut = new(StringComparer.Ordinal)
    {
        ["ActionItem.CreatedAtUtc"] = "shown with the task only: no figure, check or gate reads when a task was added (its due, status and completion are hashed)",
        ["ActionItem.CreatedBy"] = "shown with the task only, as CreatedAtUtc",
        ["AnalystNote.IsCurrent"] = "changes when the next version is written; the record check's lineage rule covers it (a replaced version marked current, a latest one hidden)",
        ["TimelineEntry.IsCurrent"] = "as AnalystNote.IsCurrent; a retracted entry marked current is flagged too",
        ["CaseBrief.IsCurrent"] = "as AnalystNote.IsCurrent (a replaced version marked current is flagged)",
        ["ApiToken.LastUsedAtUtc"] = "stamped on every API call and not audited (REV-05); it grants nothing",
        ["Case.Year"] = "a part the case number was made from: the number (CaseNumber) is hashed, these only pick the next free one",
        ["Case.Sequence"] = "as Case.Year",
        ["Case.DescriptiveName"] = "as Case.Year",
        ["Case.HasCustomNumber"] = "whether the number was typed in rather than issued: a numbering preference, not case content",
        ["Case.ReportProfileId"] = "which section layout its report uses (E-28): a reporting preference, audited but not case content",
        ["Case.EntityLayouts"] = "graph positions: cosmetic, deliberately outside the audit trail",
        ["Evidence.StoragePath"] = "where the file is kept under a random name: its SHA-256 is hashed, and the evidence re-hash checks the file there against it",
        ["Report.StoragePath"] = "where the file is kept: its SHA-256 is hashed, and the file is checked against it on every download and approval",
        ["Evidence.CustodyEvents"] = "custody events are their own record, outside the audit trail (owner decision, C18)",
        ["ReportProfile.TemplateId"] = "which Word template the profile starts from: each report records the template it used (name and SHA-256)",
        // Read only with another value, and shown only with it: without that value they say nothing.
        ["CaseBrief.ConfirmedBy@Bare"] = "a confirmer is shown (and hashed) only with the time it was confirmed",
        ["TimelineEntry.RetractedBy@Bare"] = "a retraction's author is shown (and hashed) only with the time it was retracted",
        ["TimelineEntry.RetractReason@Bare"] = "a retraction's reason is shown (and hashed) only with the time it was retracted",
    };

    // Whether a change to the property shows in the canonical; null where the shape has nothing to change (an optional
    // value object that isn't there).
    private static IEnumerable<(string Key, Func<IHashableEntity, bool?> Changes)> Probes(Type type)
    {
        foreach (var p in CanonicalFixtures.Settable(type))
        {
            if (p.Name == nameof(IHashableEntity.RowHash) || LeftOutEverywhere.ContainsKey(p.Name)) continue;
            if (CanonicalFixtures.IsOwned(p.PropertyType))
            {
                foreach (var inner in CanonicalFixtures.Settable(p.PropertyType))
                    yield return ($"{type.Name}.{p.Name}.{inner.Name}", e => p.GetValue(e) is { } owned ? Mutates(e, () => Mutate(owned, inner)) : null);
                continue;
            }
            yield return ($"{type.Name}.{p.Name}", e => Mutates(e, () => Mutate(e, p)));
        }
        // Collections of child rows that aren't hashed on their own: a canonical that reads them must change when one
        // is added.
        foreach (var p in type.GetProperties(BindingFlags.Public | BindingFlags.Instance)
                     .Where(p => p.PropertyType.IsGenericType && p.PropertyType.GetGenericTypeDefinition() == typeof(List<>))
                     .OrderBy(p => p.Name, StringComparer.Ordinal))
        {
            var item = p.PropertyType.GetGenericArguments()[0];
            if (!typeof(Entity).IsAssignableFrom(item) || typeof(IHashableEntity).IsAssignableFrom(item)) continue;
            yield return ($"{type.Name}.{p.Name}", e => Mutates(e, () =>
            {
                var added = Activator.CreateInstance(item, nonPublic: true)!;
                foreach (var ip in CanonicalFixtures.Settable(item))
                    ip.SetValue(added, CanonicalFixtures.Value(ip.PropertyType, CanonicalFixtures.Seed(item, ip.Name), ip.Name, other: true));
                ((IList)p.GetValue(e)!).Add(added);
            }));
        }
    }

    private static bool? Mutates(IHashableEntity e, Action mutate)
    {
        var before = CanonicalFixtures.In(Canonical.CurrentFormat, e);
        mutate();
        return CanonicalFixtures.In(Canonical.CurrentFormat, e) != before;
    }

    private static void Mutate(object target, PropertyInfo p)
    {
        var current = p.GetValue(target);
        var seed = CanonicalFixtures.Seed(target.GetType(), p.Name);
        p.SetValue(target, current is null
            ? CanonicalFixtures.Value(p.PropertyType, seed, p.Name)
            : current is bool b ? !b
            : Equals(current, CanonicalFixtures.Value(p.PropertyType, seed, p.Name, other: true))
                ? CanonicalFixtures.Value(p.PropertyType, seed, p.Name)
                : CanonicalFixtures.Value(p.PropertyType, seed, p.Name, other: true));
    }

    [Fact]
    public void Every_stored_value_is_in_the_row_hash_or_listed_with_its_reason()
    {
        var uncovered = new List<string>();
        var stale = new List<string>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var type in CanonicalFixtures.HashableTypes)
            foreach (var (key, changes) in Probes(type))
            {
                var missedSomewhere = false;
                foreach (var shape in CanonicalFixtures.Shapes(type))
                {
                    // Covered when a change shows in every shape the property can be set in. A listing is for the whole
                    // record ("Type.Property") or for one shape ("Type.Property@Shape").
                    var forShape = key + "@" + shape.Name;
                    var listed = LeftOut.ContainsKey(key) ? key : LeftOut.ContainsKey(forShape) ? forShape : null;
                    if (listed is not null) seen.Add(listed);
                    if (changes(shape.Make()) is not { } shows) continue;
                    if (!shows) missedSomewhere = true;
                    if (listed is null && !shows) uncovered.Add($"{key} (not in the {shape.Name} canonical)");
                    if (listed == forShape && shows) stale.Add(listed);
                }
                if (LeftOut.ContainsKey(key) && !missedSomewhere) stale.Add(key);
            }

        string.Join("\n", uncovered).Should().BeEmpty("each stored value is in the row hash, or listed in LeftOut with why it isn't");
        string.Join("\n", stale).Should().BeEmpty("these are in the row hash now: take them off LeftOut");
        LeftOut.Keys.Except(seen).Should().BeEmpty("LeftOut names only properties a hashable record has");
    }
}
