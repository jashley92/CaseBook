using System.Reflection;
using IncidentManager.Domain.Common;
using IncidentManager.Domain.Entities;

namespace IncidentManager.UnitTests;

/// <summary>
/// C18: fixed instances of every hashable record, built by reflection so a property added later is set too. "Full" sets
/// every property a canonical could read (text holding '|' and '\', so the formats differ); "Bare" leaves everything
/// optional unset. Values are derived from the type and property name, so the same fixture comes back every run.
/// </summary>
internal static class CanonicalFixtures
{
    public static IReadOnlyList<Type> HashableTypes { get; } = typeof(Case).Assembly.GetTypes()
        .Where(t => typeof(IHashableEntity).IsAssignableFrom(t) && t is { IsAbstract: false, IsInterface: false })
        .OrderBy(t => t.Name, StringComparer.Ordinal).ToList();

    private static readonly DateTimeOffset Base = new(2026, 1, 2, 3, 4, 5, TimeSpan.Zero);

    public static IHashableEntity Full(Type type) => (IHashableEntity)Fill(New(type), full: true);

    public static IHashableEntity Bare(Type type) => (IHashableEntity)Fill(New(type), full: false);

    /// <summary>The shapes each record is checked in: Full and Bare, and for a timeline entry an attack step too (its
    /// canonical takes another branch).</summary>
    public static IReadOnlyList<(string Name, Func<IHashableEntity> Make)> Shapes(Type type)
    {
        var shapes = new List<(string, Func<IHashableEntity>)> { ("Full", () => Full(type)), ("Bare", () => Bare(type)) };
        if (type == typeof(TimelineEntry))
            shapes.Add(("Event", () => { var t = (TimelineEntry)Full(type); t.Kind = Domain.Enums.TimelineKind.Event; return t; }));
        return shapes;
    }

    private static object New(Type type) => Activator.CreateInstance(type, nonPublic: true)!;

    /// <summary>The properties a fixture sets (and the coverage test mutates): every readable property with a setter
    /// (private or not) whose type is a value, text or one of the owned value objects.</summary>
    public static IEnumerable<PropertyInfo> Settable(Type type) =>
        type.GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Where(p => p.GetSetMethod(nonPublic: true) is not null && p.GetIndexParameters().Length == 0)
            .Where(p => IsScalar(p.PropertyType) || IsOwned(p.PropertyType))
            .OrderBy(p => p.Name, StringComparer.Ordinal);

    public static bool IsOwned(Type t) => t.Namespace == "IncidentManager.Domain.ValueObjects" && t.IsClass;

    private static bool IsScalar(Type t)
    {
        var u = Nullable.GetUnderlyingType(t) ?? t;
        return u == typeof(string) || u.IsPrimitive || u.IsEnum || u == typeof(decimal) || u == typeof(Guid)
               || u == typeof(DateTimeOffset) || u == typeof(DateTime) || u == typeof(TimeSpan);
    }

    private static object Fill(object target, bool full)
    {
        foreach (var p in Settable(target.GetType()))
        {
            if (p.Name == nameof(IHashableEntity.RowHash)) continue;
            if (IsOwned(p.PropertyType))
            {
                // A required value object (LegalReferral) is filled in both shapes; an optional one (ThirdParty) only in Full.
                var nullable = new NullabilityInfoContext().Create(p).WriteState == NullabilityState.Nullable;
                if (!full && nullable) { p.SetValue(target, null); continue; }
                p.SetValue(target, Fill(New(p.PropertyType), full));
                continue;
            }
            var optional = Nullable.GetUnderlyingType(p.PropertyType) is not null
                           || (p.PropertyType == typeof(string) && new NullabilityInfoContext().Create(p).WriteState == NullabilityState.Nullable);
            var u = Nullable.GetUnderlyingType(p.PropertyType) ?? p.PropertyType;
            // Bare: optional values unset, and everything else at a fixed value (an Id or a time that's always set).
            if (!full && optional) { p.SetValue(target, null); continue; }
            if (!full && u != typeof(Guid) && u != typeof(DateTimeOffset) && u != typeof(DateTime)) continue;
            p.SetValue(target, Value(u, Seed(target.GetType(), p.Name), p.Name));
        }
        if (full)
        {
            // What a canonical reads beyond the row: a case's data elements, a step's tactics.
            if (target is Case c)
                c.DataElements = [new CaseDataElement { CaseId = c.Id, ElementKey = "SSN" }, new CaseDataElement { CaseId = c.Id, ElementKey = "DOB" }];
            if (target is TimelineEntry t)
                t.Tactics = [new EventStepTactic { TimelineEntryId = t.Id, Tactic = Domain.Enums.MitreTactic.Execution },
                             new EventStepTactic { TimelineEntryId = t.Id, Tactic = Domain.Enums.MitreTactic.Persistence }];
        }
        return target;
    }

    /// <summary>A fixed value of <paramref name="t"/> for a seed; <paramref name="other"/> gives a different one.</summary>
    public static object Value(Type t, uint seed, string name, bool other = false)
    {
        var u = Nullable.GetUnderlyingType(t) ?? t;
        var n = (int)(seed % 97) + (other ? 1 : 0);
        if (u == typeof(string)) return other ? name + "-changed" : name + @"|v\" + n.ToString(System.Globalization.CultureInfo.InvariantCulture);
        if (u == typeof(bool)) return !other;
        if (u == typeof(Guid)) return Guid.Parse($"{seed:x8}-0000-4000-8000-{(other ? 1 : 0):x12}");
        if (u == typeof(DateTimeOffset)) return Base.AddMinutes(n);
        if (u == typeof(DateTime)) return Base.UtcDateTime.AddMinutes(n);
        if (u == typeof(TimeSpan)) return TimeSpan.FromMinutes(n);
        if (u.IsEnum)
        {
            var values = Enum.GetValues(u);
            return values.GetValue((1 + (other ? 1 : 0)) % values.Length)!;
        }
        return Convert.ChangeType(n + 1, u, System.Globalization.CultureInfo.InvariantCulture);
    }

    /// <summary>FNV-1a over the type and property names: stable across runs (string.GetHashCode isn't).</summary>
    public static uint Seed(Type type, string property)
    {
        var h = 2166136261u;
        foreach (var ch in type.Name + "." + property) h = (h ^ ch) * 16777619u;
        return h;
    }

    /// <summary>The canonical in <paramref name="format"/>.</summary>
    public static string In(int format, IHashableEntity e) => Canonical.InFormat(format, e.BuildCanonicalContent);

    /// <summary>The plain SHA-256 of the canonical in <paramref name="format"/>.</summary>
    public static string Sha(int format, IHashableEntity e) =>
        Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(In(format, e)))).ToLowerInvariant();
}
