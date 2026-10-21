using System.Globalization;

namespace IncidentManager.Domain.Common;

/// <summary>
/// Formatting for <see cref="IHashableEntity.BuildCanonicalContent"/> that doesn't depend on the server: a time is its UTC
/// instant in round-trip form whatever offset it was read back with (BUG-25), an enum is its number.
/// <para>BUG-24: a canonical joins its fields with '|', so in the first format text could move between two fields of a
/// record ("a|b" + "c" and "a" + "b|c") without changing the hash. Format 2 escapes '\' and '|' in free text
/// (<see cref="Text"/>). Row hashes are written in format 2 and say so with a <see cref="V2Prefix"/>; a hash without it
/// is checked in the first format, in which <see cref="Text"/> leaves text as it is, so older rows verify unchanged.</para>
/// </summary>
public static class Canonical
{
    /// <summary>Starts a row hash computed over a format-2 canonical.</summary>
    public const string V2Prefix = "v2:";

    /// <summary>
    /// BUG-316: starts a row hash over a format-3 canonical: format 2 plus fields the earlier formats left out (an
    /// indicator's TLP marking and pin, an evidence file's description), so a TLP lowered in the database, then shared
    /// by the IOC feed and STIX, is caught. New hashes are written in format 3; a row moves to it on its next save, and
    /// one not saved since keeps verifying in the format it was written in.
    /// </summary>
    public const string V3Prefix = "v3:";

    /// <summary>
    /// C18: starts a row hash over a format-4 canonical: format 3 plus stored values the earlier formats left out (a
    /// note's and an attack step's lineage, a notice's kept deadline, a case's kept jurisdictions and legal-hold release
    /// request, a task's completion stamp), each folded in only when set, so a record without them builds what format 3
    /// built. Reports are hashed from this format. The start-up upgrade (RowHashUpgrade) moves every record its stored
    /// hash doesn't cover to this format; after it, a hash in an earlier format that leaves out a set value is a change
    /// made outside CaseBook (<see cref="Covers"/>).
    /// </summary>
    public const string V4Prefix = "v4:";

    /// <summary>
    /// CAP-07: starts a row hash over a format-5 canonical: format 4 plus how a regulator was notified (a notice's method,
    /// reference, who gave it and the file holding it), CAP-08's evidence collection (when, where from and by whom a
    /// file was collected) and CAP-21's evidence withdrawal (when, by whom and why), each folded in only when set, so a
    /// record without them builds what
    /// format 4 built and keeps its hash. No row written before format 5 can hold them, so there's nothing to upgrade.
    /// </summary>
    public const string V5Prefix = "v5:";

    /// <summary>
    /// Starts a row hash over a format-6 canonical: format 5 plus an evidence file's purge (when, by whom and why its bytes
    /// were deleted), folded in only when set, so every record builds what format 5 built until one is purged. No row
    /// written before format 6 can hold a purge, so there's nothing to upgrade.
    /// </summary>
    public const string V6Prefix = "v6:";

    /// <summary>
    /// FR-51: starts a row hash over a format-7 canonical: format 6 plus who recorded a case's containment and when they
    /// did, folded in only when set, so every record builds what format 6 built until a case is marked contained. No row
    /// written before format 7 can hold them, so there's nothing to upgrade.
    /// </summary>
    public const string V7Prefix = "v7:";

    /// <summary>
    /// Starts a row hash over a format-8 canonical: format 7 plus an administrator's removal of a case (who, when, why, its
    /// number then) and its purge, folded in only when set, so every record builds what format 7 built until a case is
    /// removed. No row written before format 8 can hold them, so there's nothing to upgrade.
    /// </summary>
    public const string V8Prefix = "v8:";

    /// <summary>The format row hashes are written in.</summary>
    public const int CurrentFormat = 8;

    /// <summary>Whether the canonical being built is in <paramref name="format"/> or later (an entity adds the fields
    /// that format brought in only then).</summary>
    public static bool AtLeast(int format) => t_format >= format;

    [ThreadStatic] private static int t_format;

    // C18: set while building when the record holds a value a later format brought in that this format leaves out.
    [ThreadStatic] private static bool t_leftOut;

    /// <summary>A free-text field: escaped in format 2, as it is in the first format.</summary>
    public static string? Text(string? value) =>
        t_format >= 2 && value is not null && value.AsSpan().IndexOfAny('\\', '|') >= 0
            ? value.Replace("\\", "\\\\", StringComparison.Ordinal).Replace("|", "\\|", StringComparison.Ordinal)
            : value;

    /// <summary>
    /// C18: a part <paramref name="format"/> brought in: built from that format on, and nothing before it.
    /// <paramref name="holdsValue"/> says whether the record holds a value the part records, so a hash in an earlier
    /// format falls short of the record only then (<see cref="Covers"/>).
    /// </summary>
    public static string From(int format, bool holdsValue, Func<string> part)
    {
        if (t_format >= format) return part();
        if (holdsValue) t_leftOut = true;
        return "";
    }

    /// <summary>C18: a part <paramref name="format"/> brought in that's folded in only when <paramref name="isSet"/>, so
    /// a record without it builds the same canonical in that format as before it.</summary>
    public static string Since(int format, bool isSet, Func<string> part) => isSet ? From(format, true, part) : "";

    /// <summary>Builds a canonical in the given format (1 to 8). Canonicals are built synchronously, so the format is
    /// per thread.</summary>
    public static string InFormat(int format, Func<string> build)
    {
        var (previous, left) = (t_format, t_leftOut);
        t_format = format;
        try { return build(); }
        finally { (t_format, t_leftOut) = (previous, left); }
    }

    /// <summary>
    /// C18: whether a hash in <paramref name="format"/> covers everything the record holds: false when the record has a
    /// value a later format brought in, which a hash in this one can't show was changed.
    /// </summary>
    public static bool Covers(int format, Func<string> build)
    {
        var (previous, left) = (t_format, t_leftOut);
        t_format = format;
        t_leftOut = false;
        try
        {
            build();
            return !t_leftOut;
        }
        finally { (t_format, t_leftOut) = (previous, left); }
    }

    /// <summary>The format a stored row hash was written in, from its prefix (none: the first).</summary>
    public static int FormatOf(string storedHash) =>
        storedHash.StartsWith(V8Prefix, StringComparison.Ordinal) ? 8
        : storedHash.StartsWith(V7Prefix, StringComparison.Ordinal) ? 7
        : storedHash.StartsWith(V6Prefix, StringComparison.Ordinal) ? 6
        : storedHash.StartsWith(V5Prefix, StringComparison.Ordinal) ? 5
        : storedHash.StartsWith(V4Prefix, StringComparison.Ordinal) ? 4
        : storedHash.StartsWith(V3Prefix, StringComparison.Ordinal) ? 3
        : storedHash.StartsWith(V2Prefix, StringComparison.Ordinal) ? 2
        : 1;

    /// <summary>The prefix a row hash in <paramref name="format"/> starts with.</summary>
    public static string PrefixOf(int format) => format switch { 8 => V8Prefix, 7 => V7Prefix, 6 => V6Prefix, 5 => V5Prefix, 4 => V4Prefix, 3 => V3Prefix, 2 => V2Prefix, _ => "" };

    public static string Time(DateTimeOffset t) => t.ToUniversalTime().ToString("o", CultureInfo.InvariantCulture);

    public static string Time(DateTimeOffset? t) => t is { } v ? Time(v) : "";

    public static string Num<TEnum>(TEnum value) where TEnum : struct, Enum => Convert.ToInt32(value, CultureInfo.InvariantCulture).ToString(CultureInfo.InvariantCulture);

    public static string Num<TEnum>(TEnum? value) where TEnum : struct, Enum => value is { } v ? Num(v) : "";
}
