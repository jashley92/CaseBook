using System.Collections.Concurrent;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using IncidentManager.Domain.Entities;

namespace IncidentManager.Application.Evidence;

/// <summary>
/// CAP-12: who an evidence package is for, how it goes to them and why: named once for every file in it, with the limits
/// a single recorded transfer has (PROD-13).
/// </summary>
public sealed record EvidenceHandOver(string Recipient, string? Method, string Purpose)
{
    public const int MaxRecipientLength = 200, MaxMethodLength = 100, MaxPurposeLength = 500;

    /// <summary>The hand-over as it's recorded (trimmed; a blank method is none), or the reason it can't be.</summary>
    public static EvidenceHandOver Checked(string? recipient, string? method, string? purpose)
    {
        var to = (recipient ?? "").Trim();
        var why = (purpose ?? "").Trim();
        var how = string.IsNullOrWhiteSpace(method) ? null : method.Trim();
        if (to.Length == 0) throw new ArgumentException("Say who will receive the evidence.");
        if (why.Length == 0) throw new ArgumentException("Give the purpose of the hand-over.");
        if (to.Length > MaxRecipientLength || why.Length > MaxPurposeLength || how?.Length > MaxMethodLength)
            throw new ArgumentException($"Keep the recipient to {MaxRecipientLength} characters, the method to {MaxMethodLength} and the purpose to {MaxPurposeLength}.");
        return new EvidenceHandOver(to, how, why);
    }

    /// <summary>"To X via Y. Purpose: Z", as a recorded transfer says it.</summary>
    public string Sentence => Method is null ? $"To {Recipient}. Purpose: {Purpose}" : $"To {Recipient} via {Method}. Purpose: {Purpose}";
}

/// <summary>CAP-12: a package prepared for download: its ticket (single use, for the person who prepared it), how many
/// files and how many bytes.</summary>
public sealed record EvidencePackageStaged(string Ticket, int Files, long Bytes, DateTimeOffset ExpiresAtUtc);

/// <summary>
/// CAP-12: the packages prepared and not yet downloaded. Preparing one checks everything (the permission, the case, the
/// files, the size) and keeps what was picked here, so the download is a plain link to a ticket: no file, recipient or
/// purpose goes in a URL. A ticket is taken once, by the person who prepared it, within <see cref="Lifetime"/>.
/// Singleton (one app instance, as the upload sessions).
/// </summary>
public sealed class EvidencePackageTickets
{
    /// <summary>How long a prepared package waits to be downloaded.</summary>
    public static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(10);

    /// <summary>Packages one person may have waiting at once.</summary>
    public const int MaxPerUser = 3;

    internal sealed record Request(string UserId, Guid CaseId, IReadOnlyList<Guid> EvidenceIds, EvidenceHandOver HandOver,
        DateTimeOffset ExpiresAtUtc);

    private readonly ConcurrentDictionary<string, Request> _waiting = new(StringComparer.Ordinal);

    internal string Stage(string userId, Guid caseId, IReadOnlyList<Guid> evidenceIds, EvidenceHandOver handOver, DateTimeOffset now)
    {
        foreach (var (key, r) in _waiting)
            if (r.ExpiresAtUtc <= now) _waiting.TryRemove(key, out _);
        // The oldest of this person's waiting packages gives way, so preparing again never fails on the limit.
        foreach (var old in _waiting.Where(w => w.Value.UserId == userId).OrderBy(w => w.Value.ExpiresAtUtc)
                     .Take(Math.Max(0, _waiting.Count(w => w.Value.UserId == userId) - (MaxPerUser - 1))).ToList())
            _waiting.TryRemove(old.Key, out _);
        var ticket = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();
        _waiting[ticket] = new Request(userId, caseId, evidenceIds, handOver, now + Lifetime);
        return ticket;
    }

    /// <summary>The request a ticket holds, taken (so a second download of it is refused), or null when it isn't this
    /// person's, was used, or has expired.</summary>
    internal Request? Take(string ticket, string userId, DateTimeOffset now)
    {
        if (string.IsNullOrEmpty(ticket) || !_waiting.TryGetValue(ticket, out var r) || r.UserId != userId) return null;
        if (!_waiting.TryRemove(new KeyValuePair<string, Request>(ticket, r))) return null;   // taken by a request alongside
        return r.ExpiresAtUtc > now ? r : null;
    }
}

/// <summary>CAP-12: one file in a package: its record as it stood when the download began, its custody so far, and the
/// name it has in the zip.</summary>
public sealed record EvidencePackageFile(Domain.Entities.Evidence Evidence, string EntryName, IReadOnlyList<ChainOfCustodyEvent> Custody);

/// <summary>
/// CAP-12: an evidence package being downloaded: the case, the files and the hand-over, checked again as the download
/// began. <see cref="EvidenceService.RecordPackageAsync"/> records it once every byte has been written.
/// </summary>
public sealed class EvidencePackage
{
    /// <summary>The name of the manifest inside the zip; no file takes it.</summary>
    public const string ManifestName = "MANIFEST.txt";

    /// <summary>The most files one package holds (C10: the work a download does is bounded).</summary>
    public const int MaxFiles = 500;

    public required Guid Id { get; init; }
    public required Guid CaseId { get; init; }
    public required string CaseNumber { get; init; }
    public required EvidenceHandOver HandOver { get; init; }
    public required IReadOnlyList<EvidencePackageFile> Files { get; init; }
    public required DateTimeOffset PreparedAtUtc { get; init; }
    public required string PreparedBy { get; init; }

    public long TotalBytes => Files.Sum(f => f.Evidence.SizeBytes);

    /// <summary>The zip's file name: the case number (as a file name allows) and when it was packaged.</summary>
    public string FileName =>
        $"{EvidenceRisk.EntryName(CaseNumber)} evidence {PreparedAtUtc.UtcDateTime.ToString("yyyy-MM-dd HHmm", CultureInfo.InvariantCulture)}.zip";

    /// <summary>
    /// The size and count every package is held to, checked when it's prepared and again when its download begins (C2:
    /// one rule for both): at least one file, at most <see cref="MaxFiles"/>, and in all no more than the largest single
    /// file the store takes (<c>Evidence:MaxUploadMB</c>), so one download is never larger than one upload may be.
    /// </summary>
    public static void CheckSize(int files, long bytes, EvidenceStorageOptions limits)
    {
        if (files == 0) throw new ArgumentException("Pick at least one file to package.");
        if (files > MaxFiles) throw new ArgumentException($"A package holds up to {MaxFiles} files. Pick fewer, and package the rest separately.");
        if (bytes > limits.MaxUploadBytes)
            throw new ArgumentException($"Those files come to {EvidenceRoom.Size(bytes)}, more than the {EvidenceRoom.Size(limits.MaxUploadBytes)} " +
                "a package may hold (the largest evidence file CaseBook takes). Pick fewer, and package the rest separately.");
    }

    /// <summary>
    /// Each file's name in the zip: its base name only (no folders, nothing a file system refuses: C13), and never the same
    /// as another's or the manifest's, ignoring case (a later one becomes "name (2).ext").
    /// </summary>
    public static IReadOnlyList<string> EntryNames(IEnumerable<string> fileNames)
    {
        var taken = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { ManifestName };
        var names = new List<string>();
        foreach (var original in fileNames)
        {
            var name = EvidenceRisk.EntryName(original);
            var (stem, ext) = (Path.GetFileNameWithoutExtension(name), Path.GetExtension(name));
            for (var n = 2; !taken.Add(name); n++) name = $"{stem} ({n.ToString(CultureInfo.InvariantCulture)}){ext}";
            names.Add(name);
        }
        return names;
    }

    /// <summary>
    /// MANIFEST.txt: the case, the hand-over, and for each file its name in the zip, its original name, SHA-256, size, when
    /// it was collected (CAP-08) and uploaded, and its chain of custody so far. Plain text, one fact per line: every value
    /// from a record is flattened to one line (C13: a name or a reason can't start a line of its own). Times are UTC.
    /// </summary>
    public string Manifest(Func<string?, string> displayName)
    {
        var s = new StringBuilder();
        void Line(string text = "") => s.Append(text).Append("\r\n");
        Line("CaseBook evidence package");
        Line($"Case: {One(CaseNumber)}");
        Line($"Package: {One(FileName)} (id {Id})");
        Line($"Prepared: {Utc(PreparedAtUtc)} by {One(displayName(PreparedBy))}");
        Line($"For: {One(HandOver.Recipient)}");
        Line($"Method: {(HandOver.Method is { } m ? One(m) : "not given")}");
        Line($"Purpose: {One(HandOver.Purpose)}");
        Line($"Files: {Files.Count.ToString(CultureInfo.InvariantCulture)}, {TotalBytes.ToString("N0", CultureInfo.InvariantCulture)} bytes in all");
        Line();
        Line($"The zip's password is \"{EvidenceRisk.ZipPassword}\", the security field's convention for samples, so no file can run by accident.");
        Line("Each file's SHA-256 below is the one recorded when it was uploaded, and its bytes were checked against it as they were packaged.");
        Line("CaseBook records this hand-over in each file's chain of custody (\"Transferred\") and in its audit trail once the package has been sent.");
        for (var i = 0; i < Files.Count; i++)
        {
            var (ev, entry, custody) = (Files[i].Evidence, Files[i].EntryName, Files[i].Custody);
            Line();
            Line($"{(i + 1).ToString(CultureInfo.InvariantCulture)}. {One(entry)}");
            if (!string.Equals(entry, ev.OriginalFileName, StringComparison.Ordinal)) Line($"   Original name: {One(ev.OriginalFileName)}");
            Line($"   SHA-256: {ev.Sha256}");
            Line($"   Size: {ev.SizeBytes.ToString("N0", CultureInfo.InvariantCulture)} bytes");
            Line($"   Collected: {(ev.CollectedAtUtc is { } at ? Utc(at) : "not recorded (taken to be the upload)")}");
            if (ev.CollectedFrom is { } from) Line($"   Collected from: {One(from)}");
            if (ev.CollectedBy is { } by) Line($"   Collected by: {One(by)}");
            Line($"   Uploaded: {Utc(ev.CreatedAtUtc)} by {One(displayName(ev.CreatedBy))}");
            if (!string.IsNullOrWhiteSpace(ev.Description)) Line($"   Description: {One(ev.Description)}");
            Line("   Chain of custody:");
            foreach (var c in custody.OrderBy(c => c.AtUtc))
                Line($"     {Utc(c.AtUtc)}  {One(c.Action)} by {One(displayName(c.Actor))}{(string.IsNullOrWhiteSpace(c.Details) ? "" : ": " + One(c.Details))}");
        }
        return s.ToString();
    }

    private static string Utc(DateTimeOffset t) => t.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss 'UTC'", CultureInfo.InvariantCulture);

    // One line: control characters (a line break, a tab, an escape) become spaces, runs of spaces one.
    private static string One(string? text)
    {
        if (string.IsNullOrEmpty(text)) return "";
        var b = new StringBuilder(text.Length);
        foreach (var ch in text)
        {
            var c = char.IsControl(ch) || char.GetUnicodeCategory(ch) is UnicodeCategory.LineSeparator or UnicodeCategory.ParagraphSeparator ? ' ' : ch;
            if (c == ' ' && b.Length > 0 && b[^1] == ' ') continue;
            b.Append(c);
        }
        return b.ToString().Trim();
    }
}
