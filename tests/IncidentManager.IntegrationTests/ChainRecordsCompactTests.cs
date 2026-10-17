using System.Text.Json;
using FluentAssertions;
using IncidentManager.Application.Integrity;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Security;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// The record check's map keeps a record's id as a GUID and its recorded hash as 32 bytes when CaseBook wrote them, to
/// hold a large trail in a fraction of the memory. It must read back exactly what the trail recorded, and compare a stored
/// hash exactly as the text did (ignoring case), whatever the trail holds, including ids and hashes CaseBook never writes.
/// The row-hash check compares digest bytes too, and must agree with comparing the hash's text.
/// </summary>
public sealed class ChainRecordsCompactTests
{
    private const string Hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    private static long _sequence;

    private static AuditLogEntry Entry(string type, string id, string? hash, AuditAction action = AuditAction.Update) => new()
    {
        Sequence = ++_sequence, EntityType = type, EntityId = id, Action = action, EntryHash = "e" + _sequence,
        AfterJson = action == AuditAction.Delete ? null
            : JsonSerializer.Serialize(hash is null ? new Dictionary<string, object?> { ["Body"] = "x" }
                : new Dictionary<string, object?> { ["RowHash"] = hash }),
    };

    public static TheoryData<string, string?> Recorded => new()
    {
        { Guid.NewGuid().ToString(), "v4:" + Hex },          // as CaseBook writes both: kept compact
        { Guid.NewGuid().ToString(), Hex },                  // a first-format hash, no prefix
        { Guid.NewGuid().ToString(), "v2:" + Hex },
        { Guid.NewGuid().ToString(), null },                 // an entry from before updates recorded the hash
        { Guid.NewGuid().ToString(), "V4:" + Hex },          // upper-case prefix: kept as written
        { Guid.NewGuid().ToString(), "v4:" + Hex.ToUpperInvariant() },
        { Guid.NewGuid().ToString(), "v4:" + Hex[..63] },    // short
        { Guid.NewGuid().ToString(), "v1:" + Hex },          // no such format
        { Guid.NewGuid().ToString(), "v4:" + Hex[..62] + "zz" },
        { Guid.NewGuid().ToString(), "" },
        { Guid.NewGuid().ToString().ToUpperInvariant(), "v4:" + Hex },   // an id CaseBook never writes: kept as written
        { "{" + Guid.NewGuid() + "}", "v4:" + Hex },
        { "settings-bundle", "v4:" + Hex },
    };

    [Theory]
    [MemberData(nameof(Recorded))]
    public void A_record_reads_back_as_the_trail_recorded_it(string id, string? hash)
    {
        var records = new RowIntegrityVerifier.ChainRecords();
        var entry = Entry("AnalystNote", id, hash);
        records.Add(entry);

        records.TryGet(("AnalystNote", id), out var last).Should().BeTrue();
        last.Should().Be((hash, entry.Sequence, false));
        var otherCase = id.Any(char.IsAsciiLetterLower) ? id.ToUpperInvariant() : id.ToLowerInvariant();
        records.TryGet(("AnalystNote", otherCase), out _).Should().BeFalse("an id is matched exactly, as the text key was");
        records.TryGet(("TimelineEntry", id), out _).Should().BeFalse();
        records.Count.Should().Be(1);
        records.Head.Should().Be(entry.Sequence);
        records.HeadHash.Should().Be(entry.EntryHash);
    }

    [Theory]
    [MemberData(nameof(Recorded))]
    public void A_stored_hash_is_compared_as_the_text_was(string id, string? hash)
    {
        var records = new RowIntegrityVerifier.ChainRecords();
        records.Add(Entry("AnalystNote", id, hash));
        records.TryGetEntry(("AnalystNote", id), out var last).Should().BeTrue();
        last.HasHash.Should().Be(hash is not null);

        var stored = new List<string>
        {
            "v4:" + Hex, "V4:" + Hex, "v4:" + Hex.ToUpperInvariant(), Hex, Hex.ToUpperInvariant(), "v2:" + Hex, "v3:" + Hex,
            "v4:" + Hex[..63] + "0", "v4:" + Hex[..63], "v1:" + Hex, "", "v4:" + Hex + " ", " v4:" + Hex,
        };
        if (hash is not null) stored.Add(hash);
        foreach (var s in stored)
            last.HashEquals(s).Should().Be(hash is not null && string.Equals(hash, s, StringComparison.OrdinalIgnoreCase),
                $"recorded {hash ?? "(none)"}, stored {s}");
    }

    [Fact]
    public void The_latest_entry_decides_and_a_removal_is_kept()
    {
        var records = new RowIntegrityVerifier.ChainRecords();
        var id = Guid.NewGuid();
        records.Add(Entry("AnalystNote", id.ToString(), "v4:" + Hex));
        records.Add(Entry("AnalystNote", id.ToString(), "v4:" + new string('f', 64)));
        records.TryGetEntry("AnalystNote", id, out var last).Should().BeTrue();
        last.Hash.Should().Be("v4:" + new string('f', 64));

        var removal = Entry("AnalystNote", id.ToString(), null, AuditAction.Delete);
        records.Add(removal);
        records.TryGet(("AnalystNote", id.ToString()), out var gone).Should().BeTrue();
        gone.Should().Be(((string?)null, removal.Sequence, true));
        records.Count.Should().Be(1);
    }

    [Fact]
    public void Records_not_read_from_their_tables_are_listed_and_others_arent()
    {
        var records = new RowIntegrityVerifier.ChainRecords();
        var read = Guid.NewGuid();
        var gone = Guid.NewGuid();
        records.Add(Entry("AnalystNote", read.ToString(), "v4:" + Hex));
        records.Add(Entry("AnalystNote", gone.ToString(), "v4:" + Hex));
        records.Add(Entry("AnalystNote", "NOT-A-GUID", "v4:" + Hex));
        records.Add(Entry("TimelineEntry", read.ToString(), "v4:" + Hex));   // the same id in another table

        var present = new HashSet<(int Type, Guid Id)> { records.PresentKey("AnalystNote", read)!.Value };
        records.PresentKey("CaseLink", read).Should().BeNull("a type the trail never named has no key");

        records.NotPresent(present, (_, _) => true).Should().BeEquivalentTo(new[]
        {
            ("AnalystNote", gone.ToString()), ("AnalystNote", "NOT-A-GUID"), ("TimelineEntry", read.ToString()),
        });
        records.Present(("AnalystNote", read.ToString()), present).Should().BeTrue();
        records.Present(("AnalystNote", read.ToString().ToUpperInvariant()), present).Should().BeFalse();
        records.NotPresent(present, (type, _) => type == "TimelineEntry").Should().Equal(("TimelineEntry", read.ToString()));
    }

    // The comparison it replaced: the hash's text against the stored text, ignoring case.
    private static bool AsText(HashChainService hasher, AnalystNote note, string stored)
    {
        var format = IncidentManager.Domain.Common.Canonical.FormatOf(stored);
        return string.Equals(IncidentManager.Domain.Common.Canonical.PrefixOf(format)
                             + hasher.Hash(IncidentManager.Domain.Common.Canonical.InFormat(format, note.BuildCanonicalContent)),
            stored, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void The_row_hash_check_agrees_with_comparing_the_text()
    {
        var hasher = new HashChainService();
        var note = new AnalystNote
        {
            CaseId = Guid.NewGuid(), Body = "Ünïcödé body | with a pipe \\ and a backslash, 東京", CreatedBy = "alice",
            CreatedAtUtc = new DateTimeOffset(2026, 10, 17, 9, 0, 0, TimeSpan.Zero),
        };
        var current = hasher.ComputeRowHash(note);
        var digits = current[(current.IndexOf(':') + 1)..];
        var candidates = new List<string>
        {
            current, current.ToUpperInvariant(), "V" + current[1..], digits, digits.ToUpperInvariant(),
            current[..^1] + (current[^1] == '0' ? '1' : '0'), current + "0", current[..^1], current + " ", " " + current,
            "", "v4:", "v9:" + digits, "v1:" + digits, current.Replace(digits[..2], "zz"),
        };
        foreach (var format in new[] { 2, 3 })
        {
            var prefix = IncidentManager.Domain.Common.Canonical.PrefixOf(format);
            var older = prefix + hasher.Hash(IncidentManager.Domain.Common.Canonical.InFormat(format, note.BuildCanonicalContent));
            candidates.Add(older);
            candidates.Add(older.ToUpperInvariant());
        }
        candidates.Add(hasher.Hash(IncidentManager.Domain.Common.Canonical.InFormat(1, note.BuildCanonicalContent)));

        foreach (var stored in candidates)
            hasher.RowHashMatches(note, stored).Should().Be(AsText(hasher, note, stored), $"stored {stored}");
        hasher.RowHashMatches(note, current).Should().BeTrue();
    }
}
