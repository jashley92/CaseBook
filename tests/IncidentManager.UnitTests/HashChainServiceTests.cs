using FluentAssertions;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Security;
using Xunit;

namespace IncidentManager.UnitTests;

public class HashChainServiceTests
{
    private readonly HashChainService _svc = new();

    private List<AuditLogEntry> BuildChain(int count)
    {
        var chain = new List<AuditLogEntry>();
        AuditLogEntry? prev = null;
        for (var i = 0; i < count; i++)
        {
            var entry = new AuditLogEntry
            {
                AtUtc = new DateTimeOffset(2026, 1, 1, 0, 0, i, TimeSpan.Zero),
                Actor = $"user{i}",
                Action = AuditAction.Create,
                EntityType = "Case",
                EntityId = Guid.NewGuid().ToString(),
                CaseNumber = $"2026-{i:00}_Test",
                Summary = $"event {i}"
            };
            _svc.ChainAppend(entry, prev);
            chain.Add(entry);
            prev = entry;
        }
        return chain;
    }

    [Fact]
    public void Swapping_an_entrys_reason_and_label_breaks_the_chain(/* BUG-184 */)
    {
        var chain = BuildChain(2);
        chain[1].Reason = "Corrected the effective time";
        chain[1].EntryHash = "";
        _svc.ChainAppend(chain[1], chain[0]);   // as written, with its reason
        _svc.VerifyChain(chain).IsValid.Should().BeTrue();

        (chain[1].EntityLabel, chain[1].Reason) = (chain[1].Reason, null);   // the reason moved into the label

        _svc.VerifyChain(chain).IsValid.Should().BeFalse("format 2 says which field each value is");
    }

    [Fact]
    public void An_entry_in_the_first_format_after_one_in_format_2_is_a_break(/* BUG-184 */)
    {
        var chain = BuildChain(3);
        // Rewritten as a first-format entry and re-hashed, so its own hash and links still hold.
        chain[2].Format = null;
        chain[2].EntryHash = _svc.Hash(chain[2].BuildCanonicalContent() + "|" + chain[2].PrevHash);

        var result = _svc.VerifyChain(chain);
        result.IsValid.Should().BeFalse();
        result.FirstBrokenSequence.Should().Be(3);
        chain.Take(2).Should().OnlyContain(e => e.Format == AuditLogEntry.CurrentFormat);
    }

    [Fact]
    public void ChainAppend_assigns_sequential_positions_and_links_hashes()
    {
        var chain = BuildChain(3);

        chain[0].Sequence.Should().Be(1);
        chain[1].Sequence.Should().Be(2);
        chain[2].Sequence.Should().Be(3);

        chain[0].PrevHash.Should().BeEmpty("the genesis entry links against an empty previous hash");
        chain[1].PrevHash.Should().Be(chain[0].EntryHash);
        chain[2].PrevHash.Should().Be(chain[1].EntryHash);

        chain.Select(e => e.EntryHash).Should().OnlyHaveUniqueItems();
        chain.Should().OnlyContain(e => e.EntryHash.Length == 64, "SHA-256 hex is 64 chars");
    }

    [Fact]
    public void VerifyChain_returns_valid_for_an_untampered_chain()
    {
        var result = _svc.VerifyChain(BuildChain(5));

        result.IsValid.Should().BeTrue();
        result.FirstBrokenSequence.Should().BeNull();
    }

    [Fact]
    public void VerifyChain_detects_an_altered_record_at_its_sequence()
    {
        var chain = BuildChain(5);

        // Simulate someone editing history directly in the database.
        chain[2].Summary = "tampered!";

        var result = _svc.VerifyChain(chain);

        result.IsValid.Should().BeFalse();
        result.FirstBrokenSequence.Should().Be(3);
        result.Detail.Should().Contain("altered");
    }

    [Fact]
    public void VerifyChain_detects_a_deleted_entry_as_a_sequence_gap()
    {
        var chain = BuildChain(5);

        chain.RemoveAt(2); // delete the third entry

        var result = _svc.VerifyChain(chain);

        result.IsValid.Should().BeFalse();
        result.FirstBrokenSequence.Should().Be(4, "sequence jumps from 2 to 4");
    }

    [Fact]
    public void VerifyChain_detects_a_relinked_forgery()
    {
        var chain = BuildChain(4);

        // Attacker rewrites an entry and recomputes ONLY its own hash, leaving the link stale.
        chain[1].Actor = "attacker";
        // (EntryHash left unchanged) -> content no longer matches hash
        var result = _svc.VerifyChain(chain);

        result.IsValid.Should().BeFalse();
        result.FirstBrokenSequence.Should().Be(2);
    }

    [Fact]
    public void ComputeRowHash_is_deterministic_and_content_sensitive()
    {
        var c = Case.Open(2026, 1, "Phishing Wave", "Phishing wave",
            Classification.Incident, Severity.High, CaseOrigin.InternalDetection,
            "analyst", DateTimeOffset.UnixEpoch);

        var h1 = _svc.ComputeRowHash(c);
        var h2 = _svc.ComputeRowHash(c);
        h1.Should().Be(h2);

        c.Title = "Phishing wave (updated)";
        _svc.ComputeRowHash(c).Should().NotBe(h1, "changing a business field changes the row hash");
    }
}
